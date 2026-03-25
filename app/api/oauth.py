import base64
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from urllib.parse import parse_qs, urlencode

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session
from app.models import OAuthAuthorizationCode, OAuthClient, User
from app.schemas import (
    OpenIDClientCreate,
    OAuthAuthorizeRequest,
    OAuthClientOut,
)
from app.security import (
    create_access_token,
    create_id_token,
    create_refresh_token,
    decode_token,
    ensure_group_exists,
    get_password_hash,
    verify_password,
)

router = APIRouter(tags=["oauth"])
settings = get_settings()
logger = logging.getLogger("auth.audit")


def _anon(value: str | None) -> str:
    if not value:
        return "na"
    return sha256(value.encode("utf-8")).hexdigest()[:12]


def _audit(event: str, **fields) -> None:
    parts = [f"event={event}"]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    logger.info(" ".join(parts))


def _serialize_list(values: list[str]) -> str:
    cleaned = sorted({v.strip() for v in values if v and v.strip()})
    return json.dumps(cleaned)


def _deserialize_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(item) for item in data]
    except json.JSONDecodeError:
        pass
    return []


def _client_to_out(client: OAuthClient) -> OAuthClientOut:
    return OAuthClientOut(
        id=client.id,
        name=client.name,
        client_id=client.client_id,
        is_confidential=client.is_confidential,
        is_active=client.is_active,
        grant_types=_deserialize_list(client.grant_types),
        scopes=_deserialize_list(client.scopes),
        redirect_uris=_deserialize_list(client.redirect_uris),
        created_at=client.created_at,
    )


def _is_openid_client(client: OAuthClient) -> bool:
    return "openid" in _deserialize_list(client.scopes)


def _validate_openid_client(client: OAuthClient) -> None:
    if not _is_openid_client(client):
        raise HTTPException(status_code=400, detail="Client is not configured for OpenID Connect")
    if "authorization_code" not in _deserialize_list(client.grant_types):
        raise HTTPException(status_code=400, detail="OpenID client must allow authorization_code grant")
    if not client.is_confidential:
        raise HTTPException(status_code=400, detail="OpenID client must be confidential")


def _parse_token_request(content_type: str, raw_body: bytes, payload_json: dict | None) -> dict:
    if "application/json" in content_type and payload_json is not None:
        return payload_json

    form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
    single: dict[str, str] = {}
    for key, value in form.items():
        single[key] = value[0] if value else ""
    return single


def _parse_basic_auth(authorization: str | None) -> tuple[str | None, str | None]:
    if not authorization:
        return None, None

    scheme, _, credentials = authorization.partition(" ")
    if scheme.lower() != "basic" or not credentials:
        return None, None

    try:
        decoded = base64.b64decode(credentials).decode("utf-8")
    except Exception:
        return None, None

    client_id, sep, client_secret = decoded.partition(":")
    if not sep:
        return None, None
    return client_id, client_secret


def _validate_scope(scope_value: str, allowed_scopes: list[str]) -> list[str]:
    requested = [s for s in scope_value.split(" ") if s]
    if not requested:
        return allowed_scopes

    unknown = [scope for scope in requested if scope not in allowed_scopes]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Scope is not allowed for this client: {', '.join(unknown)}")
    return requested


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "none":
        return True
    if method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    if method == "S256":
        digest = sha256(code_verifier.encode("utf-8")).digest()
        generated = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
        return secrets.compare_digest(generated, code_challenge)
    return False


async def _issue_user_oauth_tokens(user: User, scopes: list[str]) -> dict:
    access_token, access_exp_ts, _ = create_access_token(user.id, [g.name for g in user.groups], scopes=scopes)
    refresh_token, refresh_exp_ts, _ = create_refresh_token(user.id, [g.name for g in user.groups])
    now_ts = int(datetime.now().timestamp())

    response: dict = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": max(access_exp_ts - now_ts, 0),
        "refresh_token": refresh_token,
        "refresh_expires_in": max(refresh_exp_ts - now_ts, 0),
        "scope": " ".join(scopes),
    }

    if "openid" in scopes:
        id_token, _, _ = create_id_token(user.id, user.email, [g.name for g in user.groups])
        response["id_token"] = id_token

    return response


async def _issue_client_access_token(client: OAuthClient, scopes: list[str]) -> dict:
    subject = f"client:{client.client_id}"
    access_token, access_exp_ts, _ = create_access_token(subject, [], scopes=scopes)
    now_ts = int(datetime.now().timestamp())
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": max(access_exp_ts - now_ts, 0),
        "scope": " ".join(scopes),
    }


async def _resolve_client(
    session: AsyncSession,
    body: dict,
    authorization: str | None,
) -> OAuthClient:
    body_client_id = body.get("client_id")
    body_client_secret = body.get("client_secret")
    header_client_id, header_client_secret = _parse_basic_auth(authorization)

    client_id = header_client_id or body_client_id
    client_secret = header_client_secret or body_client_secret

    if not client_id:
        raise HTTPException(status_code=401, detail="client_id is required")

    client = await session.scalar(select(OAuthClient).where(OAuthClient.client_id == client_id))
    if not client or not client.is_active:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    if client.is_confidential:
        if not client_secret or not client.client_secret_hash:
            raise HTTPException(status_code=401, detail="client_secret is required for confidential clients")
        if not verify_password(client_secret, client.client_secret_hash):
            raise HTTPException(status_code=401, detail="Invalid client credentials")

    return client


async def _register_client(payload: OpenIDClientCreate, session: AsyncSession) -> tuple[OAuthClient, str | None]:
    client_id = f"mm_{secrets.token_urlsafe(18)}"
    client_secret: str | None = None
    client_secret_hash: str | None = None

    if payload.is_confidential:
        client_secret = secrets.token_urlsafe(36)
        client_secret_hash = get_password_hash(client_secret)

    client = OAuthClient(
        name=payload.name,
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        is_confidential=payload.is_confidential,
        is_active=True,
        grant_types=_serialize_list(payload.grant_types),
        scopes=_serialize_list(payload.scopes),
        redirect_uris=_serialize_list(payload.redirect_uris),
    )
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return client, client_secret


async def _create_authorization_code(
    session: AsyncSession,
    client: OAuthClient,
    user: User,
    redirect_uri: str,
    scopes: list[str],
    state: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> dict:
    normalized_challenge = (code_challenge or "").strip()
    normalized_method = (code_challenge_method or "").strip()
    if normalized_challenge:
        if normalized_method not in {"plain", "S256"}:
            raise HTTPException(status_code=400, detail="code_challenge_method must be plain or S256")
    else:
        normalized_method = "none"

    code = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    auth_code = OAuthAuthorizationCode(
        code=code,
        client_id=client.id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=" ".join(scopes),
        code_challenge=normalized_challenge,
        code_challenge_method=normalized_method,
        expires_at=expires_at,
        used=False,
    )
    session.add(auth_code)
    await session.commit()
    _audit(
        "openid_authorize_code_issued",
        user=_anon(str(user.id)),
        client=_anon(client.client_id),
        scopes=",".join(scopes),
        pkce=bool(normalized_challenge),
    )

    query = {"code": code}
    if state is not None:
        query["state"] = state
    redirect_to = f"{redirect_uri}?{urlencode(query)}"

    return {
        "code": code,
        "state": state,
        "redirect_to": redirect_to,
        "expires_at": expires_at.isoformat(),
    }


async def _oauth_authorize_impl(
    payload: OAuthAuthorizeRequest,
    session: AsyncSession,
    openid_only: bool = False,
):
    client = await session.scalar(select(OAuthClient).where(OAuthClient.client_id == payload.client_id))
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if openid_only:
        _validate_openid_client(client)

    grant_types = _deserialize_list(client.grant_types)
    if "authorization_code" not in grant_types:
        raise HTTPException(status_code=400, detail="Client does not allow authorization_code grant")

    redirect_uris = _deserialize_list(client.redirect_uris)
    if payload.redirect_uri not in redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    user: User | None = await session.scalar(select(User).where(User.email == payload.username))
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    scopes = _validate_scope(payload.scope, _deserialize_list(client.scopes))
    if openid_only and "openid" not in scopes:
        raise HTTPException(status_code=400, detail="OpenID scope is required for /openid/authorize")

    return await _create_authorization_code(
        session=session,
        client=client,
        user=user,
        redirect_uri=payload.redirect_uri,
        scopes=scopes,
        state=payload.state,
        code_challenge=payload.code_challenge,
        code_challenge_method=payload.code_challenge_method,
    )


async def _oauth_token_impl(
    request: Request,
    session: AsyncSession,
    authorization: str | None,
    openid_only: bool = False,
):
    content_type = (request.headers.get("content-type") or "").lower()
    raw_body = await request.body()
    payload_json = await request.json() if "application/json" in content_type else None
    body = _parse_token_request(content_type, raw_body, payload_json)

    grant_type = body.get("grant_type")
    if not grant_type:
        raise HTTPException(status_code=400, detail="grant_type is required")

    header_client_id, _ = _parse_basic_auth(authorization)
    has_client_identity = bool(header_client_id or body.get("client_id"))
    if not openid_only and not has_client_identity:
        scope_value = body.get("scope", "")
        scopes = [s for s in scope_value.split(" ") if s]

        if grant_type == "password":
            username = body.get("username")
            password = body.get("password")
            if not username or not password:
                raise HTTPException(status_code=400, detail="username and password are required for password grant")

            user: User | None = await session.scalar(select(User).where(User.email == username))
            if not user or not verify_password(password, user.hashed_password):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
            return await _issue_user_oauth_tokens(user, scopes)

        if grant_type == "refresh_token":
            refresh_token = body.get("refresh_token")
            if not refresh_token:
                raise HTTPException(status_code=400, detail="refresh_token is required for refresh_token grant")

            try:
                token_data = decode_token(refresh_token)
            except JWTError:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

            if token_data.type != "refresh":
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a refresh token")

            user: User | None = await session.scalar(select(User).where(User.id == token_data.sub))
            if not user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
            return await _issue_user_oauth_tokens(user, scopes)

        raise HTTPException(status_code=400, detail=f"client_id is required for grant_type={grant_type}")

    if openid_only and grant_type == "client_credentials":
        raise HTTPException(status_code=400, detail="grant_type=client_credentials is not supported for /openid/token")

    client = await _resolve_client(session, body, authorization)
    if openid_only:
        _validate_openid_client(client)

    grant_types = _deserialize_list(client.grant_types)
    if grant_type not in grant_types:
        raise HTTPException(status_code=400, detail=f"This client does not allow grant_type={grant_type}")

    allowed_scopes = _deserialize_list(client.scopes)
    scopes = _validate_scope(body.get("scope", ""), allowed_scopes)
    if openid_only and "openid" not in scopes:
        raise HTTPException(status_code=400, detail="OpenID scope is required for /openid/token")

    if grant_type == "password":
        username = body.get("username")
        password = body.get("password")
        if not username or not password:
            raise HTTPException(status_code=400, detail="username and password are required for password grant")

        user: User | None = await session.scalar(select(User).where(User.email == username))
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
        tokens = await _issue_user_oauth_tokens(user, scopes)
        if openid_only:
            _audit(
                "openid_token_issued",
                grant_type=grant_type,
                user=_anon(str(user.id)),
                client=_anon(client.client_id),
                scopes=",".join(scopes),
            )
        return tokens

    if grant_type == "refresh_token":
        refresh_token = body.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="refresh_token is required for refresh_token grant")

        try:
            token_data = decode_token(refresh_token)
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        if token_data.type != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a refresh token")

        user: User | None = await session.scalar(select(User).where(User.id == token_data.sub))
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        tokens = await _issue_user_oauth_tokens(user, scopes)
        if openid_only:
            _audit(
                "openid_token_issued",
                grant_type=grant_type,
                user=_anon(str(user.id)),
                client=_anon(client.client_id),
                scopes=",".join(scopes),
            )
        return tokens

    if grant_type == "client_credentials":
        return await _issue_client_access_token(client, scopes)

    if grant_type == "authorization_code":
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")
        code_verifier = body.get("code_verifier")
        if not code or not redirect_uri:
            raise HTTPException(status_code=400, detail="code and redirect_uri are required for authorization_code grant")

        auth_code = await session.scalar(select(OAuthAuthorizationCode).where(OAuthAuthorizationCode.code == code))
        if not auth_code:
            raise HTTPException(status_code=401, detail="Invalid authorization code")

        if auth_code.used:
            raise HTTPException(status_code=401, detail="Authorization code already used")

        if datetime.now(timezone.utc) > auth_code.expires_at:
            raise HTTPException(status_code=401, detail="Authorization code expired")

        if auth_code.client_id != client.id:
            raise HTTPException(status_code=401, detail="Authorization code was not issued for this client")

        if auth_code.redirect_uri != redirect_uri:
            raise HTTPException(status_code=401, detail="redirect_uri does not match authorization code")

        if auth_code.code_challenge:
            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier is required for PKCE authorization code")
            if not _verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
                raise HTTPException(status_code=401, detail="PKCE verification failed")

        user: User | None = await session.scalar(select(User).where(User.id == auth_code.user_id))
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        auth_code.used = True
        await session.commit()

        code_scopes = [scope for scope in auth_code.scope.split(" ") if scope]
        if openid_only and "openid" not in code_scopes:
            raise HTTPException(status_code=400, detail="Authorization code scope does not include openid")
        tokens = await _issue_user_oauth_tokens(user, code_scopes)
        if openid_only:
            _audit(
                "openid_token_issued",
                grant_type=grant_type,
                user=_anon(str(user.id)),
                client=_anon(client.client_id),
                scopes=",".join(code_scopes),
            )
        return tokens

    raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")


def _get_github_oauth_config() -> tuple[bool, str | None, str | None, str | None]:
    if not settings.github_oauth_enabled:
        return False, None, None, "GitHub OAuth is disabled (GITHUB_OAUTH_ENABLED=false)."
    if not settings.github_client_id or not settings.github_client_secret:
        return False, None, None, "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be configured."
    redirect_uri = settings.github_redirect_uri or f"{settings.auth_issuer.rstrip('/')}/oauth/github/callback"
    return True, settings.github_client_id, redirect_uri, None


async def _fetch_github_verified_email(client: httpx.AsyncClient, access_token: str, fallback_email: str | None) -> str:
    if fallback_email:
        return fallback_email

    emails_res = await client.get(
        "https://api.github.com/user/emails",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
    )
    if emails_res.status_code >= 400:
        raise HTTPException(status_code=400, detail="Unable to fetch user email from GitHub")

    emails_data = emails_res.json()
    if not isinstance(emails_data, list):
        raise HTTPException(status_code=400, detail="Unexpected GitHub email payload")

    primary_verified = next(
        (item.get("email") for item in emails_data if item.get("primary") and item.get("verified") and item.get("email")),
        None,
    )
    if primary_verified:
        return str(primary_verified)

    any_verified = next((item.get("email") for item in emails_data if item.get("verified") and item.get("email")), None)
    if any_verified:
        return str(any_verified)

    any_email = next((item.get("email") for item in emails_data if item.get("email")), None)
    if any_email:
        return str(any_email)

    raise HTTPException(status_code=400, detail="GitHub account has no accessible email")


@router.get("/oauth/github/login")
async def oauth_github_login(
    redirect: bool = Query(default=True, description="When true, redirect to GitHub authorize URL"),
    state: str | None = Query(default=None),
):
    enabled, github_client_id, redirect_uri, reason = _get_github_oauth_config()
    if not enabled:
        raise HTTPException(status_code=503, detail=f"GitHub OAuth unavailable: {reason}")

    auth_state = state or secrets.token_urlsafe(24)
    params = {
        "client_id": github_client_id,
        "redirect_uri": redirect_uri,
        "scope": settings.github_scope,
        "state": auth_state,
        "allow_signup": "true",
    }
    authorization_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"

    if redirect:
        return RedirectResponse(url=authorization_url, status_code=302)
    return {
        "provider": "github",
        "authorization_url": authorization_url,
        "state": auth_state,
    }


@router.get("/oauth/github/callback")
async def oauth_github_callback(
    code: str,
    session: AsyncSession = Depends(get_session),
    state: str | None = Query(default=None),
):
    enabled, github_client_id, redirect_uri, reason = _get_github_oauth_config()
    if not enabled:
        raise HTTPException(status_code=503, detail=f"GitHub OAuth unavailable: {reason}")

    async with httpx.AsyncClient(timeout=15.0) as client:
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "state": state or "",
            },
        )
        if token_res.status_code >= 400:
            raise HTTPException(status_code=400, detail="Failed to exchange GitHub authorization code")

        token_data = token_res.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="GitHub access token is missing in callback response")

        profile_res = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
        )
        if profile_res.status_code >= 400:
            raise HTTPException(status_code=400, detail="Unable to fetch user profile from GitHub")

        profile = profile_res.json()
        github_login = profile.get("login")
        email = await _fetch_github_verified_email(client, access_token, profile.get("email"))

    user: User | None = await session.scalar(select(User).where(User.email == email))
    is_new_user = False
    if not user:
        is_new_user = True
        user = User(email=email, hashed_password=get_password_hash(secrets.token_urlsafe(48)))
        default_group = await ensure_group_exists(session, "user")
        user.groups.append(default_group)
        session.add(user)
        await session.commit()
        await session.refresh(user)

    tokens = await _issue_user_oauth_tokens(user, scopes=["profile", "email"])
    _audit(
        "github_login_success",
        user=_anon(str(user.id)),
        new_user=is_new_user,
    )
    return {
        "provider": "github",
        "state": state,
        "github_login": github_login,
        "email": email,
        "is_new_user": is_new_user,
        **tokens,
    }
