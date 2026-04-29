import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode

from authlib.common.security import generate_token
from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.oauth2.rfc6749.util import extract_basic_authorization
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi import HTTPException, Request, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import OAuthAuthorizationCode, OAuthClient, User
from app.oauth.authlib_adapter import authenticate_client as authlib_authenticate_client
from app.schemas import OAuthClientCreate, OAuthAuthorizeRequest, OAuthClientOut, OpenIDClientCreate
from app.security import (
    create_access_token,
    create_id_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)

logger = logging.getLogger("auth.audit")


def anon(value: str | None) -> str:
    if not value:
        return "na"
    # Keep stable short anonymization without leaking identifiers.
    return create_s256_code_challenge(value.encode("utf-8").hex())[:12]


def audit(event: str, **fields) -> None:
    parts = [f"event={event}"]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    logger.info(" ".join(parts))


def serialize_list(values: list[str]) -> str:
    cleaned = sorted({v.strip() for v in values if v and v.strip()})
    return json.dumps(cleaned)


def deserialize_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(item) for item in data]
    except json.JSONDecodeError:
        pass
    return []


def client_to_out(client: OAuthClient) -> OAuthClientOut:
    return OAuthClientOut(
        id=client.id,
        name=client.name,
        client_id=client.client_id,
        is_confidential=client.is_confidential,
        is_active=client.is_active,
        grant_types=deserialize_list(client.grant_types),
        scopes=deserialize_list(client.scopes),
        redirect_uris=deserialize_list(client.redirect_uris),
        created_at=client.created_at,
    )


def is_openid_client(client: OAuthClient) -> bool:
    return "openid" in deserialize_list(client.scopes)


def validate_openid_client(client: OAuthClient) -> None:
    if not is_openid_client(client):
        raise HTTPException(status_code=400, detail="Client is not configured for OpenID Connect")
    if "authorization_code" not in deserialize_list(client.grant_types):
        raise HTTPException(status_code=400, detail="OpenID client must allow authorization_code grant")
    if not client.is_confidential:
        raise HTTPException(status_code=400, detail="OpenID client must be confidential")


def parse_token_request(content_type: str, raw_body: bytes, payload_json: dict | None) -> dict:
    if "application/json" in content_type and payload_json is not None:
        return payload_json

    form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
    single: dict[str, str] = {}
    for key, value in form.items():
        single[key] = value[0] if value else ""
    return single


def validate_scope(scope_value: str, allowed_scopes: list[str]) -> list[str]:
    requested = [s for s in scope_value.split(" ") if s]
    if not requested:
        return allowed_scopes

    unknown = [scope for scope in requested if scope not in allowed_scopes]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Scope is not allowed for this client: {', '.join(unknown)}")
    return requested


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "none":
        return True
    if method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    if method == "S256":
        generated = create_s256_code_challenge(code_verifier)
        return secrets.compare_digest(generated, code_challenge)
    return False


def _scopes_from_body(body: dict) -> list[str]:
    return [s for s in (body.get("scope", "") or "").split(" ") if s]


async def _user_from_password_grant(session: AsyncSession, body: dict) -> User:
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required for password grant")

    user: User | None = await session.scalar(select(User).where(User.email == username))
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    return user


async def _user_from_refresh_token_grant(session: AsyncSession, body: dict) -> User:
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
    return user


async def _issue_tokens_for_user_grant(
    session: AsyncSession,
    body: dict,
    scopes: list[str],
    grant_type: str,
    openid_only: bool = False,
    client: OAuthClient | None = None,
) -> dict:
    if grant_type == "password":
        user = await _user_from_password_grant(session, body)
    elif grant_type == "refresh_token":
        user = await _user_from_refresh_token_grant(session, body)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")

    tokens = await issue_user_tokens(user, scopes)
    if openid_only and client:
        audit(
            "openid_token_issued",
            grant_type=grant_type,
            user=anon(str(user.id)),
            client=anon(client.client_id),
            scopes=",".join(scopes),
        )
    return tokens


async def issue_user_tokens(user: User, scopes: list[str]) -> dict:
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


async def issue_client_access_token(client: OAuthClient, scopes: list[str]) -> dict:
    subject = f"client:{client.client_id}"
    access_token, access_exp_ts, _ = create_access_token(subject, [], scopes=scopes)
    now_ts = int(datetime.now().timestamp())
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": max(access_exp_ts - now_ts, 0),
        "scope": " ".join(scopes),
    }


async def register_client(payload: OAuthClientCreate | OpenIDClientCreate, session: AsyncSession) -> tuple[OAuthClient, str | None]:
    client_id = f"mm_{generate_token(24)}"
    client_secret: str | None = None
    client_secret_hash: str | None = None

    if payload.is_confidential:
        client_secret = generate_token(48)
        client_secret_hash = get_password_hash(client_secret)

    client = OAuthClient(
        name=payload.name,
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        is_confidential=payload.is_confidential,
        is_active=True,
        grant_types=serialize_list(payload.grant_types),
        scopes=serialize_list(payload.scopes),
        redirect_uris=serialize_list(payload.redirect_uris),
    )
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return client, client_secret


async def create_authorization_code(
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

    code = generate_token(64)
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
    audit(
        "openid_authorize_code_issued",
        user=anon(str(user.id)),
        client=anon(client.client_id),
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


async def oauth_authorize_impl(
    payload: OAuthAuthorizeRequest,
    session: AsyncSession,
    openid_only: bool = False,
):
    client = await session.scalar(select(OAuthClient).where(OAuthClient.client_id == payload.client_id))
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if openid_only:
        validate_openid_client(client)

    grant_types = deserialize_list(client.grant_types)
    if "authorization_code" not in grant_types:
        raise HTTPException(status_code=400, detail="Client does not allow authorization_code grant")

    redirect_uris = deserialize_list(client.redirect_uris)
    if payload.redirect_uri not in redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    user: User | None = await session.scalar(select(User).where(User.email == payload.username))
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    scopes = validate_scope(payload.scope, deserialize_list(client.scopes))
    if openid_only and "openid" not in scopes:
        raise HTTPException(status_code=400, detail="OpenID scope is required for /openid/authorize")

    return await create_authorization_code(
        session=session,
        client=client,
        user=user,
        redirect_uri=payload.redirect_uri,
        scopes=scopes,
        state=payload.state,
        code_challenge=payload.code_challenge,
        code_challenge_method=payload.code_challenge_method,
    )


async def oauth_token_impl(
    request: Request,
    session: AsyncSession,
    authorization: str | None,
    openid_only: bool = False,
):
    content_type = (request.headers.get("content-type") or "").lower()
    raw_body = await request.body()
    payload_json = await request.json() if "application/json" in content_type else None
    body = parse_token_request(content_type, raw_body, payload_json)

    grant_type = body.get("grant_type")
    if not grant_type:
        raise HTTPException(status_code=400, detail="grant_type is required")

    header_client_id, _ = extract_basic_authorization({"authorization": authorization} if authorization else {})
    has_client_identity = bool(header_client_id or body.get("client_id"))
    if not openid_only and not has_client_identity:
        scopes = _scopes_from_body(body)
        if grant_type in {"password", "refresh_token"}:
            return await _issue_tokens_for_user_grant(
                session=session,
                body=body,
                scopes=scopes,
                grant_type=grant_type,
                openid_only=False,
                client=None,
            )

        raise HTTPException(status_code=400, detail=f"client_id is required for grant_type={grant_type}")

    if openid_only and grant_type == "client_credentials":
        raise HTTPException(status_code=400, detail="grant_type=client_credentials is not supported for /openid/token")

    try:
        client = await authlib_authenticate_client(session, body, authorization)
    except InvalidClientError as exc:
        raise HTTPException(status_code=exc.status_code or 401, detail=exc.description or "Invalid client credentials")
    if openid_only:
        validate_openid_client(client)

    grant_types = deserialize_list(client.grant_types)
    if grant_type not in grant_types:
        raise HTTPException(status_code=400, detail=f"This client does not allow grant_type={grant_type}")

    allowed_scopes = deserialize_list(client.scopes)
    scopes = validate_scope(body.get("scope", ""), allowed_scopes)
    if openid_only and "openid" not in scopes:
        raise HTTPException(status_code=400, detail="OpenID scope is required for /openid/token")

    if grant_type in {"password", "refresh_token"}:
        return await _issue_tokens_for_user_grant(
            session=session,
            body=body,
            scopes=scopes,
            grant_type=grant_type,
            openid_only=openid_only,
            client=client,
        )

    if grant_type == "client_credentials":
        return await issue_client_access_token(client, scopes)

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
            if not verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
                raise HTTPException(status_code=401, detail="PKCE verification failed")

        user: User | None = await session.scalar(select(User).where(User.id == auth_code.user_id))
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        auth_code.used = True
        await session.commit()

        code_scopes = [scope for scope in auth_code.scope.split(" ") if scope]
        if openid_only and "openid" not in code_scopes:
            raise HTTPException(status_code=400, detail="Authorization code scope does not include openid")
        tokens = await issue_user_tokens(user, code_scopes)
        if openid_only:
            audit(
                "openid_token_issued",
                grant_type=grant_type,
                user=anon(str(user.id)),
                client=anon(client.client_id),
                scopes=",".join(code_scopes),
            )
        return tokens

    raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")
