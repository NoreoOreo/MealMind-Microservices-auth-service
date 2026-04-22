import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session
from app.models import OAuthClient, User
from app.oauth import (
    anon,
    audit,
    client_to_out,
    issue_user_tokens,
    oauth_authorize_impl,
    oauth_token_impl,
    register_client,
)
from app.schemas import OAuthAuthorizeRequest, OAuthClientCreate, OAuthClientOut, OAuthClientRegisterResponse
from app.security import ensure_group_exists, get_password_hash
from app.security import get_current_user, require_permission

router = APIRouter(tags=["oauth"])
settings = get_settings()


@router.post("/oauth/clients", response_model=OAuthClientRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_oauth_client(
        payload: OAuthClientCreate,
        session: AsyncSession = Depends(get_session),
        current_user: User = Depends(get_current_user),
):
    await require_permission("auth:write", current_user=current_user)
    client, client_secret = await register_client(payload, session)
    out = client_to_out(client)
    return OAuthClientRegisterResponse(**out.model_dump(), client_secret=client_secret)


@router.get("/oauth/clients", response_model=list[OAuthClientOut])
async def list_oauth_clients(
        session: AsyncSession = Depends(get_session),
        current_user: User = Depends(get_current_user),
):
    await require_permission("auth:read", current_user=current_user)
    clients = (await session.scalars(select(OAuthClient).order_by(OAuthClient.created_at.desc()))).all()
    return [client_to_out(client) for client in clients]


@router.post("/oauth/authorize")
async def oauth_authorize(payload: OAuthAuthorizeRequest, session: AsyncSession = Depends(get_session)):
    return await oauth_authorize_impl(payload, session, openid_only=False)


@router.post("/oauth/token")
async def oauth_token(
        request: Request,
        session: AsyncSession = Depends(get_session),
        authorization: str | None = Header(default=None),
):
    return await oauth_token_impl(request, session, authorization, openid_only=False)


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
        (item.get("email") for item in emails_data if
         item.get("primary") and item.get("verified") and item.get("email")),
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

    tokens = await issue_user_tokens(user, scopes=["profile", "email"])
    audit(
        "github_login_success",
        user=anon(str(user.id)),
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
