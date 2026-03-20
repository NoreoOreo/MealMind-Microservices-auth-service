from datetime import datetime
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session
from app.models import User
from app.schemas import LoginRequest, RefreshRequest, TokenPair, UserCreate, UserOut
from app.security import (
    create_access_token,
    create_id_token,
    create_refresh_token,
    decode_token,
    ensure_group_exists,
    get_current_user,
    get_jwks,
    get_oidc_status,
    get_password_hash,
    verify_password,
)

router = APIRouter(tags=["auth"])
settings = get_settings()


async def _issue_oauth_tokens(user: User, scope_value: str = "") -> dict:
    scopes = [s for s in scope_value.split(" ") if s]
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
        enabled, reason = get_oidc_status()
        if not enabled:
            raise HTTPException(status_code=503, detail=f"OpenID Connect is requested but unavailable: {reason}")
        id_token, _, _ = create_id_token(user.id, user.email, [g.name for g in user.groups])
        response["id_token"] = id_token

    return response


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, session: AsyncSession = Depends(get_session)):
    existing = await session.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=payload.email, hashed_password=get_password_hash(payload.password))
    for name in payload.groups or ["user"]:
        group = await ensure_group_exists(session, name)
        user.groups.append(group)

    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_session)):
    user: User | None = await session.scalar(select(User).where(User.email == payload.email))
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    return TokenPair(**(await _issue_oauth_tokens(user)))


@router.post("/refresh", response_model=TokenPair)
async def refresh_tokens(payload: RefreshRequest, session: AsyncSession = Depends(get_session)):
    try:
        token_data = decode_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if token_data.type != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a refresh token")

    user: User | None = await session.scalar(select(User).where(User.id == token_data.sub))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return TokenPair(**(await _issue_oauth_tokens(user)))


@router.post("/oauth/token")
async def oauth_token(
        request: Request,
        session: AsyncSession = Depends(get_session),
):
    content_type = (request.headers.get("content-type") or "").lower()
    grant_type = None
    username = None
    password = None
    refresh_token = None
    scope = ""

    if "application/json" in content_type:
        payload = await request.json()
        grant_type = payload.get("grant_type")
        username = payload.get("username")
        password = payload.get("password")
        refresh_token = payload.get("refresh_token")
        scope = payload.get("scope", "")
    else:
        raw_body = (await request.body()).decode("utf-8")
        form = parse_qs(raw_body, keep_blank_values=True)
        grant_type = (form.get("grant_type") or [None])[0]
        username = (form.get("username") or [None])[0]
        password = (form.get("password") or [None])[0]
        refresh_token = (form.get("refresh_token") or [None])[0]
        scope = (form.get("scope") or [""])[0]

    if not grant_type:
        raise HTTPException(status_code=400, detail="grant_type is required")

    if grant_type == "password":
        if not username or not password:
            raise HTTPException(status_code=400, detail="username and password are required for password grant")
        user: User | None = await session.scalar(select(User).where(User.email == username))
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
        return await _issue_oauth_tokens(user, scope)

    if grant_type == "refresh_token":
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
        return await _issue_oauth_tokens(user, scope)

    raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")


@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    enabled, reason = get_oidc_status()
    if not enabled:
        raise HTTPException(status_code=503, detail=f"OpenID Connect unavailable: {reason}")

    issuer = settings.auth_issuer.rstrip("/")
    return {
        "issuer": issuer,
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [settings.jwt_algorithm],
        "grant_types_supported": ["password", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "claims_supported": ["sub", "email", "email_verified", "groups"],
    }


@router.get("/.well-known/jwks.json")
async def jwks():
    try:
        return get_jwks()
    except JWTError as exc:
        raise HTTPException(status_code=503, detail=f"JWKS unavailable: {str(exc)}")


@router.get("/userinfo")
async def userinfo(current_user: User = Depends(get_current_user)):
    return {
        "sub": current_user.id,
        "email": current_user.email,
        "email_verified": True,
        "groups": [g.name for g in current_user.groups],
    }
