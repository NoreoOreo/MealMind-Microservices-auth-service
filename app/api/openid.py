from html import escape

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session
from app.models import OAuthClient, User
from app.schemas import OAuthAuthorizeRequest, OAuthClientOut, OAuthClientRegisterResponse, OpenIDClientCreate
from app.security import decode_token, get_current_user, get_jwks, get_oidc_status, require_permission, verify_password
from app.api.oauth import (
    _anon,
    _audit,
    _client_to_out,
    _create_authorization_code,
    _deserialize_list,
    _oauth_authorize_impl,
    _oauth_token_impl,
    _register_client,
    _validate_openid_client,
    _validate_scope,
)

router = APIRouter(tags=["openid"])
settings = get_settings()


@router.post("/openid/clients", response_model=OAuthClientRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_openid_client(
    payload: OpenIDClientCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    await require_permission("auth:write", current_user=current_user)
    client, client_secret = await _register_client(payload, session)
    out = _client_to_out(client)
    return OAuthClientRegisterResponse(**out.model_dump(), client_secret=client_secret)


@router.get("/openid/clients", response_model=list[OAuthClientOut])
async def list_openid_clients(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    await require_permission("auth:read", current_user=current_user)
    clients = (await session.scalars(select(OAuthClient).order_by(OAuthClient.created_at.desc()))).all()
    return [_client_to_out(client) for client in clients if "openid" in _deserialize_list(client.scopes)]


@router.get("/openid/authorize", response_class=HTMLResponse)
async def openid_authorize_browser(
    request: Request,
    session: AsyncSession = Depends(get_session),
    response_type: str = Query(default="code"),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="openid profile email"),
    state: str | None = Query(default=None),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")

    client = await session.scalar(select(OAuthClient).where(OAuthClient.client_id == client_id))
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="Unknown client_id")
    _validate_openid_client(client)

    redirect_uris = _deserialize_list(client.redirect_uris)
    if redirect_uri not in redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    scopes = _validate_scope(scope, _deserialize_list(client.scopes))
    if "openid" not in scopes:
        raise HTTPException(status_code=400, detail="OpenID scope is required")
    _audit(
        "openid_authorize_requested",
        client=_anon(client.client_id),
        scopes=",".join(scopes),
        pkce=bool(code_challenge),
    )

    method = (code_challenge_method or "").strip() or "none"
    if code_challenge and method not in {"plain", "S256"}:
        raise HTTPException(status_code=400, detail="code_challenge_method must be plain or S256")
    if not code_challenge and method not in {"none", ""}:
        raise HTTPException(status_code=400, detail="code_challenge_method requires code_challenge")

    # Use a relative action so reverse-proxy prefixes (e.g. /api/v1/auth) are preserved in browser requests.
    form_action = "authorize/login"
    html = f"""
<!doctype html>
<html>
  <head><meta charset=\"utf-8\"><title>MealMind OpenID Login</title></head>
  <body style=\"font-family: sans-serif; max-width: 420px; margin: 40px auto;\">
    <h2>Sign in</h2>
    <p>Client: <strong>{escape(client.name)}</strong></p>
    <form method=\"post\" action=\"{escape(form_action)}\">
      <input type=\"hidden\" name=\"client_id\" value=\"{escape(client_id)}\">
      <input type=\"hidden\" name=\"redirect_uri\" value=\"{escape(redirect_uri)}\">
      <input type=\"hidden\" name=\"scope\" value=\"{escape(scope)}\">
      <input type=\"hidden\" name=\"state\" value=\"{escape(state or '')}\">
      <input type=\"hidden\" name=\"code_challenge\" value=\"{escape(code_challenge or '')}\">
      <input type=\"hidden\" name=\"code_challenge_method\" value=\"{escape(method)}\">
      <label>Email<br><input type=\"email\" name=\"username\" style=\"width: 100%;\"></label><br><br>
      <label>Password<br><input type=\"password\" name=\"password\" style=\"width: 100%;\"></label><br><br>
      <p style=\"margin: 4px 0 8px 0; color: #666;\">OR use existing access token</p>
      <label>Access token<br><textarea name=\"access_token\" rows=\"6\" style=\"width: 100%;\"></textarea></label><br><br>
      <button type=\"submit\">Login</button>
    </form>
  </body>
</html>
"""
    return HTMLResponse(content=html)


@router.post("/openid/authorize/login")
async def openid_authorize_login(
    session: AsyncSession = Depends(get_session),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(default="openid profile email"),
    state: str | None = Form(default=None),
    code_challenge: str | None = Form(default=None),
    code_challenge_method: str | None = Form(default=None),
    username: str | None = Form(default=None),
    password: str | None = Form(default=None),
    access_token: str | None = Form(default=None),
):
    client = await session.scalar(select(OAuthClient).where(OAuthClient.client_id == client_id))
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="Unknown client_id")
    _validate_openid_client(client)

    redirect_uris = _deserialize_list(client.redirect_uris)
    if redirect_uri not in redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    scopes = _validate_scope(scope, _deserialize_list(client.scopes))
    if "openid" not in scopes:
        raise HTTPException(status_code=400, detail="OpenID scope is required")

    token_value = (access_token or "").strip()
    if token_value:
        try:
            token_data = decode_token(token_value, expected_type="access")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid access_token")
        user = await session.scalar(select(User).where(User.id == token_data.sub))
        if not user:
            raise HTTPException(status_code=401, detail="User from access_token was not found")
    else:
        if not username or not password:
            raise HTTPException(status_code=400, detail="Provide either access_token or username/password")
        user = await session.scalar(select(User).where(User.email == username))
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    _audit(
        "openid_authorize_authenticated",
        user=_anon(str(user.id)),
        client=_anon(client.client_id),
        method="access_token" if token_value else "password",
    )

    result = await _create_authorization_code(
        session=session,
        client=client,
        user=user,
        redirect_uri=redirect_uri,
        scopes=scopes,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    return RedirectResponse(url=result["redirect_to"], status_code=302)


@router.post("/openid/authorize")
async def openid_authorize(payload: OAuthAuthorizeRequest, session: AsyncSession = Depends(get_session)):
    return await _oauth_authorize_impl(payload, session, openid_only=True)


@router.post("/openid/token")
async def openid_token(
    request: Request,
    session: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
):
    return await _oauth_token_impl(request, session, authorization, openid_only=True)


@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    enabled, reason = get_oidc_status()
    if not enabled:
        raise HTTPException(status_code=503, detail=f"OpenID Connect unavailable: {reason}")

    issuer = settings.auth_issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/openid/authorize",
        "token_endpoint": f"{issuer}/openid/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [settings.jwt_algorithm],
        "grant_types_supported": ["authorization_code", "password", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "claims_supported": ["sub", "email", "email_verified", "groups"],
        "code_challenge_methods_supported": ["plain", "S256"],
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
