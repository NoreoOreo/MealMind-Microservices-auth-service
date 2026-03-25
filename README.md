# MealMind Auth Service

Lightweight auth service on FastAPI + SQLAlchemy + Redis. Provides JWT access/refresh, CRUD for groups/permissions, service accounts, and a single Redis RPC queue (`auth:queue`) for authorization checks.

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export DATABASE_URL='postgresql+asyncpg://auth:auth@localhost:5432/auth'
export JWT_SECRET_KEY='change-me'
export JWT_ALGORITHM='HS256'
export AUTH_ISSUER='http://localhost:8000'
export AUTH_AUDIENCE=''
export OIDC_ENABLED=false
export GITHUB_OAUTH_ENABLED=true
export GITHUB_CLIENT_ID=''
export GITHUB_CLIENT_SECRET=''
export GITHUB_REDIRECT_URI='http://localhost/api/v1/auth/oauth/github/callback'
export ACCESS_TOKEN_EXPIRE_MINUTES=60
export REFRESH_TOKEN_EXPIRE_MINUTES=10080
export REDIS_URL='redis://localhost:6379/0'
# service-account passwords (optional)
export PROFILE_ADMIN_PASSWORD='changeme'
export MEAL_ADMIN_PASSWORD='changeme'
export AI_ADMIN_PASSWORD='changeme'
# rebuild schema on startup (destructive, use once when migrating to UUID ids)
# export RESET_SCHEMA_ON_START=true

python main.py --reload
```

## API (prefix `/api/v1`)
- `POST /register` – email, `password`, `password_confirm`, optional `groups` (default group `user`).
- `POST /login` – returns `access_token` + `refresh_token`.
- `POST /refresh` – takes refresh, returns new access/refresh pair.
- `POST /oauth/clients` – register OAuth client (`auth:write` required).
- `GET /oauth/clients` – list registered OAuth clients (`auth:read` required).
- `POST /oauth/authorize` – issue authorization code (PKCE).
- `POST /oauth/token` – OAuth2 token endpoint (`grant_type=authorization_code|password|refresh_token|client_credentials`).
- `GET /oauth/github/login` – start GitHub OAuth2 login/register flow.
- `GET /oauth/github/callback` – GitHub OAuth2 callback (auto-register + JWT issue).
- `POST /openid/clients` – register OpenID client (`auth:write` required, confidential client with `openid` scope).
- `GET /openid/clients` – list OpenID clients only (`auth:read` required).
- `POST /openid/authorize` – OpenID authorization endpoint (PKCE, requires `openid` scope).
- `POST /openid/token` – OpenID token endpoint (returns `id_token`, requires client_id/client_secret).
- `GET /userinfo` – OpenID UserInfo style endpoint (Bearer token required).
- `GET /.well-known/openid-configuration` – OpenID Connect discovery metadata.
- `GET /.well-known/jwks.json` – JWK set for token verification.
- `GET/POST/PUT/DELETE /permissions` – manage permissions (requires `auth:write`).
- `GET/POST/PUT/DELETE /groups` – manage groups and their permissions (requires `auth:write`).

## OAuth2 / OpenID Connect notes
- OAuth2 clients are stored in DB and can be registered via `/oauth/clients`.
- OAuth2 grants supported: `authorization_code` (with PKCE), `password`, `refresh_token`, `client_credentials`.
- `/oauth/token` validates client credentials (`client_secret_basic` or `client_secret_post`) for confidential clients.
- GitHub OAuth2 registration/login is optional and controlled by env (`GITHUB_OAUTH_ENABLED=true` + client credentials).
- OpenID endpoints are separated from OAuth endpoints: `/openid/clients`, `/openid/authorize`, `/openid/token`.
- OpenID client registration is admin-only and requires confidential client (`client_id` + `client_secret`).
- OpenID Connect is available only with asymmetric signing (`JWT_ALGORITHM=RS256`), configured `JWT_PRIVATE_KEY` + `JWT_PUBLIC_KEY`, and non-empty `AUTH_AUDIENCE`.
- If the service runs with `HS256`, OIDC discovery/JWKS endpoints return `503` and explain why (symmetric key cannot be safely published as JWKS).

### Example flow (authorization_code + PKCE)
1. Register client:
```json
POST /oauth/clients
{
  "name": "web-app",
  "is_confidential": true,
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email"],
  "redirect_uris": ["http://localhost:3000/callback"]
}
```
2. Request authorization code:
```json
POST /oauth/authorize
{
  "client_id": "mm_...",
  "redirect_uri": "http://localhost:3000/callback",
  "scope": "openid profile email",
  "state": "abc123",
  "code_challenge": "<pkce-challenge>",
  "code_challenge_method": "S256",
  "username": "user@example.com",
  "password": "secret"
}
```
3. Exchange code for tokens:
```json
POST /oauth/token
{
  "grant_type": "authorization_code",
  "client_id": "mm_...",
  "client_secret": "...",
  "code": "...",
  "redirect_uri": "http://localhost:3000/callback",
  "code_verifier": "<pkce-verifier>"
}
```

### Grafana login via OpenID
- Register a dedicated OpenID client with redirect URI: `http://localhost:3000/login/generic_oauth`.
- Configure Grafana Generic OAuth with:
  - `auth_url=http://localhost/api/v1/auth/openid/authorize`
  - `token_url=http://auth:8000/openid/token`
  - `api_url=http://auth:8000/userinfo`
- Browser login is served by `GET /openid/authorize` (email/password form), then redirects back to Grafana with `code`.

## Seeding on startup
- Permissions: `auth:*`, `profile:get|write|queue`, `meal:get|write|queue`, `ai:queue`.
- Groups (UUID ids):  
  - `user` → `auth:*`  
  - `admin` → all permissions  
  - `microserves` → only queues (`profile:queue`, `meal:queue`, `ai:queue`)
- Service users (if absent):  
  - `profile@admin.com` / `PROFILE_ADMIN_PASSWORD`  
  - `meal@admin.com` / `MEAL_ADMIN_PASSWORD`  
  - `ai@admin.com` / `AI_ADMIN_PASSWORD`  
  Each belongs to `admin` + `microserves`.

## Docker
```bash
docker build -t auth-service .
docker run --rm -p 8000:8000 \
  -e JWT_SECRET_KEY=change-me \
  -e DATABASE_URL=postgresql+asyncpg://auth:auth@host.docker.internal:5432/auth \
  -e REDIS_URL=redis://host.docker.internal:6379/0 \
  auth-service
```
