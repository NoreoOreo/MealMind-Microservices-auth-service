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
- `POST /oauth/token` – OAuth2 token endpoint (`grant_type=password|refresh_token`).
- `GET /userinfo` – OpenID UserInfo style endpoint (Bearer token required).
- `GET /.well-known/openid-configuration` – OpenID Connect discovery metadata.
- `GET /.well-known/jwks.json` – JWK set for token verification.
- `GET/POST/PUT/DELETE /permissions` – manage permissions (requires `auth:write`).
- `GET/POST/PUT/DELETE /groups` – manage groups and their permissions (requires `auth:write`).

## OAuth2 / OpenID Connect notes
- OAuth2 is implemented via `/oauth/token` with `password` and `refresh_token` grants.
- OpenID Connect is available only with asymmetric signing (`JWT_ALGORITHM=RS256`), configured `JWT_PRIVATE_KEY` + `JWT_PUBLIC_KEY`, and non-empty `AUTH_AUDIENCE`.
- If the service runs with `HS256`, OIDC discovery/JWKS endpoints return `503` and explain why (symmetric key cannot be safely published as JWKS).

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
