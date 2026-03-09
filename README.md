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
export ACCESS_TOKEN_EXPIRE_MINUTES=60
export REFRESH_TOKEN_EXPIRE_MINUTES=10080
export REDIS_URL='redis://localhost:6379/0'
# service-account passwords (optional)
export PROFILE_ADMIN_PASSWORD='changeme'
export MEAL_ADMIN_PASSWORD='changeme'
export AI_ADMIN_PASSWORD='changeme'

python main.py --reload
```

## API (prefix `/api/v1`)
- `POST /register` – email, `password`, `password_confirm`, optional `groups` (default group `user`).
- `POST /login` – returns `access_token` + `refresh_token`.
- `POST /refresh` – takes refresh, returns new access/refresh pair.
- `GET/POST/PUT/DELETE /permissions` – manage permissions (requires `auth:write`).
- `GET/POST/PUT/DELETE /groups` – manage groups and their permissions (requires `auth:write`).

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
