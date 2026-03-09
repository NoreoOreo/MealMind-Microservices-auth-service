# MealMind Auth Service

Минимальный сервис авторизации на FastAPI + SQLAlchemy + Redis Queue.

## Стек
- FastAPI (JWT, 3 API: `/register`, `/login`, `/logout`)
- SQLAlchemy 2.0 (async) + PostgreSQL (через `asyncpg`)
- Redis 5 (очередь `auth:queue` для RPC)

## Запуск
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET_KEY='change-me'                # поменяйте секрет
export DATABASE_URL='postgresql+asyncpg://auth:auth@localhost:5432/auth'
export REDIS_URL='redis://localhost:6379/0'
uvicorn app.main:app --reload
```

## API
- `POST /register` — email + пароль дважды (`password`, `password_confirm`), опционально `groups` (список имён групп). Создаёт пользователя и привязывает группы (по умолчанию `user`). Пароли должны совпадать.
- `POST /login` — email/пароль, возвращает пару токенов: access (короткий) и refresh (долгий).
- `POST /refresh` — принимает refresh token, возвращает новую пару токенов (старый refresh отзывается).
- `POST /refresh` — принимает refresh token, возвращает новую пару токенов.
- `CRUD /permissions` — управление разрешениями (требуются права `auth:write`).
- `CRUD /groups` — управление группами и их разрешениями (требуются права `auth:write`).

## Redis Queue listener
Фоновой consumer слушает только одну очередь `auth:queue` и маршрутизирует по `action`. Поддерживаемые действия:

- `authorize` — провалидировать access‑token и вернуть данные пользователя (UUID `id`, группы/permissions).
- `logout` — no-op, просто подтверждает, что запрос дошёл (blacklist отключён).
- `user:get` / `login` — алиасы для `authorize`.

Кто запрашивает, обязан передать свою очередь в поле `refer` (alias: `answer`/`reply_key`). Ответы публикуются туда же. Примеры:
```json
{ "action": "authorize", "token": "<access_token>", "refer": "profile:queue" }
{ "action": "logout",    "token": "<access_token>", "refer": "profile:queue" }
```
Ответ кладётся в Redis‑лист по ключу `refer` (или alias). Если ключ не передан — только пишем в логи и вернём ошибку `missing_refer`.

## Docker
Собрать и запустить (нужен внешний Postgres/Redis по env):
```bash
docker build -t auth-service .
docker run --rm -p 8000:8000 \
  -e JWT_SECRET_KEY=change-me \
  -e DATABASE_URL=postgresql+asyncpg://auth:auth@host.docker.internal:5432/auth \
  -e REDIS_URL=redis://host.docker.internal:6379/0 \
  auth-service
```

## Пример .env
Скопируйте `.env.example` в `.env` и при необходимости поменяйте значения:
```
DATABASE_URL=postgresql+asyncpg://auth:auth@localhost:5432/auth
JWT_SECRET_KEY=change-me
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_MINUTES=10080
REDIS_URL=redis://localhost:6379/0
REDIS_JWT_BLACKLIST_KEY=jwt:blacklist
REDIS_QUEUE_KEY=auth:queue
```
