import logging
import uuid
from typing import Tuple

from jose import JWTError
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Group, User
from app.security import decode_token, is_token_blacklisted
from app.worker.utils import publish, extract_reply_key

logger = logging.getLogger(__name__)
settings = get_settings()


async def _get_user_payload(session, user_id: str):
    user = await session.scalar(
        select(User)
        .options(selectinload(User.groups).selectinload(Group.permissions))
        .where(User.id == user_id)
    )
    if not user:
        return None
    return {
        "id": user.id,
        "email": user.email,
        "groups": [
            {
                "id": group.id,
                "name": group.name,
                "permissions": [perm.name for perm in group.permissions],
            }
            for group in user.groups
        ],
    }


async def _validate_access_token(redis, payload: dict, action: str) -> Tuple[object, str | None]:
    reply_key = extract_reply_key(payload)
    if not reply_key:
        await publish(redis, None, {"action": action, "status": "error", "reason": "missing_refer"})
        return None, None
    token = payload.get("token")
    if not token:
        await publish(redis, reply_key, {"action": action, "status": "error", "reason": "missing_token"})
        return None, reply_key
    try:
        token_data = decode_token(token, expected_type="access")
    except JWTError:
        await publish(redis, reply_key, {"action": action, "status": "error", "reason": "invalid_token"})
        return None, reply_key
    if await is_token_blacklisted(token_data.jti):
        await publish(redis, reply_key, {"action": action, "status": "error", "reason": "token_revoked"})
        return None, reply_key
    return token_data, reply_key


async def handle_authorize(redis, payload: dict) -> None:
    token_data, reply_key = await _validate_access_token(redis, payload, action="authorize")
    if not token_data:
        return

    async with AsyncSessionLocal() as session:
        user_payload = await _get_user_payload(session, token_data.sub)
        if not user_payload:
            await publish(
                redis,
                reply_key,
                {"action": "authorize", "status": "error", "reason": "user_not_found",
                 "refer": settings.redis_queue_key},
            )
            return
        response = {
            "action": "authorize",
            "status": "ok",
            "user": user_payload,
            "refer": settings.redis_queue_key,
        }
        await publish(redis, reply_key, response)


ACTION_HANDLERS = {
    "authorize": handle_authorize,
}


async def handle_event_authenticate(redis, payload: dict) -> None:
    reply_key = extract_reply_key(payload)
    msg_id = payload.get("message_id") or str(uuid.uuid4())
    jwt_token = payload.get("payload", {}).get("jwt_token")
    if not jwt_token:
        await publish(redis, reply_key, {
            "event_type": "user.authenticate.result",
            "status": "error",
            "reason": "missing_jwt_token",
            "in_reply_to": msg_id,
            "refer": settings.redis_queue_key,
        })
        return

    token_data, _ = await _validate_access_token(redis, {"token": jwt_token, "target": reply_key}, action="authorize")
    if not token_data:
        return

    async with AsyncSessionLocal() as session:
        user_payload = await _get_user_payload(session, token_data.sub)
        if not user_payload:
            await publish(redis, reply_key, {
                "event_type": "user.authenticate.result",
                "status": "error",
                "reason": "user_not_found",
                "in_reply_to": msg_id,
                "refer": settings.redis_queue_key,
            })
            return
    await publish(redis, reply_key, {
        "event_type": "user.authenticate.result",
        "status": "ok",
        "user": user_payload,
        "in_reply_to": msg_id,
        "refer": settings.redis_queue_key,
    })


EVENT_HANDLERS = {
    "user.authenticate": handle_event_authenticate,
}
