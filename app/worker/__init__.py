import asyncio
import logging
import json

from app.config import get_settings
from app.redis_client import get_redis
from app.worker.handlers import ACTION_HANDLERS, EVENT_HANDLERS

logger = logging.getLogger(__name__)
settings = get_settings()


async def handle_message(redis, raw: str) -> None:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Invalid JSON from queue: %s", raw)
        return

    event_type = payload.get("event_type")
    if event_type and event_type in EVENT_HANDLERS:
        handler = EVENT_HANDLERS[event_type]
    else:
        action = payload.get("action") or "authorize"
        handler = ACTION_HANDLERS.get(action)
        if not handler:
            logger.info("Unhandled action/event payload=%s", payload)
            return

    try:
        await handler(redis, payload)
    except Exception as exc:  # pragma: no cover
        logger.exception("Error processing action=%s payload=%s err=%s", action, payload, exc)


async def consume_queue() -> None:
    redis = await get_redis()
    logger.info("Starting Redis queue consumer on %s", settings.redis_queue_key)
    while True:
        try:
            item = await redis.blpop(settings.redis_queue_key, timeout=0)
            if item is None:
                await asyncio.sleep(1)
                continue
            _, raw = item
            await handle_message(redis, raw)
        except asyncio.CancelledError:
            logger.info("Queue consumer cancelled")
            raise
        except Exception as exc:  # pragma: no cover - safety net
            logger.exception("Queue consumer error: %s", exc)
            await asyncio.sleep(1)
