import json
import logging

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def extract_reply_key(payload: dict) -> str | None:
    """Resolve reply queue from new and legacy fields."""
    return (
        payload.get("target")
        or payload.get("refer")
        or payload.get("answer")
        or payload.get("reply_key")
    )


async def publish(redis, key: str | None, message: dict) -> None:
    if not key:
        logger.info("No reply key provided, message=%s", message)
        return
    await redis.rpush(key, json.dumps(message))
