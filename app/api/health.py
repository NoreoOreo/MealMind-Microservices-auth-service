import logging

from fastapi import APIRouter
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.redis_client import get_redis
from app.schemas import Message

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)


@router.get("/health", response_model=Message, include_in_schema=False)
async def health() -> Message:
    redis = await get_redis()
    redis_ok = await redis.ping()
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(select(1))
        db_ok = True
    except Exception as exc:  # pragma: no cover
        db_ok = False
        logger.exception("DB health check failed: %s", exc)
    return Message(message=f"ok|redis:{redis_ok}|db:{db_ok}|fastapi:true")
