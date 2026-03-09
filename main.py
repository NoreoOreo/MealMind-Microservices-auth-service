"""
Simple entrypoint to run the Auth service locally.

Usage:
  python main.py                 # start FastAPI + background queue consumer
  python main.py --reload        # same, with auto-reload (dev)
  python main.py --worker-only   # run only the Redis queue consumer
"""

import argparse
import asyncio

import uvicorn

from app.database import AsyncSessionLocal, init_db
from app.events import seed_defaults
from app.worker import consume_queue


async def _bootstrap_worker_only() -> None:
    # Ensure DB schema + seeds match API startup behaviour before consuming queue.
    await init_db()
    async with AsyncSessionLocal() as session:
        await seed_defaults(session)
        await session.commit()
    await consume_queue()


def run_api(host: str, port: int, reload: bool) -> None:
    uvicorn.run("app.main:app", host=host, port=port, reload=reload, factory=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Auth service runner for local debugging")
    parser.add_argument("--worker-only", action="store_true", help="run only Redis consumer (no HTTP API)")
    parser.add_argument("--host", default="0.0.0.0", help="bind host for HTTP API")
    parser.add_argument("--port", type=int, default=8000, help="bind port for HTTP API")
    parser.add_argument("--reload", action="store_true", help="enable FastAPI autoreload (dev only)")
    args = parser.parse_args()

    if args.worker_only:
        asyncio.run(_bootstrap_worker_only())
    else:
        run_api(args.host, args.port, args.reload)


if __name__ == "__main__":
    main()
