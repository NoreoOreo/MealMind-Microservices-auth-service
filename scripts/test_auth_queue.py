#!/usr/bin/env python3
"""
Quick check for auth:queue event handler.

Usage:
  python scripts/test_auth_queue.py --token <ACCESS_TOKEN> [--redis-url redis://localhost:6379/0] [--timeout 5]

Sends:
{
  "event_type": "user.authenticate",
  "message_id": "<uuid>",
  "reply_to": "auth:queue",
  "sender": "cli-test",
  "target": "<reply_queue>",
  "payload": { "jwt_token": "<token>" }
}
and waits for the response on <reply_queue>.
"""

import argparse
import asyncio
import json
import os
import sys
import uuid

from redis import asyncio as aioredis


async def main() -> int:
    parser = argparse.ArgumentParser(description="Test auth:queue authenticate flow")
    parser.add_argument("--token", required=True, help="access JWT token to validate")
    parser.add_argument("--redis-url", default=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    parser.add_argument("--queue", default=os.getenv("REDIS_QUEUE_KEY", "auth:queue"), help="auth queue key")
    parser.add_argument("--timeout", type=int, default=5, help="seconds to wait for reply")
    args = parser.parse_args()

    redis = aioredis.from_url(args.redis_url, decode_responses=True, encoding="utf-8")
    try:
        reply_queue = f"test:reply:{uuid.uuid4().hex[:8]}"
        message_id = str(uuid.uuid4())
        payload = {
            "event_type": "user.authenticate",
            "message_id": message_id,
            "sender": "cli-test",
            "target": reply_queue,
            "payload": {"jwt_token": args.token},
        }

        await redis.rpush(args.queue, json.dumps(payload))
        print(f"→ sent to {args.queue}, waiting on {reply_queue} (timeout {args.timeout}s)")

        res = await redis.brpop(reply_queue, timeout=args.timeout)
        if not res:
            print("✖ timed out waiting for reply")
            return 1
        _, raw = res
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            print(f"✖ invalid JSON reply: {raw}")
            return 1

        status = data.get("status")
        if status == "ok":
            print("✔ authorized")
            print(json.dumps(data.get("user"), indent=2))
            return 0
        else:
            print("✖ auth failed")
            print(json.dumps(data, indent=2))
            return 1
    finally:
        await redis.close()


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except KeyboardInterrupt:
        exit_code = 1
    sys.exit(exit_code)
