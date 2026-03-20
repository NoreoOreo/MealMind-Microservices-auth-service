import asyncio
import json
import sys
import uuid

from redis import asyncio as aioredis


async def main() -> int:
    token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1lYWxtaW5kLWF1dGgta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMGFlYTY5ZS01MjY2LTQyMTktODgwNy1iNjQxMjM4NDNhYTQiLCJleHAiOjE3NzM5OTQ0NzksImp0aSI6ImYwZmViZjYxLTc4ZDUtNGMwYy1iOTU2LTVjOTI2NWExYTYxMiIsImdyb3VwcyI6WyJ1c2VyIl0sInR5cGUiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdC9hcGkvdjEvYXV0aCIsImF1ZCI6Im1lYWxtaW5kLWNsaWVudHMifQ.cVvYjPy37oQlzcJSFo_y8Xgne_0XrbvJvdCAknE7OqQ0HADBdmUirw4bZp5Srmy4-CyMhBVtps5jtLpN5cOFj9gdpuErUsegM41U1l9bJBpyOPQr7nnhutMqK_yGzIFvVYtJSwJ4NCYm8YV1LrBxO3VDCA7pmRF05FSdl_ukIMahvuQhTeArWEgOJfLp_qfvc2x7xEWttchdUUv5QV6CTBQViJuP6-_gH8Gbkkz4L-CID8d9rk_5Vgfn8WY-rdyrlcvsBenqM8LWxb5zpKDXW_UrkrFvqe3bjryh2mWYZYU0sYYWX6uu-LlnYB6_G98u05naujcG63MT_iE4enZMzg"
    redis_url = "redis://localhost:6379/0"
    queue = "auth:queue"
    timeout = 5

    redis = aioredis.from_url(redis_url, decode_responses=True, encoding="utf-8")
    try:
        reply_queue = f"test:reply:{uuid.uuid4().hex[:8]}"
        message_id = str(uuid.uuid4())
        print(message_id)
        payload = {
            "event_type": "user.authenticate",
            "message_id": message_id,
            "sender": "cli-test",
            "target": reply_queue,
            "payload": {"jwt_token": token},
        }

        await redis.rpush(queue, json.dumps(payload))
        print(f"→ sent to {queue}, waiting on {reply_queue} (timeout {timeout}s)")

        res = await redis.brpop(reply_queue, timeout=timeout)
        if not res:
            print("✖ timed out waiting for reply")
            return 1
        _, raw = res
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            print(f"✖ invalid JSON reply: {raw}")
            return 1

        print(json.dumps(data, indent=2))
    finally:
        await redis.close()


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except KeyboardInterrupt:
        exit_code = 1
    sys.exit(exit_code)
