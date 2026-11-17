# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Redis-backed sessions and login rate limiting, plus API token helpers."""

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis

TOKEN_PREFIX = "vxl_"  # noqa: S105 - a public prefix, not a secret


def hash_secret(value: str) -> str:
    """Session ids and API tokens are 256-bit random, so an unsalted SHA-256 is enough."""
    return hashlib.sha256(value.encode()).hexdigest()


def new_api_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


@dataclass(frozen=True)
class SessionData:
    user_id: uuid.UUID
    csrf: str


class SessionStore:
    def __init__(self, redis: Redis, ttl_s: int) -> None:
        self.redis = redis
        self.ttl_s = ttl_s

    @staticmethod
    def _key(session_hash: str) -> str:
        return f"vex:sess:{session_hash}"

    @staticmethod
    def _user_key(user_id: uuid.UUID) -> str:
        return f"vex:usess:{user_id}"

    async def create(self, user_id: uuid.UUID) -> tuple[str, SessionData]:
        sid = secrets.token_urlsafe(32)
        data = SessionData(user_id, secrets.token_urlsafe(32))
        key = self._key(hash_secret(sid))
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.set(key, json.dumps({"u": str(user_id), "c": data.csrf}), ex=self.ttl_s)
            pipe.sadd(self._user_key(user_id), key)
            pipe.expire(self._user_key(user_id), self.ttl_s)
            await pipe.execute()
        return sid, data

    async def get(self, sid: str) -> SessionData | None:
        raw = await self.redis.get(self._key(hash_secret(sid)))
        if raw is None:
            return None
        obj = json.loads(raw)
        return SessionData(uuid.UUID(obj["u"]), obj["c"])

    async def delete(self, sid: str) -> None:
        await self.redis.delete(self._key(hash_secret(sid)))

    async def delete_all_for(self, user_id: uuid.UUID) -> None:
        keys = await self.redis.smembers(self._user_key(user_id))
        if keys:
            await self.redis.delete(*keys)
        await self.redis.delete(self._user_key(user_id))


class RateLimiter:
    """Fixed-window counters. Only failed logins are counted; a success resets the account."""

    def __init__(self, redis: Redis, window_s: int) -> None:
        self.redis = redis
        self.window_s = window_s

    async def blocked(self, key: str, limit: int) -> int | None:
        """Seconds until the window ends when `key` is at its limit, else None."""
        count = await self.redis.get(f"vex:rl:{key}")
        if count is not None and int(count) >= limit:
            return max(await self.redis.ttl(f"vex:rl:{key}"), 1)
        return None

    async def hit(self, key: str) -> None:
        k = f"vex:rl:{key}"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(k)
            pipe.expire(k, self.window_s, nx=True)
            await pipe.execute()

    async def reset(self, key: str) -> None:
        await self.redis.delete(f"vex:rl:{key}")
