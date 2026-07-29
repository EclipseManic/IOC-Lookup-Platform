import json
from collections.abc import Awaitable, Callable
from typing import Any

from app.backend.logger import logger


class CacheLayer:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._redis: Any = None
        self._enabled = True

    async def _connect(self):
        import redis.asyncio as aioredis
        self._redis = aioredis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            retry_on_timeout=False,
        )
        await self._redis.ping()

    async def _get_redis(self):
        if not self._enabled:
            return None
        if self._redis is None:
            try:
                await self._connect()
            except Exception:
                logger.warning("Redis unavailable — cache disabled")
                self._enabled = False
                self._redis = None
        return self._redis

    async def get(self, key: str) -> dict | None:
        r = await self._get_redis()
        if r is None:
            return None
        try:
            data = await r.get(key)
            if data is not None:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def set(self, key: str, value: dict, ttl: int):
        r = await self._get_redis()
        if r is None:
            return
        try:
            await r.setex(key, ttl, json.dumps(value))
        except Exception:
            pass

    async def get_or_compute(self, key: str, ttl: int, fn: Callable[[], Awaitable[dict | None]]) -> dict | None:
        cached = await self.get(key)
        if cached is not None:
            return cached
        result = await fn()
        if result is not None:
            await self.set(key, result, ttl)
        return result

    async def delete(self, key: str):
        r = await self._get_redis()
        if r is None:
            return
        try:
            await r.delete(key)
        except Exception:
            pass

    async def save_task(self, task_id: str, task_dict: dict, ttl: int = 3600):
        r = await self._get_redis()
        if r is None:
            return
        try:
            key = f"task:{task_id}"
            await r.setex(key, ttl, json.dumps(task_dict))
        except Exception:
            pass

    async def get_task(self, task_id: str) -> dict | None:
        r = await self._get_redis()
        if r is None:
            return None
        try:
            key = f"task:{task_id}"
            data = await r.get(key)
            if data is not None:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def list_task_ids(self, prefix: str = "task:", limit: int = 50) -> list[str]:
        r = await self._get_redis()
        if r is None:
            return []
        try:
            cursor = 0
            keys = []
            while len(keys) < limit:
                cursor, batch = await r.scan(cursor=cursor, match=f"{prefix}*", count=limit)
                keys.extend(batch)
                if cursor == 0:
                    break
            return keys[:limit]
        except Exception:
            return []

    async def delete_task(self, task_id: str):
        r = await self._get_redis()
        if r is None:
            return
        try:
            key = f"task:{task_id}"
            await r.delete(key)
        except Exception:
            pass

    async def clear(self):
        r = await self._get_redis()
        if r is None:
            return
        try:
            await r.flushdb()
        except Exception:
            pass

    async def close(self):
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._enabled = True


CACHE_TTL = {
    "VirusTotal": 300,
    "AbuseIPDB": 3600,
    "ThreatFox": 1800,
    "MalwareBazaar": 1800,
    "urlscan.io": 3600,
    "Tria.ge": 3600,
    "Hybrid Analysis": 3600,
    "GreyNoise": 3600,
    "AlienVault OTX": 1800,
    "Shodan": 3600,
    "SecurityTrails": 3600,
    "PhishTank": 1800,
    "URLhaus": 1800,
    "Spur.us": 3600,
    "Tor Exit": 3600,
    "Censys": 3600,
    "IPinfo": 3600,
}

DEFAULT_TTL = 300

TASK_TTL = 3600


def cache_key(source: str, ioc_type: str, value: str) -> str:
    return f"cache:{source}:{ioc_type}:{value.lower().strip()}"
