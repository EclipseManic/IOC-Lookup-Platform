import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from app.backend.logger import get_logger

logger = get_logger("cache")


class LocalFileCache:
    def __init__(self, cache_dir: str | None = None):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            from app.backend.config import settings
            self.cache_dir = Path(settings.cache_dir) if settings.cache_dir else Path(__file__).resolve().parent.parent.parent / ".cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace(":", "_").replace("/", "_").replace("?", "_").replace(" ", "_")
        return self.cache_dir / f"{safe}.json"

    def get(self, key: str) -> dict | None:
        path = self._path(key)
        try:
            if not path.exists():
                return None
            with path.open("r", encoding="utf-8") as f:
                entry = json.load(f)
            if entry.get("expires_at") and time.time() > entry["expires_at"]:
                path.unlink(missing_ok=True)
                return None
            return entry.get("value")
        except Exception:
            return None

    def set(self, key: str, value: dict, ttl: int):
        path = self._path(key)
        try:
            entry = {"value": value, "expires_at": time.time() + ttl}
            path.write_text(json.dumps(entry), encoding="utf-8")
        except Exception:
            pass

    def delete(self, key: str):
        try:
            self._path(key).unlink(missing_ok=True)
        except Exception:
            pass

    def clear(self):
        try:
            for f in self.cache_dir.glob("*.json"):
                f.unlink(missing_ok=True)
        except Exception:
            pass

    def list_keys(self, prefix: str = "task:", limit: int = 50) -> list[str]:
        try:
            safe = prefix.replace(":", "_").replace("/", "_").replace("?", "_").replace(" ", "_")
            keys = [f.stem for f in self.cache_dir.glob(f"{safe}*.json")]
            return keys[:limit]
        except Exception:
            return []


class CacheLayer:
    def __init__(self, redis_url: str | None = None):
        self.redis_url = redis_url or ""
        self._redis: Any = None
        self._enabled = bool(self.redis_url)
        self._local = LocalFileCache()

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
        if self._redis is not None:
            return self._redis
        if not self._enabled or not self.redis_url:
            return None
        if self._redis is None:
            try:
                await self._connect()
            except Exception:
                logger.warning("Redis unavailable — cache degraded to local files")
                self._enabled = False
                self._redis = None
        return self._redis

    async def get(self, key: str) -> dict | None:
        r = await self._get_redis()
        if r is None:
            return self._local.get(key)
        try:
            data = await r.get(key)
            if data is not None:
                return json.loads(data)
        except Exception:
            return self._local.get(key)
        return None

    async def set(self, key: str, value: dict, ttl: int):
        r = await self._get_redis()
        if r is None:
            self._local.set(key, value, ttl)
            return
        try:
            await r.setex(key, ttl, json.dumps(value))
        except Exception:
            self._local.set(key, value, ttl)

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
            self._local.delete(key)
            return
        try:
            await r.delete(key)
        except Exception:
            self._local.delete(key)

    async def save_task(self, task_id: str, task_dict: dict, ttl: int = 3600):
        r = await self._get_redis()
        if r is None:
            self._local.set(f"task:{task_id}", task_dict, ttl)
            return
        try:
            key = f"task:{task_id}"
            await r.setex(key, ttl, json.dumps(task_dict))
        except Exception:
            self._local.set(f"task:{task_id}", task_dict, ttl)

    async def get_task(self, task_id: str) -> dict | None:
        r = await self._get_redis()
        if r is None:
            return self._local.get(f"task:{task_id}")
        try:
            key = f"task:{task_id}"
            data = await r.get(key)
            if data is not None:
                return json.loads(data)
        except Exception:
            return self._local.get(f"task:{task_id}")
        return None

    async def list_task_ids(self, prefix: str = "task:", limit: int = 50) -> list[str]:
        r = await self._get_redis()
        if r is None:
            return self._local.list_keys(prefix, limit)
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
            return self._local.list_keys(prefix, limit)

    async def delete_task(self, task_id: str):
        r = await self._get_redis()
        if r is None:
            self._local.delete(f"task:{task_id}")
            return
        try:
            key = f"task:{task_id}"
            await r.delete(key)
        except Exception:
            self._local.delete(f"task:{task_id}")

    async def clear(self):
        r = await self._get_redis()
        if r is None:
            self._local.clear()
            return
        try:
            await r.flushdb()
        except Exception:
            self._local.clear()

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
