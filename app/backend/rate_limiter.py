import asyncio
import time

from app.backend.logger import logger


class RateLimiter:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._redis = None
        self._enabled = True
        self._local_counters: dict[str, list[float]] = {}
        self._local_lock = asyncio.Lock()

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
                logger.warning("Redis unavailable — rate limiter degraded to local")
                self._enabled = False
                self._redis = None
        return self._redis

    async def acquire(self, source: str, limit: int, window: int) -> bool:
        r = await self._get_redis()
        if r is None:
            return await self._local_acquire(source, limit, window)
        return await self._redis_acquire(r, source, limit, window)

    async def _redis_acquire(self, r, source: str, limit: int, window: int) -> bool:
        key = f"ratelimit:{source}"
        now = time.time()
        cutoff = now - window
        try:
            removed = await r.zremrangebyscore(key, "-inf", cutoff)
            count = await r.zcard(key)
            if count >= limit:
                return False
            await r.zadd(key, {str(now): now})
            await r.expire(key, window + 5)
            return True
        except Exception:
            return await self._local_acquire(source, limit, window)

    async def _local_acquire(self, source: str, limit: int, window: int) -> bool:
        async with self._local_lock:
            now = time.time()
            cutoff = now - window
            timestamps = self._local_counters.get(source, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= limit:
                return False
            timestamps.append(now)
            self._local_counters[source] = timestamps
            return True

    async def acquire_blocking(self, source: str, limit: int, window: int, timeout: float = 30.0) -> bool:
        deadline = time.time() + timeout
        delay = 0.5
        attempts = 0
        max_attempts = 3
        while time.time() < deadline:
            ok = await self.acquire(source, limit, window)
            if ok:
                return True
            attempts += 1
            if attempts >= max_attempts:
                logger.warning(f"Rate limit exceeded for {source} after {attempts} attempts")
                return False
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 5.0)
        logger.warning(f"Rate limit timeout for {source} after {timeout}s")
        return False

    async def close(self):
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._enabled = True
