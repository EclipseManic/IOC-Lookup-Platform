import asyncio
import socket
import time

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter
from app.backend.logger import get_logger

logger = get_logger("adapter.tor_exit")


_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_cache: list[str] = []
_cache_time: float = 0
_CACHE_TTL = 300
_cache_lock = asyncio.Lock()


class TorExitAdapter(SourceAdapter):
    name = "Tor Exit"
    supported_types = ["ipv4"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=60)

    async def _check_dnsel(self, ioc_value: str) -> bool:
        try:
            rev_parts = ioc_value.split(".")
            rev_parts.reverse()
            dnsel_host = ".".join(rev_parts) + ".dnsel.torproject.org"
            addrinfo = await asyncio.wait_for(
                asyncio.to_thread(
                    socket.getaddrinfo, dnsel_host, 0, type=socket.SOCK_STREAM
                ),
                timeout=5,
            )
            for family, stype, proto, canonname, sockaddr in addrinfo:
                if sockaddr[0] == "127.0.0.2":
                    return True
            return False
        except Exception:
            return False

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        global _cache, _cache_time
        found = False

        async with _cache_lock:
            if not _cache or time.time() - _cache_time > _CACHE_TTL:
                try:
                    client = self._get_client()
                    resp = await client.get(_TOR_LIST_URL, timeout=15)
                    if resp.status_code == 200:
                        _cache = [line.strip() for line in resp.text.splitlines() if line.strip()]
                        _cache_time = time.time()
                    else:
                        logger.warning("Tor exit list download failed with status %d", resp.status_code)
                except Exception as e:
                    logger.warning("Tor exit list download error: %s", e)

        if ioc_value in _cache:
            found = True

        if not found:
            found = await self._check_dnsel(ioc_value)

        if found:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="malicious", raw_score=0.8, tags=["tor_exit_node"],
            )

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=0.0, status="not_found",
        )
