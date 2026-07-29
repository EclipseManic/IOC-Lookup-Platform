import asyncio
import csv
import io
import logging
import time

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings

logger = logging.getLogger("ioc-platform")

PHISHTANK_DB_URL = "http://data.phishtank.com/data/online-valid.csv"
_db_cache: set[str] = set()
_db_cache_time: float = 0
_db_cache_lock = asyncio.Lock()
_DB_CACHE_TTL = 1800


class PhishTankAdapter(SourceAdapter):
    name = "PhishTank"
    supported_types = ["url"]
    rate_limit = RateLimitConfig(requests_per_minute=10)

    _remaining = 0
    _reset_time = 0

    def __init__(self):
        self.api_key = settings.phishtank_api_key

    def _update_rate_headers(self, resp):
        try:
            headers = getattr(resp, "headers", {}) or {}
            remaining = headers.get("X-Rate-Limit-Remaining", "")
            reset = headers.get("X-Rate-Limit-Reset", "")
            if remaining:
                try:
                    self._remaining = int(remaining)
                except ValueError:
                    pass
            if reset:
                try:
                    self._reset_time = int(reset)
                except ValueError:
                    pass
        except Exception:
            pass

    async def _ensure_db_cache(self):
        global _db_cache, _db_cache_time
        async with _db_cache_lock:
            if _db_cache and time.time() - _db_cache_time < _DB_CACHE_TTL:
                return
            try:
                client = self._get_client()
                resp = await client.get(PHISHTANK_DB_URL, timeout=30)
                if resp.status_code == 200:
                    text = resp.text
                    # CSV format: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
                    reader = csv.reader(io.StringIO(text))
                    urls = set()
                    next(reader, None)
                    for row in reader:
                        if len(row) >= 2:
                            url = row[1].strip().rstrip("/")
                            if url:
                                urls.add(url)
                    _db_cache = urls
                    _db_cache_time = time.time()
                    logger.info("PhishTank DB cache loaded with %d URLs", len(urls))
            except Exception as e:
                logger.warning("PhishTank DB download failed: %s", e)

    async def _check_db(self, ioc_value: str) -> bool:
        await self._ensure_db_cache()
        normalized = ioc_value.strip().rstrip("/")
        return normalized in _db_cache or normalized.replace("https://", "http://") in _db_cache

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            # Fallback: check against public CSV database
            found = await self._check_db(ioc_value)
            if found:
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="malicious", raw_score=0.7,
                    tags=["phishing", "public_db_hit"],
                    source_link="https://phishtank.com/",
                )
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        client = self._get_client()
        resp = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": ioc_value, "format": "json", "app_key": self.api_key},
                headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "IOC-Platform/1.0"},
                timeout=15,
            )

        self._update_rate_headers(resp)

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"],
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        data = resp.json()
        results = data.get("results", {})
        in_phish = results.get("in_database", False)
        valid = results.get("valid") == "y"

        verdict = "malicious" if in_phish and valid else "unknown"
        tags = ["phishing"] if verdict == "malicious" else []
        if in_phish:
            tags.append("in_database")

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=1.0 if verdict == "malicious" else None,
            tags=tags,
        )
