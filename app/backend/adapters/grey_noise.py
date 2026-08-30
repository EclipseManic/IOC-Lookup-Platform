import time

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key, retry_after_seconds
from app.backend.config import settings


class GreyNoiseAdapter(SourceAdapter):
    name = "GreyNoise"
    supported_types = ["ipv4"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=10)

    WEEKLY_LIMIT = 50
    _weekly_requests_used = 0
    _quota_reset_time = 0.0
    _quota_remaining: int | None = None

    def __init__(self):
        self.api_key = settings.greynoise_api_key

    async def _check_weekly_quota(self) -> tuple[bool, str | None]:
        if is_valid_api_key(self.api_key):
            return True, None

        now = time.time()
        if now > GreyNoiseAdapter._quota_reset_time:
            GreyNoiseAdapter._weekly_requests_used = 0
            GreyNoiseAdapter._quota_remaining = None
            GreyNoiseAdapter._quota_reset_time = now + 604800

        if GreyNoiseAdapter._quota_remaining is not None:
            if GreyNoiseAdapter._quota_remaining <= 0:
                return False, "weekly_quota_exhausted"
            return True, None

        # The anonymous community endpoint has a small local budget. API-key
        # requests are governed by GreyNoise's server-side quota instead; a
        # process-wide anonymous counter must not throttle authenticated users.
        if GreyNoiseAdapter._weekly_requests_used >= self.WEEKLY_LIMIT:
            return False, "weekly_quota_exhausted"
        return True, None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        allowed, quota_tag = await self._check_weekly_quota()
        if not allowed:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=[quota_tag or "weekly_quota_exhausted"],
            )

        client = self._get_client()
        headers = {"accept": "application/json"}
        if is_valid_api_key(self.api_key):
            headers["key"] = self.api_key
        resp = await client.get(
                f"https://api.greynoise.io/v3/community/{ioc_value}",
                headers=headers,
                timeout=10,
            )

        if not is_valid_api_key(self.api_key):
            GreyNoiseAdapter._weekly_requests_used += 1
        if GreyNoiseAdapter._quota_remaining is not None:
            GreyNoiseAdapter._quota_remaining = max(GreyNoiseAdapter._quota_remaining - 1, 0)

        if resp.status_code == 429:
            if not is_valid_api_key(self.api_key):
                GreyNoiseAdapter._quota_remaining = 0
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"], http_status=resp.status_code,
                retry_after_seconds=retry_after_seconds(resp),
            )
        if resp.status_code == 401:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized"],
            )
        if resp.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        data = resp.json()
        classification = data.get("classification", "")
        tags = []
        if classification:
            tags.append(f"classification:{classification}")
        if data.get("name"):
            tags.append(f"name:{data['name']}")
        if data.get("link"):
            tags.append(f"link:{data['link']}")
        if data.get("last_seen"):
            tags.append(f"last_seen:{data['last_seen']}")

        if classification == "noise":
            verdict = "unknown"
            raw_score = None
            tags.append("internet_scanner")
        elif classification == "riot":
            verdict = "clean"
            raw_score = 0.0
            tags.append("known_service")
        elif classification == "unknown":
            verdict = "unknown"
            raw_score = None
            tags.append("greynoise_no_data")
        elif classification == "malicious":
            verdict = "malicious"
            raw_score = 0.5
            tags.append("malicious_scanner")
        else:
            verdict = "unknown"
            raw_score = None

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, tags=tags, raw_data=data,
        )
