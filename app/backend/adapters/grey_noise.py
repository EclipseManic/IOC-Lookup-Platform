import time

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class GreyNoiseAdapter(SourceAdapter):
    name = "GreyNoise"
    supported_types = ["ipv4"]
    rate_limit = RateLimitConfig(requests_per_minute=10)

    WEEKLY_LIMIT = 50
    _weekly_requests_used = 0
    _quota_reset_time = 0.0

    def _check_weekly_quota(self) -> bool:
        now = time.time()
        if now > self._quota_reset_time:
            self._weekly_requests_used = 0
            self._quota_reset_time = now + 604800
        return True

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not self._check_weekly_quota():
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["weekly_quota_exhausted"],
            )

        client = self._get_client()
        headers = {"accept": "application/json"}
        resp = await client.get(
                f"https://api.greynoise.io/v3/community/{ioc_value}",
                headers=headers,
                timeout=10,
            )

        GreyNoiseAdapter._weekly_requests_used += 1

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"],
            )
        if resp.status_code == 401:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized"],
            )
        if resp.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0,
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
            verdict=verdict, raw_score=raw_score, tags=tags,
        )
