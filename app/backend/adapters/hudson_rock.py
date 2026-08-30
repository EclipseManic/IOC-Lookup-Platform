"""Hudson Rock Cavalier Infostealers API adapter for compromised email lookup.

Documentation: https://docs.hudsonrock.com/
Endpoint: https://api.hudsonrock.com/json/v3/search-by-login/emails
Auth: api-key header using HUDSON_API_KEY
"""

import httpx

from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.hudson_rock")


class HudsonRockAdapter(SourceAdapter):
    name = "Hudson Rock"
    supported_types = ["email"]
    rate_limit = RateLimitConfig(requests_per_minute=30, requests_per_day=1000)

    def __init__(self):
        super().__init__()
        self.api_key = settings.hudson_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type != "email":
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                tags=["unsupported_type"],
            )

        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                tags=["no_api_key_configured"],
            )

        client = self._get_client()
        url = "https://api.hudsonrock.com/json/v3/search-by-login/emails"
        headers = {
            "api-key": self.api_key,
            "accept": "application/json",
            "content-type": "application/json",
            "User-Agent": "IOC-Platform/1.0",
        }
        payload = {"emails": [ioc_value]}

        try:
            resp = await client.post(url, headers=headers, json=payload, timeout=15)
        except httpx.TimeoutException:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["timeout"],
            )
        except httpx.HTTPError as exc:
            logger.warning("Hudson Rock request failed: %s", exc)
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["request_error"],
            )

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                tags=["rate_limited"],
                http_status=429,
                retry_after_seconds=retry_after_seconds(resp),
            )

        if resp.status_code in (401, 403):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["unauthorized"],
                http_status=resp.status_code,
            )

        if resp.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                status="not_found",
                verdict="clean",
                raw_score=0.0,
                tags=["not_compromised"],
                http_status=404,
            )

        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=[f"http_{resp.status_code}"],
                http_status=resp.status_code,
            )

        try:
            data = resp.json()
        except Exception:
            data = {}

        # Parse Hudson Rock response structure
        # Format is typically {"data": [...]} or a list of matches per email
        stealers = []
        total_credentials = 0
        infections = data.get("data") if isinstance(data, dict) else data
        if isinstance(infections, list):
            for item in infections:
                if isinstance(item, dict):
                    malware = item.get("stealer_family") or item.get("malware_family")
                    if malware:
                        stealers.append(str(malware))
                    creds = item.get("credentials_count") or item.get("total_credentials") or 1
                    total_credentials += int(creds)
        elif isinstance(infections, dict):
            total_credentials = int(infections.get("total_credentials") or infections.get("count", 0) or 0)
            family = infections.get("stealer_family")
            if family:
                stealers.append(str(family))

        stealers = list(dict.fromkeys(stealers))

        if total_credentials > 0 or stealers:
            tags = ["infostealer_compromised", f"credentials_leaked:{total_credentials}"]
            tags.extend(f"stealer:{s}" for s in stealers[:5])
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                status="found",
                verdict="malicious",
                raw_score=0.90,
                confidence="high",
                reports_count=total_credentials,
                tags=tags,
                source_link="https://www.hudsonrock.com/",
                provider_summary=f"Infostealer infection detected: {total_credentials} credentials compromised" + (f" ({', '.join(stealers)})" if stealers else ""),
                raw_data=data if isinstance(data, dict) else {"data": data},
            )

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            status="found",
            verdict="clean",
            raw_score=0.0,
            confidence="low",
            tags=["no_infostealer_infection"],
            source_link="https://www.hudsonrock.com/",
            provider_summary="No infostealer compromise observed",
            raw_data=data if isinstance(data, dict) else {"data": data},
        )
