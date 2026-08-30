import threading
from datetime import datetime, timezone

import httpx

from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings


class ChainAbuseAdapter(SourceAdapter):
    """ChainAbuse reports for cryptocurrency wallet addresses."""

    name = "ChainAbuse"
    supported_types = ["btc", "eth"]
    rate_limit = RateLimitConfig(requests_per_minute=2, requests_per_day=10)
    produces_reputation = True
    produces_relationships = True
    MONTHLY_LIMIT = 10
    _monthly_requests_used = 0
    _quota_month = ""
    _quota_lock = threading.Lock()

    def __init__(self):
        self.api_key = settings.chainabuse_api_key

    @classmethod
    def _reserve_quota(cls) -> bool:
        now = datetime.now(timezone.utc)
        month = f"{now.year:04d}-{now.month:02d}"
        with cls._quota_lock:
            if month != cls._quota_month:
                cls._quota_month = month
                cls._monthly_requests_used = 0
            if cls._monthly_requests_used >= cls.MONTHLY_LIMIT:
                return False
            cls._monthly_requests_used += 1
            return True

    @staticmethod
    def _reports(data):
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if not isinstance(data, dict):
            return []
        reports = data.get("reports") or data.get("data") or data.get("results") or []
        if isinstance(reports, dict):
            reports = list(reports.values())
        return [item for item in reports if isinstance(item, dict)] if isinstance(reports, list) else []

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )
        if not self._reserve_quota():
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["monthly_quota_exhausted"],
            )
        client = self._get_client()
        response = await client.get(
            "https://api.chainabuse.com/v0/reports",
            params={"address": ioc_value},
            auth=httpx.BasicAuth(self.api_key, self.api_key),
            headers={"accept": "application/json"},
            timeout=15,
        )
        if response.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"], http_status=429,
                retry_after_seconds=retry_after_seconds(response),
            )
        if response.status_code in (401, 403):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized"], http_status=response.status_code,
            )
        if response.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["no_reports"], http_status=404,
            )
        if response.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{response.status_code}"], http_status=response.status_code,
            )
        data = response.json()
        raw_data = data if isinstance(data, dict) else {"response": data}
        reports = self._reports(data)
        if not reports:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["no_reports"], raw_data=raw_data,
                source_link=f"https://www.chainabuse.com/address/{ioc_value}",
            )
        categories: list[str] = []
        for report in reports:
            for key in ("category", "category_name", "scam_type", "type"):
                value = report.get(key)
                if value:
                    categories.append(str(value))
        categories = list(dict.fromkeys(categories))[:30]
        tags = ["abuse_reports", f"reports:{len(reports)}"] + [f"category:{item}" for item in categories[:10]]
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="malicious", raw_score=min(1.0, 0.65 + len(reports) * 0.05), confidence="high",
            tags=tags, categories=categories, reports_count=len(reports), reports=reports[:25],
            related_iocs=[(str(item.get("transaction_hash")), "transaction") for item in reports if item.get("transaction_hash")],
            source_link=f"https://www.chainabuse.com/address/{ioc_value}", raw_data=raw_data,
        )
