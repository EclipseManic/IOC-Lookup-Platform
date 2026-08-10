import asyncio
import threading
import time

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class AbuseIPDBAdapter(SourceAdapter):
    name = "AbuseIPDB"
    supported_types = ["ipv4", "ipv6"]
    rate_limit = RateLimitConfig(requests_per_minute=30, requests_per_day=1000)

    DAILY_LIMIT = 1000
    _daily_requests_used = 0
    _quota_reset_time = 0.0
    _remaining = 0
    _reset_time = 0

    _blacklist: dict[str, int] = {}
    _blacklist_updated: float = 0
    _blacklist_lock = asyncio.Lock()
    _daily_quota_lock = threading.Lock()
    BLACKLIST_TTL = 86400  # 24h (free tier limit)

    def __init__(self):
        self.api_key = settings.abuseipdb_api_key

    def _consume_daily_quota(self) -> bool:
        with AbuseIPDBAdapter._daily_quota_lock:
            now = time.time()
            if now > AbuseIPDBAdapter._quota_reset_time:
                AbuseIPDBAdapter._daily_requests_used = 0
                AbuseIPDBAdapter._quota_reset_time = now + 86400
            if AbuseIPDBAdapter._daily_requests_used >= AbuseIPDBAdapter.DAILY_LIMIT:
                return False
            AbuseIPDBAdapter._daily_requests_used += 1
            return True

    def _check_daily_quota(self) -> bool:
        with AbuseIPDBAdapter._daily_quota_lock:
            now = time.time()
            if now > AbuseIPDBAdapter._quota_reset_time:
                AbuseIPDBAdapter._daily_requests_used = 0
                AbuseIPDBAdapter._quota_reset_time = now + 86400
            return AbuseIPDBAdapter._daily_requests_used < AbuseIPDBAdapter.DAILY_LIMIT

    def _update_rate_headers(self, resp):
        try:
            headers = getattr(resp, "headers", {}) or {}
            remaining = headers.get("X-RateLimit-Remaining", "")
            reset = headers.get("X-RateLimit-Reset", "")
            if remaining:
                self._remaining = int(remaining)
            if reset:
                self._reset_time = int(reset)
        except Exception as exc:
            logger.debug("AbuseIPDB rate-limit header parse failed: %s", exc)

    async def _refresh_blacklist(self):
        if time.time() - self._blacklist_updated < self.BLACKLIST_TTL:
            return
        async with self._blacklist_lock:
            if time.time() - self._blacklist_updated < self.BLACKLIST_TTL:
                return
            if not is_valid_api_key(self.api_key):
                return
            try:
                client = self._get_client()
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/blacklist",
                    params={"confidenceMinimum": 90, "limit": 10000},
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    timeout=30,
                )
                if resp.status_code == 200:
                    items = resp.json().get("data", [])
                    self._blacklist = {
                        item["ipAddress"]: item.get("abuseConfidenceScore", 100)
                        for item in items if isinstance(item, dict) and "ipAddress" in item
                    }
                    self._blacklist_updated = time.time()
            except Exception as exc:
                logger.warning("AbuseIPDB blacklist refresh failed: %s", exc)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        if not self._check_daily_quota():
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["daily_quota_exhausted"],
            )

        await self._refresh_blacklist()
        bl_score = self._blacklist.get(ioc_value)
        if bl_score is not None:
            if not self._consume_daily_quota():
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="unknown", tags=["daily_quota_exhausted"],
                )
            score = bl_score / 100.0
            confidence = "high" if bl_score >= 95 else "medium"
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="malicious", confidence=confidence,
                raw_score=round(score, 4),
                tags=["blacklist_hit", f"abuse_confidence:{bl_score}"],
                source_link=f"https://www.abuseipdb.com/check/{ioc_value}",
                reports_count=1,
            )

        client = self._get_client()
        resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={
                    "ipAddress": ioc_value,
                    "maxAgeInDays": 365,
                },
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=15,
            )

        if resp.status_code == 401:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["invalid_api_key"],
            )
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

        self._update_rate_headers(resp)
        if not self._consume_daily_quota():
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["daily_quota_exhausted"],
            )

        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0) / 100.0
        total_reports = data.get("totalReports", 0)
        last_reported = data.get("lastReportedAt")

        if score >= 0.5:
            verdict = "malicious"
        elif score >= 0.25:
            verdict = "suspicious"
        else:
            verdict = "clean"

        confidence = "high" if total_reports > 10 else "medium" if total_reports > 0 else "low"

        tags = []
        isp = data.get("isp", "")
        country = data.get("countryCode", "")
        domain = data.get("domain", "")
        usage = data.get("usageType", "")
        if isp:
            tags.append(f"ISP: {isp}")
        if country:
            tags.append(f"Country: {country}")
        if usage:
            tags.append(f"Usage: {usage}")
        if total_reports:
            tags.append(f"total_reports: {total_reports}")
        if last_reported:
            tags.append(f"last_reported: {last_reported[:10]}")

        if domain:
            tags.append(f"domain: {domain}")

        hostnames = data.get("hostnames", [])
        for h in hostnames[:5]:
            if h:
                tags.append(f"hostname: {h}")

        if data.get("isTor", False):
            tags.append("tor_exit_node")

        if data.get("isWhitelisted", False):
            tags.append("whitelisted")

        if data.get("ipVersion", 4) == 6:
            tags.append("ipv6")

        categories = list(data.get("categories", {}).values()) if isinstance(data.get("categories"), dict) else []

        reports = data.get("reports", []) or []
        reports_out = []
        for r in reports[:20]:
            if isinstance(r, dict):
                reports_out.append({
                    "categories": list(r.get("categories", []) or []),
                    "comment": r.get("comment", ""),
                    "reported_at": r.get("reportedAt", ""),
                })

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=round(score, 4),
            tags=tags,
            categories=categories,
            first_seen=None,
            last_seen=self._parse_dt(last_reported) if last_reported else None,
            source_link=f"https://www.abuseipdb.com/check/{ioc_value}",
            reports_count=total_reports,
            reports=reports_out,
        )

    def _parse_dt(self, val: str):
        from datetime import datetime
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None
