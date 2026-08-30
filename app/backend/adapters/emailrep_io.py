from datetime import datetime

from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings


class EmailRepIOAdapter(SourceAdapter):
    """Email address reputation from EmailRep.io (Sublime Security).

    Key-free on the Community tier (up to 250 queries/month, 10/day with a
    free API key); an API key raised the limits and is passed via the ``Key``
    header. A ``User-Agent`` header is mandatory (403 without one).
    """

    name = "EmailRep.io"
    supported_types = ["email"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=10, requests_per_day=250)

    _FLAG_FIELDS = (
        "blacklisted",
        "malicious_activity",
        "malicious_activity_recent",
        "credentials_leaked",
        "credentials_leaked_recent",
        "data_breach",
        "suspicious_tld",
        "new_domain",
        "spam",
        "disposable",
        "free_provider",
        "spoofable",
        "spf_strict",
        "dmarc_enforced",
        "accept_all",
    )

    def __init__(self):
        self.api_key = settings.emailrep_api_key

    @staticmethod
    def _parse_dt(value):
        if not value or str(value).strip().lower() in ("never", "n/a", ""):
            return None
        candidates = (
            str(value).replace("Z", "+00:00"),
            str(value),
        )
        for candidate in candidates:
            try:
                return datetime.fromisoformat(candidate)
            except (ValueError, TypeError):
                continue
        for fmt in ("%m/%d/%Y", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(str(value), fmt).replace(tzinfo=None)
            except (ValueError, TypeError):
                continue
        return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        headers = {"accept": "application/json", "User-Agent": "ioc-platform-backend/2.0"}
        if is_valid_api_key(self.api_key):
            headers["Key"] = self.api_key

        client = self._get_client()
        resp = await client.get(
            f"https://emailrep.io/{ioc_value}", headers=headers, timeout=10
        )

        if resp.status_code == 401:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized"],
            )
        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"], http_status=resp.status_code,
                retry_after_seconds=retry_after_seconds(resp),
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
        details = data.get("details") or {}
        reputation = str(data.get("reputation") or "").lower()
        suspicious = bool(data.get("suspicious"))

        tags = [f"reputation:{reputation}"] if reputation else []
        for flag in self._FLAG_FIELDS:
            if details.get(flag) is True:
                tags.append(f"emailrep:{flag}")
        references = data.get("references")
        if references is not None:
            tags.append(f"references:{references}")

        if suspicious or details.get("blacklisted") is True:
            verdict = "malicious"
            raw_score = 0.8
            confidence = "high"
        elif details.get("malicious_activity") is True or details.get("malicious_activity_recent") is True:
            verdict = "malicious"
            raw_score = 0.6
            confidence = "high"
        elif details.get("credentials_leaked") is True or details.get("data_breach") is True:
            verdict = "suspicious"
            raw_score = 0.35
            confidence = "medium"
        elif reputation == "low":
            verdict = "suspicious"
            raw_score = 0.3
            confidence = "medium"
        elif reputation == "high":
            verdict = "clean"
            raw_score = 0.0
            confidence = "low"
        elif reputation == "none" or not reputation:
            verdict = "unknown"
            raw_score = None
            confidence = "low"
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict=verdict, raw_score=raw_score, confidence=confidence,
                tags=[], status="not_found",
                source_link=f"https://emailrep.io/{ioc_value}",
            )
        else:
            verdict = "unknown"
            raw_score = None
            confidence = "low"

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            first_seen=self._parse_dt(details.get("first_seen")),
            last_seen=self._parse_dt(details.get("last_seen")),
            source_link=f"https://emailrep.io/{ioc_value}",
            reports_count=references,
            raw_data=data,
        )
