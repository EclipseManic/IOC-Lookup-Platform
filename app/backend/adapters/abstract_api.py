"""AbstractAPI Email Validation and Deliverability Adapter."""

import httpx
from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings
from app.backend.logger import describe_exception, get_logger

logger = get_logger("adapter.abstract_api")


class AbstractAPIAdapter(SourceAdapter):
    """Email validation and deliverability intelligence from AbstractAPI.

    Provides deliverability checks, quality scoring, disposable/burner email detection,
    MX records, and SMTP live checks.
    Free tier allows 100 requests/month at 1 request/second.
    """

    name = "AbstractAPI"
    supported_types = ["email"]
    public_without_key = False
    rate_limit = RateLimitConfig(
        requests_per_minute=60,
        requests_per_day=100,
        minimum_interval_seconds=1.0,
    )

    def __init__(self):
        self.api_key = settings.abstractapi_api_key

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
                status="unavailable",
                tags=["no_api_key_configured"],
            )

        client = self._get_client()
        url = "https://emailvalidation.abstractapi.com/v1/"
        params = {
            "api_key": self.api_key,
            "email": ioc_value,
        }

        try:
            resp = await client.get(url, params=params, timeout=12)
        except httpx.TimeoutException:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["timeout"],
            )
        except httpx.HTTPError as exc:
            logger.warning("AbstractAPI request error: %s", describe_exception(exc))
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["http_error"],
            )

        if resp.status_code == 429:
            retry_after = retry_after_seconds(resp)
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                status="rate_limited",
                tags=["rate_limited"],
                retry_after_seconds=retry_after,
            )

        if resp.status_code in (401, 403):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                status="unavailable",
                tags=["unauthorized", "invalid_api_key"],
            )

        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=[f"http_{resp.status_code}"],
            )

        try:
            data = resp.json()
        except Exception:
            data = None
        if not isinstance(data, dict):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["malformed_response"],
                provider_summary="AbstractAPI returned a malformed response",
            )

        deliverability = str(data.get("deliverability") or "").upper()
        quality_score = data.get("quality_score")
        if quality_score is not None:
            try:
                quality_score = float(quality_score)
            except (ValueError, TypeError):
                quality_score = None

        def _get_val(obj):
            if isinstance(obj, dict):
                return bool(obj.get("value"))
            return bool(obj)

        is_disposable = _get_val(data.get("is_disposable_email"))
        is_free = _get_val(data.get("is_free_email"))
        is_role = _get_val(data.get("is_role_email"))
        is_catchall = _get_val(data.get("is_catchall_email"))
        is_valid_format = _get_val(data.get("is_valid_format"))
        is_mx_found = _get_val(data.get("is_mx_found"))
        is_smtp_valid = _get_val(data.get("is_smtp_valid"))

        tags = []
        if deliverability:
            tags.append(f"deliverability:{deliverability.lower()}")
        if is_disposable:
            tags.append("abstract:disposable_email")
        if is_free:
            tags.append("abstract:free_provider")
        if is_role:
            tags.append("abstract:role_account")
        if is_catchall:
            tags.append("abstract:catchall")
        if not is_valid_format:
            tags.append("abstract:invalid_format")
        if not is_mx_found:
            tags.append("abstract:no_mx_record")
        if not is_smtp_valid:
            tags.append("abstract:smtp_invalid")

        # Verdict assignment
        if is_disposable:
            verdict = "suspicious"
            raw_score = 0.65
            confidence = "high"
        elif not is_valid_format or deliverability == "UNDELIVERABLE" or not is_mx_found:
            verdict = "suspicious"
            raw_score = 0.40
            confidence = "medium"
        elif deliverability == "DELIVERABLE" and (quality_score is not None and quality_score >= 0.70):
            verdict = "clean"
            raw_score = 0.0
            confidence = "medium"
        elif deliverability == "RISKY":
            verdict = "suspicious"
            raw_score = 0.30
            confidence = "low"
        else:
            verdict = "unknown"
            raw_score = quality_score if quality_score is not None else 0.0
            confidence = "low"

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            raw_data=data,
            source_link=f"https://app.abstractapi.com/api/email-validation",
        )
