from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings


class FileScanAdapter(SourceAdapter):
    """FileScan.io malware sandbox report search by file hash."""

    name = "FileScan.io"
    supported_types = ["md5", "sha1", "sha256"]
    rate_limit = RateLimitConfig(requests_per_minute=20, requests_per_day=1000)
    produces_reputation = True
    produces_metadata = True

    def __init__(self):
        self.api_key = settings.filescan_api_key

    @staticmethod
    def _records(data):
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if not isinstance(data, dict):
            return []
        for key in ("reports", "results", "data", "items"):
            items = data.get(key)
            if isinstance(items, dict):
                items = [items]
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return [data] if any(key in data for key in ("verdict", "classification", "sha256", "hash")) else []

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )
        response = await self._get_client().get(
            "https://www.filescan.io/api/reports/search",
            params={"query": ioc_value},
            headers={"X-Api-Key": self.api_key, "accept": "application/json"},
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
                verdict="unknown", status="not_found", tags=["not_found"], http_status=404,
            )
        if response.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{response.status_code}"], http_status=response.status_code,
            )
        data = response.json()
        raw_data = data if isinstance(data, dict) else {"response": data}
        records = self._records(data)
        if not records:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["not_found"], raw_data=raw_data,
                source_link=f"https://www.filescan.io/scan?sha256={ioc_value}",
            )
        record = records[0]
        native = str(record.get("verdict") or record.get("classification") or record.get("status") or "unknown").lower()
        if native in {"malicious", "malware", "bad"} or record.get("malicious") is True:
            verdict, score, confidence = "malicious", 0.85, "high"
        elif native in {"suspicious", "harmful", "risky"}:
            verdict, score, confidence = "suspicious", 0.5, "medium"
        elif native in {"clean", "benign", "harmless"}:
            verdict, score, confidence = "clean", 0.0, "medium"
        else:
            verdict, score, confidence = "unknown", None, "low"
        tags = []
        for key in ("tags", "labels", "families"):
            values = record.get(key, [])
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                for item in values:
                    if not item:
                        continue
                    if isinstance(item, dict):
                        tag_obj = item.get("tag") if isinstance(item.get("tag"), dict) else item
                        name = tag_obj.get("name") or item.get("name")
                        if name:
                            tags.append(str(name).strip())
                    else:
                        tags.append(str(item).strip())
        family = record.get("malware_family") or record.get("family") or record.get("threat_name")
        if family:
            tags.append(f"family:{family}")
        behavior = record.get("behavior") or record.get("behaviour") or record.get("sandbox_summary")
        if behavior:
            tags.append("sandbox_behavior_available")
        clean_tags = list(dict.fromkeys(tags))
        provider_summary = f"FileScan verdict: {verdict.title()}" if verdict != "unknown" else "No conclusive threat detected"
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=score, confidence=confidence,
            tags=clean_tags, malware_family=str(family) if family else None,
            categories=[str(item) for item in record.get("categories", [])] if isinstance(record.get("categories"), list) else [],
            raw_data=raw_data, source_link=f"https://www.filescan.io/scan?sha256={ioc_value}",
            provider_summary=provider_summary,
        )
