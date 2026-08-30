import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key, retry_after_seconds
from app.backend.config import settings


class IPinfoAdapter(SourceAdapter):
    name = "IPinfo"
    supported_types = ["ipv4", "ipv6"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=30)

    def __init__(self):
        self.api_key = settings.ipinfo_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()

        if not is_valid_api_key(self.api_key):
            return await self._lite_lookup(client, ioc_value, ioc_type)

        return await self._paid_lookup(client, ioc_value, ioc_type)

    async def _lite_lookup(self, client, ioc_value: str, ioc_type: str) -> NormalizedResult:
        resp = await client.get(
            f"https://ipinfo.io/{ioc_value}/json",
            timeout=10,
        )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["lite_api_unavailable"],
            )

        data = resp.json()
        tags = []
        country = data.get("country_code", "") or data.get("country", "")
        asn = data.get("asn", "")
        asn_name = data.get("as_name", "") or data.get("asn_name", "")
        if country:
            tags.append(f"country:{country}")
        if asn:
            tags.append(f"asn:{asn}")
        if asn_name:
            tags.append(f"asn_name:{asn_name}")
        tags.append("source:lite")
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, tags=tags,
        )

    async def _paid_lookup(self, client, ioc_value: str, ioc_type: str) -> NormalizedResult:
        resp = await client.get(
                f"https://ipinfo.io/{ioc_value}/json",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10,
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
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        data = resp.json()
        tags = []
        categories = []

        ip = data.get("ip", "")
        city = data.get("city", "")
        region = data.get("region", "")
        country = data.get("country", "")
        loc = data.get("loc", "")
        postal = data.get("postal", "")
        timezone = data.get("timezone", "")
        org = data.get("org", "")
        asn_info = data.get("asn", {}) or {}

        if city: tags.append(f"city:{city}")
        if region: tags.append(f"region:{region}")
        if country: tags.append(f"country:{country}")
        if timezone: tags.append(f"timezone:{timezone}")
        if org: tags.append(f"org:{org}")
        if isinstance(asn_info, dict):
            asn_val = asn_info.get("asn", "")
            asn_name = asn_info.get("name", "")
            if asn_val: tags.append(f"asn:{asn_val}")
            if asn_name: tags.append(f"asn_name:{asn_name}")

        hosting = data.get("hosting", {})
        is_hosting = False
        is_bogon = False
        if isinstance(hosting, dict):
            is_hosting = bool(hosting.get("is_hosting", False))
            is_bogon = bool(hosting.get("is_bogon", False))
            if is_hosting:
                tags.append("is_hosting")
            if is_bogon:
                tags.append("is_bogon")

        raw_score = None
        verdict = "unknown"
        if is_bogon:
            raw_score = 0.3
            verdict = "suspicious"
        elif is_hosting:
            raw_score = 0.2
            verdict = "suspicious"

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, tags=tags,
            categories=categories, raw_data=data,
        )
