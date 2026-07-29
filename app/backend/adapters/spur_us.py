import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class SpurUsAdapter(SourceAdapter):
    name = "Spur.us"
    supported_types = ["ipv4"]
    rate_limit = RateLimitConfig(requests_per_minute=30)

    def __init__(self):
        self.api_key = settings.spur_us_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        client = self._get_client()
        resp = await client.get(
                f"https://app.spur.us/api/v1/context/{ioc_value}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )

        if resp.status_code == 401:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized"],
            )
        if resp.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=None,
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

        data = resp.json()
        tags = []

        usage_type = data.get("usage_type", "")
        if usage_type:
            tags.append(f"usage:{usage_type}")

        risk_score = data.get("risk_score")
        if risk_score is not None:
            tags.append(f"risk:{risk_score}")

        if data.get("asn"):
            tags.append(f"asn:{data['asn']}")
        if data.get("asn_organization"):
            tags.append(f"asn_org:{data['asn_organization']}")
        if data.get("country"):
            tags.append(f"country:{data['country']}")
        if data.get("city"):
            tags.append(f"city:{data['city']}")
        if data.get("organization"):
            tags.append(f"org:{data['organization']}")

        for flag_key in ("is_vpn", "is_proxy", "is_datacenter", "is_tor", "is_abuser", "is_starlink"):
            if data.get(flag_key):
                tags.append(flag_key)

        tunnels = data.get("tunnels", [])
        if isinstance(tunnels, list):
            for t in tunnels[:5]:
                if isinstance(t, dict):
                    t_type = t.get("type", "")
                    t_org = t.get("organization", "")
                    if t_type:
                        tags.append(f"tunnel:{t_type}")
                    if t_org:
                        tags.append(f"tunnel_org:{t_org}")

        verdict = "unknown"
        raw_score = None
        if data.get("is_abuser") or data.get("is_proxy"):
            verdict = "suspicious"
            raw_score = 0.4
        if data.get("is_tor"):
            verdict = "suspicious"
            raw_score = 0.3

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, tags=tags,
        )
