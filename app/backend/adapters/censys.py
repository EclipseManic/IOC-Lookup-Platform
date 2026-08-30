import base64
import time

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key, retry_after_seconds
from app.backend.config import settings


class CensysAdapter(SourceAdapter):
    name = "Censys"
    supported_types = ["ipv4"]
    rate_limit = RateLimitConfig(requests_per_minute=24)

    CENSYS_MONTHLY_LIMIT = 100
    _monthly_credits_used = 0
    _credit_reset_time = 0.0

    def __init__(self):
        self.api_key = settings.censys_api_key
        self._has_credentials = is_valid_api_key(self.api_key)

    def _auth_header(self) -> str:
        if ":" in self.api_key:
            api_id, api_secret = self.api_key.split(":", 1)
            token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
            return f"Basic {token}"
        # Modern Censys personal access tokens (censys_...) use Bearer auth.
        return f"Bearer {self.api_key}"

    def _request_headers(self) -> dict:
        """Platform API headers (PAT auth + vendor-specific accept version).

        docs.censys.com (2026-07-28): the Platform API requires the vendor
        Accept header ``application/vnd.censys.api.v3.host.v1+json`` and
        authenticates with a Personal Access Token.
        """
        return {
            "Authorization": self._auth_header(),
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }

    def _check_credits(self) -> bool:
        now = time.time()
        if now > self._credit_reset_time:
            self._monthly_credits_used = 0
            self._credit_reset_time = now + 2592000
        return self._monthly_credits_used < self.CENSYS_MONTHLY_LIMIT

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not self._has_credentials:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        if not self._check_credits():
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["out_of_credits"],
            )

        client = self._get_client()
        resp = await client.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{ioc_value}",
            headers=self._request_headers(),
            timeout=15,
        )

        if resp.status_code == 429:
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
                verdict="unknown", raw_score=None, status="not_found",
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        CensysAdapter._monthly_credits_used += 1

        data = resp.json()
        resource = data.get("result", {}).get("resource")
        if not resource:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=None, status="not_found",
            )
        # A host returned by Censys is confirmed to exist on the internet.
        # This tag also keeps NormalizedResult's post-validator from demoting
        # a data-light host (no location/ASN/services) to not_found.
        tags = ["active_ip"]

        location = resource.get("location", {})
        if location.get("city"):
            tags.append(f"city:{location['city']}")
        if location.get("country"):
            tags.append(f"country:{location['country']}")
        if location.get("timezone"):
            tags.append(f"timezone:{location['timezone']}")

        asys = resource.get("autonomous_system", {})
        if asys.get("asn"):
            tags.append(f"asn:{asys['asn']}")
        if asys.get("name"):
            tags.append(f"org:{asys['name']}")

        services = resource.get("services", [])
        if services:
            tags.append(f"services:{len(services)}")
            ports_seen = []
            for s in services:
                if not isinstance(s, dict):
                    continue
                port = s.get("port")
                if port is not None:
                    ports_seen.append(str(port))
                parts = []
                svc_name = s.get("service_name", "")
                transport = s.get("transport_protocol", "")
                if svc_name:
                    parts.append(svc_name)
                if transport:
                    parts.append(transport)
                software = s.get("software", [])
                if isinstance(software, list):
                    for sw in software:
                        if isinstance(sw, dict):
                            prod = sw.get("product", "") or sw.get("name", "")
                            ver = sw.get("version", "")
                            sw_parts = [prod, ver]
                            sw_str = "/".join(p for p in sw_parts if p)
                            if sw_str:
                                parts.append(sw_str)
                if parts and port is not None:
                    tags.append(f"svc:{port}:{'|'.join(parts)}")
            if ports_seen:
                tags.append(f"ports:{','.join(ports_seen[:20])}")

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, status="found", tags=tags, raw_data=data,
        )
