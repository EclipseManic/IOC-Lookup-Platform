import calendar
import time

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class ShodanAdapter(SourceAdapter):
    name = "Shodan"
    supported_types = ["ipv4"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=60)

    SHODAN_MONTHLY_LIMIT = 100
    _monthly_credits_used = 0
    _credit_reset_time = 0.0

    def __init__(self):
        self.api_key = settings.shodan_api_key

    def _check_credits(self) -> bool:
        now = time.time()
        if now > self._credit_reset_time:
            self._monthly_credits_used = 0
            now_dt = time.gmtime(now)
            days_in_month = calendar.monthrange(now_dt.tm_year, now_dt.tm_mon)[1]
            self._credit_reset_time = now + days_in_month * 86400
        return self._monthly_credits_used < self.SHODAN_MONTHLY_LIMIT

    async def _internetdb_lookup(self, ioc_value: str) -> NormalizedResult | None:
        try:
            client = self._get_client()
            resp = await client.get(
                f"https://internetdb.shodan.io/{ioc_value}",
                timeout=10,
            )
            if resp.status_code == 404:
                return None
            if resp.status_code != 200:
                return None
            data = resp.json()
            tags = []
            raw_ports = data.get("ports", [])
            if raw_ports:
                tags.append(f"ports:{','.join(str(p) for p in raw_ports[:20])}")
            vulns = data.get("vulns", [])
            if vulns:
                tags.append(f"vulns:{','.join(vulns[:10])}")
            hostnames = data.get("hostnames", [])
            if hostnames:
                tags.extend(f"hostname:{h}" for h in hostnames[:5])
            cpes = data.get("cpes", [])
            if cpes:
                tags.append(f"cpes:{','.join(cpes[:10])}")
            tags.append("source:internetdb")
            return NormalizedResult(
                ioc=ioc_value, ioc_type="ipv4", source=self.name,
                verdict="unknown", raw_score=None, tags=tags,
            )
        except Exception:
            return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        internetdb_result = await self._internetdb_lookup(ioc_value)
        if internetdb_result is not None:
            return internetdb_result

        if not is_valid_api_key(self.api_key):
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
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ioc_value}",
                params={"key": self.api_key},
                timeout=15,
            )
        except httpx.TimeoutException:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="timeout", tags=["timeout"],
            )
        except (httpx.ConnectError, httpx.HTTPError):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="error", tags=["connection_error"],
            )

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"],
            )
        if resp.status_code in (401, 403):
            err_msg = ""
            try:
                err_msg = resp.json().get("error", "")
            except Exception:
                pass
            if "membership" in err_msg.lower():
                # Free Shodan key cannot query /shodan/host/, and InternetDB was already checked.
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="unknown", status="not_found", tags=["not_found", "membership_required"],
                )
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized" if resp.status_code == 401 else "forbidden"],
            )
        if resp.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["not_found"], raw_score=None,
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        ShodanAdapter._monthly_credits_used += 1

        data = resp.json()
        tags = []

        raw_ports = data.get("ports", [])
        if raw_ports:
            tags.append(f"ports:{','.join(str(p) for p in raw_ports[:20])}")

        services_by_port = {}
        for svc in data.get("data", []):
            if not isinstance(svc, dict):
                continue
            port = svc.get("port")
            if port is None:
                continue
            parts = []
            transport = svc.get("transport", "")
            if transport:
                parts.append(transport)
            product = svc.get("product", "")
            version = svc.get("version", "")
            if product:
                parts.append(product)
            if version:
                parts.append(version)
            cpe = svc.get("cpe", "")
            if cpe and isinstance(cpe, str):
                parts.append(f"cpe:{cpe}")
            title = svc.get("http", {}).get("title", "") if isinstance(svc.get("http"), dict) else ""
            if title:
                parts.append(f"title:{title}")
            hostname = svc.get("hostname", "")
            if hostname:
                parts.append(hostname)
            if parts:
                services_by_port.setdefault(port, "/".join(parts))

        for port, desc in sorted(services_by_port.items()):
            tags.append(f"svc:{port}:{desc}")

        vulns = data.get("vulns", [])
        if vulns:
            tags.append(f"vulns:{','.join(vulns[:10])}")

        hostnames = data.get("hostnames", [])
        if hostnames:
            tags.extend(f"hostname:{h}" for h in hostnames[:5])

        org = data.get("org", "")
        isp = data.get("isp", "")
        os_val = data.get("os", "")

        details = []
        if org:
            details.append(("org", org))
        if isp:
            details.append(("isp", isp))
        if os_val:
            details.append(("os", os_val))

        categories = list(dict.fromkeys(d for _, d in details))

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, tags=tags,
            categories=categories or [],
        )
