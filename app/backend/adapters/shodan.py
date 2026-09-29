import calendar
import time

import httpx

from app.backend.adapters._http import (
    MalformedResponse,
    describe_exception,
    exception_result,
    failure,
    http_failure,
    malformed,
    not_configured,
    read_json,
)
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.shodan")

_MAX_PORTS = 20
_MAX_SERVICES = 30


class ShodanAdapter(SourceAdapter):
    name = "Shodan"
    supported_types = ["ipv4"]
    public_without_key = True
    produces_infrastructure_context = True
    produces_metadata = True
    # InternetDB is free and unmetered; the keyed host API is 1 request/second.
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
        """Key-free InternetDB lookup. ``None`` means it had nothing to say."""
        try:
            client = self._get_client()
            resp = await client.get(f"https://internetdb.shodan.io/{ioc_value}", timeout=10)
            if resp.status_code != 200:
                # 404 = no data for this IP; anything else is not a usable answer.
                return None
            data = read_json(resp)
        except (httpx.HTTPError, MalformedResponse) as exc:
            logger.debug("Shodan InternetDB lookup failed for %s: %s", ioc_value, describe_exception(exc))
            return None
        if not isinstance(data, dict):
            return None
        ports = [p for p in (data.get("ports") or []) if isinstance(p, int)][:_MAX_PORTS]
        vulns = [str(v) for v in (data.get("vulns") or [])][:25]
        hostnames = [str(h) for h in (data.get("hostnames") or [])][:10]
        cpes = [str(c) for c in (data.get("cpes") or [])][:10]
        provider_tags = [str(t) for t in (data.get("tags") or []) if isinstance(t, str) and t.strip()][:10]
        tags = ["internetdb", *provider_tags]
        if vulns:
            tags.append("known_vulnerabilities")
        return NormalizedResult(
            ioc=ioc_value, ioc_type="ipv4", source=self.name,
            verdict="unknown", raw_score=None, tags=tags, status="found",
            provider_summary=f"InternetDB lists {len(ports)} open port(s) and {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
            raw_data={
                "source": "internetdb", "ports": ports, "vulns": vulns,
                "hostnames": hostnames, "cpes": cpes,
            },
        )

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        internetdb_result = await self._internetdb_lookup(ioc_value)
        if internetdb_result is not None:
            return internetdb_result

        if not is_valid_api_key(self.api_key):
            return not_configured(
                self.name, ioc_value, ioc_type,
                "no InternetDB data for this IP and no SHODAN_API_KEY configured for the host API",
            )

        if not self._check_credits():
            return failure(
                self.name, ioc_value, ioc_type, "unavailable", ["out_of_credits"],
                f"Shodan monthly credit budget ({self.SHODAN_MONTHLY_LIMIT}) used up locally",
                request_made=False,
            )

        client = self._get_client()
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ioc_value}",
                params={"key": self.api_key},
                timeout=15,
            )
        except httpx.HTTPError as exc:
            logger.warning("Shodan request failed for %s: %s", ioc_value, describe_exception(exc))
            return exception_result(self.name, ioc_value, ioc_type, exc)

        if resp.status_code in (401, 403):
            try:
                err_msg = str(resp.json().get("error", ""))
            except Exception:
                err_msg = ""
            if "membership" in err_msg.lower():
                # A free key cannot query /shodan/host/, and InternetDB already had no data.
                return failure(
                    self.name, ioc_value, ioc_type, "not_found", ["membership_required"],
                    "No InternetDB data; the host API needs a paid Shodan membership",
                    http_status=resp.status_code,
                )
        failed = http_failure(self.name, ioc_value, ioc_type, resp, not_found_summary="Shodan has no record of this host")
        if failed is not None:
            return failed

        ShodanAdapter._monthly_credits_used += 1
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)

        ports = [p for p in (data.get("ports") or []) if isinstance(p, int)][:_MAX_PORTS]
        services_by_port: dict[int, dict] = {}
        for svc in data.get("data") or []:
            if not isinstance(svc, dict) or svc.get("port") is None:
                continue
            http = svc.get("http") if isinstance(svc.get("http"), dict) else {}
            entry = {
                key: value
                for key, value in (
                    ("transport", svc.get("transport")),
                    ("product", svc.get("product")),
                    ("version", svc.get("version")),
                    ("cpe", svc.get("cpe") if isinstance(svc.get("cpe"), str) else None),
                    ("http_title", http.get("title")),
                    ("hostname", svc.get("hostname")),
                )
                if value
            }
            services_by_port.setdefault(svc["port"], {"port": svc["port"], **entry})
        services = [services_by_port[p] for p in sorted(services_by_port)][:_MAX_SERVICES]

        vulns = [str(v) for v in (data.get("vulns") or [])][:25]
        hostnames = [str(h) for h in (data.get("hostnames") or [])][:10]
        details = {key: data.get(key) for key in ("org", "isp", "os") if data.get(key)}
        categories = list(dict.fromkeys(str(v) for v in details.values()))
        tags = ["host_api"]
        if vulns:
            tags.append("known_vulnerabilities")
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, tags=tags,
            categories=categories, status="found", http_status=resp.status_code,
            provider_summary=f"Shodan lists {len(ports)} open port(s) and {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
            raw_data={
                "source": "host_api", "ports": ports, "services": services,
                "vulns": vulns, "hostnames": hostnames, **details,
            },
        )
