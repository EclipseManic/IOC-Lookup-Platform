import time

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class SecurityTrailsAdapter(SourceAdapter):
    name = "SecurityTrails"
    supported_types = ["domain", "ipv4"]
    rate_limit = RateLimitConfig(requests_per_minute=5)

    MONTHLY_LIMIT = 50
    _monthly_requests_used = 0
    _quota_reset_time = 0.0

    def __init__(self):
        self.api_key = settings.securitytrails_api_key

    def _check_quota(self) -> bool:
        now = time.time()
        if now > self._quota_reset_time:
            self._monthly_requests_used = 0
            self._quota_reset_time = now + 2592000
        return self._monthly_requests_used < self.MONTHLY_LIMIT

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        if not self._check_quota():
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["out_of_quota"],
            )

        headers = {"APIKEY": self.api_key, "accept": "application/json"}
        client = self._get_client()
        resp = await client.get(
                f"https://api.securitytrails.com/v1/domain/{ioc_value}/subdomains",
                headers=headers,
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

        SecurityTrailsAdapter._monthly_requests_used += 1

        data = resp.json()
        subdomain_list = data.get("subdomains", [])
        tags = []
        if subdomain_list:
            tags.append(f"subdomains:{len(subdomain_list)}")
            tags.append("has_subdomains")

        related = []
        base_domain = ioc_value if ioc_type == "domain" else ""
        for sub in subdomain_list[:50]:
            if base_domain:
                related.append((f"{sub}.{base_domain}", "subdomain_of"))
        for sub in subdomain_list[:10]:
            if base_domain:
                tags.append(f"subdomain: {sub}.{base_domain}")
            else:
                tags.append(f"subdomain: {sub}")

        if ioc_type == "domain":
            try:
                dns_resp = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{ioc_value}/history/dns",
                    headers=headers, timeout=15,
                )
                if dns_resp.status_code == 200:
                    SecurityTrailsAdapter._monthly_requests_used += 1
                    dns_data = dns_resp.json()
                    records = dns_data.get("records") if isinstance(dns_data, dict) else None
                    if isinstance(records, dict):
                        for rtype in ("a", "aaaa", "mx", "ns"):
                            recs = records.get(rtype, [])
                            if recs:
                                tags.append(f"dns_{rtype}_count: {len(recs)}")
                                for rec in recs[:3]:
                                    if isinstance(rec, dict):
                                        val = rec.get("value", rec.get("hostname", ""))
                                        if val:
                                            related.append((val, f"dns_{rtype}"))
            except Exception as exc:
                logger.debug("SecurityTrails DNS enrichment failed: %s", exc)

        if ioc_type == "ipv4":
            try:
                ip_resp = await client.get(
                    f"https://api.securitytrails.com/v1/ip/{ioc_value}/subdomains",
                    headers=headers, timeout=15,
                )
                if ip_resp.status_code == 200:
                    SecurityTrailsAdapter._monthly_requests_used += 1
                    ip_data = ip_resp.json()
                    ip_subs = ip_data.get("subdomains", [])
                    tags.append(f"ip_subdomains: {len(ip_subs)}")
                    for sub in ip_subs[:10]:
                        related.append((sub, "ip_subdomain"))
            except Exception as exc:
                logger.debug("SecurityTrails subdomain lookup failed: %s", exc)

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, tags=tags,
            related_iocs=related,
        )
