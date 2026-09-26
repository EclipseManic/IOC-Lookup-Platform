"""Hudson Rock Cavalier Infostealers API adapter.

Public API - no API key required!
Rate limit: 50 requests per 10 seconds.

Endpoints used:
  - Search by email:  https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=X
  - Search by IP:     https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip?ip=X
  - Search by domain: https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=X
  - URLs by domain:   https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=X

All responses are parsed for infostealer infection data, stealer families, compromised credentials,
and related threat intelligence.
"""

import httpx

from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    retry_after_seconds,
)
from app.backend.logger import get_logger

logger = get_logger("adapter.hudson_rock")

_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "IOC-Platform/1.0",
}


class HudsonRockAdapter(SourceAdapter):
    """Hudson Rock Cavalier — free public infostealer intelligence API."""

    name = "Hudson Rock"
    supported_types = ["email", "ipv4", "domain", "url", "username"]
    # Public API: 50 req / 10s = 300 req/min; we stay conservative at 120/min
    rate_limit = RateLimitConfig(requests_per_minute=120, requests_per_day=10_000)
    public_without_key = True  # No API key needed

    def __init__(self):
        super().__init__()
        self.api_key = None  # Not required for the Cavalier public API

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type not in self.supported_types:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                execution_state="not_applicable",
                tags=["unsupported_provider_type"],
            )

        client = self._get_client()

        # --- Route to correct endpoint ---
        if ioc_type == "email":
            url = f"{_BASE}/search-by-email"
            params = {"email": ioc_value}
        elif ioc_type == "ipv4":
            url = f"{_BASE}/search-by-ip"
            params = {"ip": ioc_value}
        elif ioc_type == "username":
            url = f"{_BASE}/search-by-username"
            params = {"username": ioc_value}
        elif ioc_type in ("domain", "url"):
            # Strip scheme from URL to get the domain
            domain = ioc_value
            if "://" in domain:
                domain = domain.split("://", 1)[1].split("/")[0]
            url = f"{_BASE}/search-by-domain"
            params = {"domain": domain}
        else:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", execution_state="not_applicable",
                tags=["unsupported_provider_type"],
            )

        try:
            resp = await client.get(url, params=params, headers=_HEADERS, timeout=15)
        except httpx.TimeoutException:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="timeout", tags=["timeout"],
            )
        except httpx.HTTPError as exc:
            logger.warning("Hudson Rock request failed: %s", exc)
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="error", tags=["request_error"],
            )

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", execution_state="rate_limited",
                tags=["rate_limited"], http_status=429,
                retry_after_seconds=retry_after_seconds(resp),
            )

        if resp.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                status="not_found", verdict="clean", execution_state="success",
                raw_score=0.0, tags=["no_infostealer_compromise"],
                source_link="https://www.hudsonrock.com/",
                provider_summary="No infostealer infection found in Hudson Rock database",
                http_status=404,
            )

        if resp.status_code == 400:
            err_text = ""
            try:
                err_text = resp.text
            except Exception:
                pass
            logger.info("Hudson Rock restricted domain query for %s: %s", ioc_value, err_text)
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                status="not_found", verdict="unknown", execution_state="success",
                raw_score=0.0, tags=["domain_search_restricted"],
                source_link="https://www.hudsonrock.com/",
                provider_summary="Hudson Rock limits infostealer search on broad public domains",
                http_status=400,
            )

        if resp.status_code not in (200, 201):
            logger.warning("Hudson Rock unexpected status %s for %s", resp.status_code, ioc_value)
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="error",
                tags=[f"http_{resp.status_code}"], http_status=resp.status_code,
            )

        try:
            data = resp.json()
        except Exception:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="error",
                tags=["malformed_response"],
            )
        if not isinstance(data, dict):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="error",
                tags=["malformed_response"],
            )

        # For domain lookups, also query urls-by-domain for compromised URLs
        if ioc_type in ("domain", "url"):
            domain_val = ioc_value
            if "://" in domain_val:
                domain_val = domain_val.split("://", 1)[1].split("/")[0]
            try:
                urls_resp = await client.get(
                    f"{_BASE}/urls-by-domain",
                    params={"domain": domain_val},
                    headers=_HEADERS,
                    timeout=10,
                )
                if urls_resp.status_code == 200:
                    urls_data = urls_resp.json()
                    if isinstance(urls_data, dict):
                        data["_urls_by_domain"] = urls_data
            except Exception as exc:
                logger.debug("Hudson Rock urls-by-domain failed: %s", exc)

        return self._parse_response(ioc_value, ioc_type, data)

    def _parse_response(self, ioc_value: str, ioc_type: str, data: dict) -> NormalizedResult:
        """Parse Cavalier API response into a NormalizedResult."""

        stealers_list = data.get("stealers") or []
        total_corporate = data.get("total_corporate_services", 0) or 0
        total_user = data.get("total_user_services", 0) or 0
        stealer_families_raw = data.get("stealerFamilies") or {}

        # Count infections and extract stealer family names
        infection_count = len(stealers_list) if stealers_list else 0
        total_credentials = total_corporate + total_user

        # Collect stealer family names from either stealers list or stealerFamilies dict
        families: list[str] = []
        if stealer_families_raw and isinstance(stealer_families_raw, dict):
            families = [
                k for k, v in stealer_families_raw.items()
                if k not in ("total", "UNKNOWN") and isinstance(v, int) and v > 0
            ]
        elif stealers_list:
            seen: set[str] = set()
            for s in stealers_list:
                if isinstance(s, dict):
                    f = s.get("stealer_family") or s.get("malware_family") or ""
                    if f and f not in seen:
                        families.append(f)
                        seen.add(f)

        # Collect interesting metadata from individual stealers
        computers: list[str] = []
        os_list: list[str] = []
        dates: list[str] = []
        for s in stealers_list[:5]:  # Cap at 5 for tags
            if isinstance(s, dict):
                cn = s.get("computer_name")
                if cn and cn != "Not Found":
                    computers.append(cn)
                os_name = s.get("operating_system")
                if os_name:
                    os_list.append(os_name)
                dc = s.get("date_compromised")
                if dc:
                    dates.append(dc[:10])  # date portion only

        # Domain-specific: most exposed services
        top_services: list[str] = []
        if isinstance(data.get("topCorporateServices"), list):
            top_services = [
                s.get("domain", "") for s in data["topCorporateServices"][:5]
                if isinstance(s, dict) and s.get("domain")
            ]

        # External services compromised
        top_external: list[str] = []
        if isinstance(data.get("topExternalServices"), list):
            top_external = [
                s.get("domain", "") for s in data["topExternalServices"][:5]
                if isinstance(s, dict) and s.get("domain")
            ]

        # Password strength stats (when available)
        pwd_stats = data.get("passwordStrength") or {}
        pwd_weak_pct = None
        pwd_strong_pct = None
        if isinstance(pwd_stats, dict):
            total_pwd = pwd_stats.get("total", 0)
            if total_pwd > 0:
                pwd_weak_pct = round((pwd_stats.get("weak", 0) / total_pwd) * 100, 1)
                pwd_strong_pct = round((pwd_stats.get("strong", 0) / total_pwd) * 100, 1)

        # Compromised URLs count from urls-by-domain
        urls_domain_data = data.get("_urls_by_domain", {})
        total_compromised_urls = None
        if isinstance(urls_domain_data, dict):
            urls_list = urls_domain_data.get("urls", [])
            if isinstance(urls_list, list):
                total_compromised_urls = len(urls_list)

        # Build tags
        tags: list[str] = []
        if infection_count > 0:
            tags.append("infostealer_compromised")
            tags.append(f"infections:{infection_count}")
        if total_credentials > 0:
            tags.append(f"credentials_at_risk:{total_credentials}")
        if total_corporate > 0:
            tags.append(f"corporate_services:{total_corporate}")
        if infection_count > 0 or total_credentials > 0:
            for f in families[:5]:
                tags.append(f"stealer:{f}")
            if top_services:
                for svc in top_services[:3]:
                    tags.append(f"exposed_service:{svc}")

        # Build a concise human-readable summary
        if infection_count == 0 and total_credentials == 0:
            provider_summary = "No infostealer compromise observed"
        else:
            parts = [f"{infection_count} infostealer infection{'s' if infection_count != 1 else ''} detected"]
            if total_credentials:
                parts.append(f"{total_credentials} credentials at risk")
            if families:
                parts.append(f"families: {', '.join(families[:4])}")
            if total_corporate:
                parts.append(f"{total_corporate} corporate services exposed")
            provider_summary = "; ".join(parts)

        # Risk determination
        if infection_count > 0 or total_credentials > 0:
            verdict = "malicious"
            raw_score = min(0.50 + (infection_count * 0.05) + (total_corporate * 0.02), 1.0)
            confidence = "high" if infection_count >= 3 or total_corporate >= 5 else "medium"
            status = "found"
            execution_state = "success"
            reports_count = infection_count if infection_count else None
        else:
            verdict = "clean"
            raw_score = 0.0
            confidence = "low"
            status = "not_found"
            execution_state = "success"
            reports_count = None

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            status=status,
            verdict=verdict,
            execution_state=execution_state,
            raw_score=raw_score,
            confidence=confidence,
            reports_count=reports_count,
            tags=tags,
            source_link="https://www.hudsonrock.com/",
            provider_summary=provider_summary,
            raw_data={
                "total_infections": infection_count,
                "total_corporate_services": total_corporate,
                "total_user_services": total_user,
                "stealer_families": stealer_families_raw if stealer_families_raw else families,
                "sample_computers": computers[:3],
                "sample_os": os_list[:3],
                "dates_compromised": sorted(set(dates))[-3:] if dates else [],
                "top_corporate_services": top_services,
                "top_external_services": top_external,
                "password_strength_weak_pct": pwd_weak_pct,
                "password_strength_strong_pct": pwd_strong_pct,
                "total_compromised_urls": total_compromised_urls,
                "raw_message": data.get("message", ""),
            },
        )
