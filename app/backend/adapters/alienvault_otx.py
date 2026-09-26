import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key, retry_after_seconds
from app.backend.config import settings
from app.backend.logger import get_logger


logger = get_logger("adapter.alienvault_otx")


_TYPE_TO_SEGMENT = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "domain",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


class AlienVaultOTXAdapter(SourceAdapter):
    name = "AlienVault OTX"
    supported_types = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]
    public_without_key = False
    rate_limit = RateLimitConfig(requests_per_minute=16, requests_per_day=1000, max_retries=1, timeout_seconds=10.0)

    def __init__(self):
        self.api_key = settings.alienvault_otx_api_key

    async def _sub_request(self, url: str) -> dict | None:
        if not self._check_circuit():
            return None
        try:
            headers = {"X-OTX-API-KEY": self.api_key} if is_valid_api_key(self.api_key) else None
            resp = await self._get_client().get(
                url, headers=headers, timeout=10,
            )
            if resp.status_code == 200:
                self._record_success()
                return resp.json()
            if resp.status_code == 429:
                self._record_failure()
            return None
        except Exception:
            self._record_failure()
            return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        segment = _TYPE_TO_SEGMENT.get(ioc_type)
        if not segment:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["unsupported_type"],
            )

        # OTX's public endpoint is not a reliable anonymous lookup path: in
        # some environments it returns a normal 200 response without usable
        # reputation data instead of a 401.  Surface that condition explicitly
        # so batch scans account for it as provider unavailability.
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                execution_state="unavailable",
                tags=["no_api_key_configured", "public_fallback"],
                request_made=False,
            )

        headers = {"X-OTX-API-KEY": self.api_key} if is_valid_api_key(self.api_key) else None
        client = self._get_client()
        try:
            resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/reputation",
                    headers=headers,
                    timeout=10,
                )
        except httpx.TimeoutException:
            self._record_failure()
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["timeout"],
            )
        except httpx.HTTPError as exc:
            self._record_failure()
            logger.warning("OTX reputation request failed: %s", exc.__class__.__name__)
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["request_error"],
            )

        if resp.status_code == 401:
            if not is_valid_api_key(self.api_key):
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="unknown", status="not_found", tags=["no_api_key_configured","public_fallback"],
                )
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized"],
            )
        if resp.status_code == 404:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
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
        pulse_count = data.get("pulse_count", 0)
        threat_score = data.get("threat_score", 0)

        tags = []
        if pulse_count > 0:
            tags.append(f"pulses:{pulse_count}")
        pulses = data.get("pulses", []) or []
        for p in pulses[:5]:
            if isinstance(p, dict):
                name = p.get("name", "")
                if name:
                    tags.append(f"pulse:{name[:60]}")
                threat_type = p.get("threat_type", "")
                if threat_type:
                    tags.append(f"threat_type:{threat_type}")

        all_families = set()
        all_mitre = set()
        try:
            general_data = await self._sub_request(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/general"
            )
            if general_data:
                base_indicator = general_data.get("base_indicator", {})
                if isinstance(base_indicator, dict):
                    itype = base_indicator.get("type", "")
                    if itype: tags.append(f"otx_indicator_type: {itype}")
                    iid = base_indicator.get("id", "")
                    if iid: tags.append(f"otx_indicator_id: {iid}")
                validation = general_data.get("validation", "")
                if validation: tags.append(f"validation: {validation}")
                pulse_info = general_data.get("pulse_info", {})
                related_pulses = pulse_info.get("related_pulses", []) or []
                for pulse in related_pulses[:5]:
                    if not isinstance(pulse, dict): continue
                    pname = pulse.get("name", "")
                    if pname: tags.append(f"pulse:{pname[:60]}")
                    for pt in (pulse.get("tags", []) or []):
                        if pt: all_families.add(pt)
                    for mf in (pulse.get("malware_families", []) or []):
                        if mf: all_families.add(mf)
                    for attack in (pulse.get("attack_ids", []) or []):
                        if isinstance(attack, dict):
                            aid = attack.get("id", "")
                            if aid: all_mitre.add(aid)
                pc = pulse_info.get("count", 0)
                if pc > pulse_count: pulse_count = pc
        except Exception as exc:
            logger.debug("AlienVault OTX pulse parsing failed: %s", exc)

        related = []
        if ioc_type in ("domain", "ipv4"):
            pd_data = await self._sub_request(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/passive_dns"
            )
            if pd_data:
                for entry in (pd_data.get("passive_dns", []) or [])[:10]:
                    if isinstance(entry, dict):
                        hostname = entry.get("hostname", "")
                        address = entry.get("address", "")
                        if hostname and address:
                            related.append((f"{hostname}:{address}", "passive_dns"))

        if ioc_type == "domain":
            whois_data = await self._sub_request(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/whois"
            )
            if whois_data:
                for key in ("registrant_name", "registrar", "created"):
                    val = whois_data.get(key, "")
                    if val:
                        tags.append(f"whois_{key}:{str(val)[:80]}")

        extra_data = {}
        malware_urls: list[str] = []
        associated_hashes: list[str] = []

        if ioc_type in ("ipv4", "ipv6"):
            geo_data = await self._sub_request(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/geo"
            )
            if geo_data and isinstance(geo_data, dict):
                for key in ("country_code", "country_name", "city", "latitude", "longitude", "asn"):
                    val = geo_data.get(key)
                    if val:
                        extra_data[key] = val
                if extra_data.get("country_name") or extra_data.get("city"):
                    extra_data["geoip"] = True

        # URL list sub-endpoint: malicious URLs hosted on/associated with this indicator
        if ioc_type in ("ipv4", "ipv6", "domain"):
            url_list_data = await self._sub_request(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/url_list"
            )
            if url_list_data and isinstance(url_list_data, dict):
                for entry in (url_list_data.get("url_list", []) or [])[:25]:
                    if isinstance(entry, dict):
                        url = entry.get("url", "")
                        if url:
                            malware_urls.append(url)

        # Malware sub-endpoint: file hashes associated with this indicator
        if ioc_type in ("ipv4", "ipv6", "domain"):
            malware_data = await self._sub_request(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/malware"
            )
            if malware_data and isinstance(malware_data, dict):
                for entry in (malware_data.get("data", []) or [])[:10]:
                    if isinstance(entry, dict):
                        h = entry.get("hash", "")
                        if h:
                            associated_hashes.append(h)

        # Analysis sub-endpoint: for IPs and file hashes
        if ioc_type in ("ipv4", "ipv6", "md5", "sha1", "sha256"):
            analysis_data = await self._sub_request(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/analysis"
            )
            if analysis_data and isinstance(analysis_data, dict):
                analysis = analysis_data.get("analysis", {})
                if isinstance(analysis, dict):
                    plugin_results = analysis.get("plugin_output", "") or analysis.get("plugins", "")
                    if plugin_results:
                        extra_data["analysis"] = plugin_results

        if pulse_count > 0 and threat_score >= 5:
            verdict = "malicious"
            raw_score = min(threat_score / 10.0, 1.0)
            confidence = "high"
        elif pulse_count > 0:
            verdict = "suspicious"
            raw_score = 0.4
            confidence = "medium"
        else:
            verdict = "unknown"
            raw_score = None
            confidence = "low"

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, confidence=confidence, raw_score=raw_score,
            tags=tags, reports_count=pulse_count,
            malware_family=", ".join(sorted(all_families)) or None,
            mitre_attck=sorted(all_mitre),
            related_iocs=related,
            raw_data={
                "api_response": data,
                "malware_urls": malware_urls,
                "associated_hashes": associated_hashes,
                **extra_data,
            },
        )
