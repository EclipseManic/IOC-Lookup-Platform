import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


_TYPE_TO_SEGMENT = {
    "ipv4": "IPv4",
    "domain": "domain",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


class AlienVaultOTXAdapter(SourceAdapter):
    name = "AlienVault OTX"
    supported_types = ["ipv4", "domain", "url", "md5", "sha1", "sha256"]
    rate_limit = RateLimitConfig(requests_per_minute=16, requests_per_day=1000)

    def __init__(self):
        self.api_key = settings.alienvault_otx_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        segment = _TYPE_TO_SEGMENT.get(ioc_type)
        if not segment:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["unsupported_type"],
            )

        client = self._get_client()
        resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/reputation",
                headers={"X-OTX-API-KEY": self.api_key},
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
                verdict="unknown", raw_score=0.0,
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
            gen_resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/general",
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=15,
            )
            if gen_resp.status_code == 200:
                general_data = gen_resp.json()
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
        except Exception:
            pass

        related = []
        if ioc_type in ("domain", "ipv4"):
            try:
                pd_resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/passive_dns",
                    headers={"X-OTX-API-KEY": self.api_key}, timeout=15,
                )
                if pd_resp.status_code == 200:
                    pd_data = pd_resp.json()
                    for entry in (pd_data.get("passive_dns", []) or [])[:10]:
                        if isinstance(entry, dict):
                            hostname = entry.get("hostname", "")
                            address = entry.get("address", "")
                            if hostname and address:
                                related.append((f"{hostname}:{address}", "passive_dns"))
            except Exception:
                pass

        if ioc_type == "domain":
            try:
                whois_resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}/whois",
                    headers={"X-OTX-API-KEY": self.api_key}, timeout=15,
                )
                if whois_resp.status_code == 200:
                    whois_data = whois_resp.json()
                    for key in ("registrant_name", "registrar", "created"):
                        val = whois_data.get(key, "")
                        if val:
                            tags.append(f"whois_{key}:{str(val)[:80]}")
            except Exception:
                pass

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
        )
