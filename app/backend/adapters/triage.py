import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class TriageAdapter(SourceAdapter):
    name = "Tria.ge"
    supported_types = ["md5", "sha1", "sha256"]
    rate_limit = RateLimitConfig(requests_per_minute=10)

    def __init__(self):
        self.api_key = settings.triage_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        client = self._get_client()
        resp = await client.get(
                f"https://api.tria.ge/v2/sample/{ioc_value}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30,
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
        status = data.get("status", "")

        if status == "complete":
            try:
                overview_resp = await client.get(
                    f"https://api.tria.ge/v2/sample/{ioc_value}/overview.json",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=15,
                )
                if overview_resp.status_code == 200:
                    overview = overview_resp.json()
                    if isinstance(overview, dict):
                        for sig in overview.get("signatures", []):
                            if isinstance(sig, str) and sig not in tags:
                                tags.append(f"sig:{sig}")
                        for mitre_id in overview.get("mitre_attck", []):
                            if isinstance(mitre_id, str) and mitre_id not in mitre:
                                mitre.append(mitre_id)
            except Exception:
                pass

        if status != "complete":
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, tags=[f"status_{status}"],
            )

        sample_verdict = data.get("verdict", "unknown")
        score = data.get("score", 0)

        if sample_verdict == "malicious":
            verdict = "malicious"
            confidence = "high"
            raw_score = min(score / 10.0 if score else 1.0, 1.0)
        elif sample_verdict == "suspicious":
            verdict = "suspicious"
            confidence = "medium"
            raw_score = 0.5
        elif sample_verdict == "clean":
            verdict = "clean"
            confidence = "medium"
            raw_score = 0.0
        else:
            verdict = "unknown"
            confidence = "low"
            raw_score = 0.0

        tags = list(data.get("tags", []))
        signatures = data.get("signatures", [])
        tags.extend(f"sig:{s}" for s in signatures if isinstance(s, str))

        mitre = data.get("mitre_attck", [])
        if isinstance(mitre, list):
            mitre = [str(m) for m in mitre]

        target = data.get("target", {}) or {}
        file_info = target.get("file", {}) or {}
        file_name = file_info.get("name", "")

        dropped = []
        extracted = data.get("extracted", {}) or {}
        for f in extracted.get("files", []):
            if isinstance(f, dict):
                dropped.append(f.get("name", f.get("path", str(f))))
            elif isinstance(f, str):
                dropped.append(f)

        registry_keys = []
        for rkey in extracted.get("registry", []):
            if isinstance(rkey, dict):
                registry_keys.append(rkey.get("path", rkey.get("key", str(rkey))))
            elif isinstance(rkey, str):
                registry_keys.append(rkey)

        network_iocs = []
        network = data.get("network", {}) or {}
        for dns_entry in network.get("dns", []):
            if isinstance(dns_entry, dict):
                dom = dns_entry.get("domain", "")
                ip = dns_entry.get("ip", "")
                if dom:
                    network_iocs.append((dom, "domain"))
                if ip:
                    network_iocs.append((ip, "ip"))
        for tcp_entry in network.get("tcp", []):
            if isinstance(tcp_entry, dict):
                tip = tcp_entry.get("ip", "")
                if tip and not any(n[0] == tip for n in network_iocs):
                    network_iocs.append((tip, "ip"))

        process_tree = data.get("process", "")

        tlsh = extracted.get("tlsh", "") or file_info.get("tlsh", "")
        ssdeep = file_info.get("ssdeep", "")

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=raw_score,
            tags=tags,
            categories=[file_name, sample_verdict] if file_name else [sample_verdict],
            malware_family=next((s for s in signatures if isinstance(s, str)), None),
            mitre_attck=mitre,
            first_seen=self._parse_dt(data.get("submitted")),
            last_seen=self._parse_dt(data.get("completed")),
            source_link=f"https://tria.ge/s/{ioc_value}",
            reports_count=1,
            dropped_files=dropped,
            registry_keys=registry_keys,
            network_iocs=network_iocs,
            process_tree=process_tree or None,
            ssdeep=ssdeep or None,
            tlsh=tlsh or None,
        )

    def _parse_dt(self, val: str) -> str | None:
        if not val:
            return None
        try:
            from datetime import datetime
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(val[:19], fmt)
                    return dt.isoformat()
                except ValueError:
                    continue
            return val[:19]
        except Exception:
            return None
