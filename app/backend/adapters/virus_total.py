import base64
from datetime import datetime
import hashlib

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class VirusTotalAdapter(SourceAdapter):
    name = "VirusTotal"
    supported_types = ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]
    rate_limit = RateLimitConfig(requests_per_minute=4, requests_per_day=500)

    def __init__(self):
        self.api_key = settings.virustotal_api_key
        rpm = getattr(settings, "vt_rate_per_minute", None)
        if rpm and rpm > 0:
            self.rate_limit = RateLimitConfig(requests_per_minute=rpm, requests_per_day=500)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        endpoint = self._endpoint(ioc_value, ioc_type)
        if not endpoint:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["unsupported_type"],
            )

        client = self._get_client()
        resp = await client.get(
                endpoint,
                headers={"x-apikey": self.api_key, "accept": "application/json"},
                timeout=15,
            )

        if resp.status_code == 401:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["invalid_api_key"],
            )
        if resp.status_code in (400, 404):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
            )
        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"],
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", raw_score=0.0, tags=[f"http_{resp.status_code}"],
            )

        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        ratio = malicious / total if total > 0 else 0.0
        if ratio >= 0.1:
            verdict = "malicious"
        elif malicious > 0 or suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        score = ratio
        confidence = "high" if malicious >= 5 else "medium" if malicious > 0 else "low"
        raw_data = {
            "detection_ratio": f"{malicious}/{total}",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        }

        threat_classification = attrs.get("popular_threat_classification")
        if not isinstance(threat_classification, dict):
            threat_classification = {}
        threat_label = threat_classification.get("suggested_threat_label", "")
        family = ""
        if threat_label:
            parts = threat_label.split(".")
            family = parts[-1] if len(parts) > 1 else threat_label

        tags = attrs.get("tags", [])
        categories_data = attrs.get("categories")
        if not isinstance(categories_data, dict):
            categories_data = {}
        categories = list(categories_data.values()) or []

        mitre = []
        sandbox_verdicts = attrs.get("sandbox_verdicts")
        if not isinstance(sandbox_verdicts, dict):
            sandbox_verdicts = {}
        for v in sandbox_verdicts.values():
            if isinstance(v, dict):
                for m in v.get("mitre_attack_ids", []):
                    if m not in mitre:
                        mitre.append(m)

        last_analysis = attrs.get("last_analysis_results", {}) or {}
        samples = []
        for eng, res in last_analysis.items():
            if isinstance(res, dict) and res.get("result"):
                samples.append(f"{eng}: {res['result']}")
        samples = samples[:20]

        related = []
        if ioc_type in ("ipv4", "domain", "url"):
            resolutions = attrs.get("resolutions", []) or []
            for res in resolutions[:10]:
                if isinstance(res, dict) and res.get("host_name"):
                    related.append((res["host_name"], "resolves_to"))

        type_description = attrs.get("type_description", "")
        if type_description:
            tags.append(f"file_type: {type_description}")

        names = attrs.get("names", [])
        if names:
            tags.append(f"file_name: {names[0]}")

        sig_info = attrs.get("signature_info", {})
        if sig_info and isinstance(sig_info, dict):
            for k, v in sig_info.items():
                if v:
                    tags.append(f"{k}: {v}")

        first_sub = attrs.get("first_submission_date")
        first_seen = None
        if first_sub:
            try:
                ts = int(first_sub)
                if ts > 1e10:
                    ts = ts / 1000
                first_seen = datetime.fromtimestamp(ts)
            except (TypeError, ValueError, OSError, OverflowError):
                first_seen = None

        last_sub = attrs.get("last_submission_date")
        last_seen = None
        if last_sub:
            try:
                ts = int(last_sub)
                if ts > 1e10:
                    ts = ts / 1000
                last_seen = datetime.fromtimestamp(ts)
            except (TypeError, ValueError, OSError, OverflowError):
                last_seen = None

        total_votes = attrs.get("total_votes", {})
        if total_votes:
            vm = total_votes.get("malicious", 0)
            if vm:
                tags.append(f"votes_malicious: {vm}")
            vh = total_votes.get("harmless", 0)
            if vh:
                tags.append(f"votes_harmless: {vh}")

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=round(score, 4),
            tags=tags,
            categories=categories,
            malware_family=family or None,
            mitre_attck=mitre,
            related_iocs=related,
            source_link=f"https://www.virustotal.com/gui/{self._url_type(ioc_type)}/{ioc_value}",
            reports_count=malicious,
            first_seen=first_seen,
            last_seen=last_seen,
            samples=samples,
            raw_data=raw_data,
        )

    def _endpoint(self, value: str, ioc_type: str) -> str:
        base = "https://www.virustotal.com/api/v3"
        mapping = {
            "md5": f"{base}/files/{value}",
            "sha1": f"{base}/files/{value}",
            "sha256": f"{base}/files/{value}",
            "ipv4": f"{base}/ip_addresses/{value}",
            "ipv6": f"{base}/ip_addresses/{value}",
            "domain": f"{base}/domains/{value}",
            "url": f"{base}/urls/{base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip('=')}",
        }
        return mapping.get(ioc_type, "")

    def _url_type(self, ioc_type: str) -> str:
        return {
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
            "ipv4": "ip-address",
            "ipv6": "ip-address",
        }.get(ioc_type, ioc_type)
