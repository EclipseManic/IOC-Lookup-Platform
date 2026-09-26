import logging
from datetime import datetime

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key, retry_after_seconds
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("hybrid_analysis")


class HybridAnalysisAdapter(SourceAdapter):
    name = "Hybrid Analysis"
    supported_types = ["md5", "sha1", "sha256", "mutex", "named_pipe", "registry_key", "service_name", "ssdeep"]
    rate_limit = RateLimitConfig(requests_per_minute=100, requests_per_day=3000)

    def __init__(self):
        self.api_key = settings.hybridanalysis_api_key

    async def _search_by_terms(self, client, ioc_value: str, ioc_type: str):
        """Search Hybrid Analysis by host-artifact terms.

        Uses the documented search/terms endpoint for non-hash IOCs.
        Returns the first matching report, None for not-found,
        or sentinel strings "rate_limited", "auth_error", "error" for transient failures.
        """
        try:
            # Map IOC type to search field — Hybrid uses generic term search
            resp = await client.post(
                "https://hybrid-analysis.com/api/v2/search/terms",
                json={"terms": [ioc_value]},
                headers={
                    "api-key": self.api_key,
                    "user-agent": "IOC-Platform/1.0",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=15,
            )
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("Hybrid Analysis rate limited for %s", ioc_value)
                return "rate_limited"
            if resp.status_code in (401, 403):
                logger.warning("Hybrid Analysis auth failed %s for %s", resp.status_code, ioc_value)
                return "auth_error"
            if resp.status_code != 200:
                logger.warning("Hybrid Analysis search/terms failed %s for %s", resp.status_code, ioc_value)
                return "error"
            data = resp.json()
            # Response is {"result": [...]} or list
            items = data.get("result", data) if isinstance(data, dict) else data
            if not isinstance(items, list) or not items:
                return None
            return items[0]
        except Exception as exc:
            logger.debug("Hybrid Analysis _search_by_terms exception for %s: %s", ioc_value, exc)
            return "error"

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        client = self._get_client()
        # Host-artifact and ssdeep types use term search instead of hash lookup
        if ioc_type in ("mutex", "named_pipe", "registry_key", "service_name", "ssdeep"):
            term_result = await self._search_by_terms(client, ioc_value, ioc_type)
            if term_result == "rate_limited":
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="unknown", tags=["rate_limited"],
                )
            if term_result == "auth_error":
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="error", tags=["http_401", "auth_error"],
                )
            if term_result == "error":
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="error", tags=["search_error"],
                )
            if term_result is None:
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="unknown", raw_score=0.0, status="not_found",
                    tags=["term_not_found"],
                )
            # Reuse report parsing by wrapping term result as report
            # Term search returns summary; fetch full report if sha256 available
            sha = term_result.get("sha256", "")
            if sha:
                # Fetch full sample for verdict
                resp = await client.get(
                    f"https://hybrid-analysis.com/api/v2/search/hash",
                    params={"hash": sha},
                    headers={
                        "api-key": self.api_key,
                        "user-agent": "IOC-Platform/1.0",
                        "Accept": "application/json",
                    },
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list) and data:
                        report = data[0]
                        # Parse as normal hash result but keep original IOC
                        return await self._parse_report(report, ioc_value, ioc_type, client)
            # Fallback: parse term result directly
            return await self._parse_report(term_result, ioc_value, ioc_type, client)

        try:
            resp = await client.get(
                "https://hybrid-analysis.com/api/v2/search/hash",
                params={"hash": ioc_value},
                headers={
                    "api-key": self.api_key,
                    "user-agent": "IOC-Platform/1.0",
                    "Accept": "application/json",
                },
                timeout=30,
            )
        except httpx.TimeoutException:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="timeout", tags=["timeout"],
            )
        except (httpx.ConnectError, httpx.HTTPError) as exc:
            logger.warning("Hybrid Analysis connection failed: %s", exc)
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", execution_state="error", tags=["connection_error"],
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
        if not isinstance(data, list) or not data:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
            )

        report = data[0]
        return await self._parse_report(report, ioc_value, ioc_type, client)

    async def _parse_report(self, report: dict, ioc_value: str, ioc_type: str, client) -> NormalizedResult:
        threat_score = report.get("threat_score")
        if threat_score is None:
            threat_score = 0
        ha_verdict = report.get("verdict", "unknown")

        if ha_verdict == "malicious" or threat_score >= 70:
            verdict = "malicious"
            confidence = "high"
            raw_score = min(threat_score / 100.0, 1.0)
        elif ha_verdict == "suspicious" or threat_score >= 30:
            verdict = "suspicious"
            confidence = "medium"
            raw_score = threat_score / 100.0
        elif ha_verdict == "clean" or threat_score == 0:
            verdict = "clean"
            confidence = "medium"
            raw_score = 0.0
        else:
            verdict = "unknown"
            confidence = "low"
            raw_score = 0.0

        tags = list(report.get("classification_tags", []))
        tags.append(f"score:{threat_score}")

        vx_family = report.get("vx_family", "")
        submit_name = report.get("submit_name", "")
        malware_family = vx_family or submit_name or None

        mitre = []
        if verdict in ("malicious", "suspicious"):
            sha256 = report.get("sha256", "") or ioc_value
            try:
                mitre_resp = await client.get(
                    f"https://hybrid-analysis.com/api/v2/report/{sha256}/mitre",
                    headers={
                        "api-key": self.api_key,
                        "user-agent": "IOC-Platform/1.0",
                        "Accept": "application/json",
                    },
                    timeout=15,
                )
                if mitre_resp.status_code == 200:
                    mitre_data = mitre_resp.json()
                    if isinstance(mitre_data, list):
                        for entry in mitre_data:
                            if isinstance(entry, dict):
                                aid = entry.get("id", entry.get("attack_id", ""))
                                if aid:
                                    mitre.append(aid)
            except Exception as exc:
                logger.debug("Hybrid Analysis MITRE extraction failed: %s", exc)
        if not mitre:
            mitre = report.get("mitre_attack_ids", [])
        if isinstance(submit_name, str) and submit_name:
            tags.append(f"family:{submit_name}")

        extracted_files = report.get("extracted_files", [])
        dropped = []
        for ef in extracted_files:
            if isinstance(ef, dict):
                dropped.append(ef.get("name", ef.get("file_path", str(ef))))

        registry_keys = report.get("registry_keys", [])
        if isinstance(registry_keys, list):
            registry_keys = [str(rk) for rk in registry_keys]

        domains = report.get("domains", [])
        hosts = report.get("hosts", [])
        network_iocs = []
        for d in domains:
            if isinstance(d, str):
                network_iocs.append((d, "domain"))
        for h in hosts:
            if isinstance(h, str) and not any(n[0] == h for n in network_iocs):
                network_iocs.append((h, "ip"))

        process_tree = ""
        process_list = report.get("process_list", [])
        if process_list:
            parts = []
            for proc in process_list:
                if isinstance(proc, dict):
                    parts.append(proc.get("name", str(proc)))
                elif isinstance(proc, str):
                    parts.append(proc)
            process_tree = " -> ".join(parts)

        ssdeep = report.get("ssdeep", "") or ""
        tlsh = report.get("tlsh", "") or ""

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=raw_score,
            tags=tags,
            categories=[submit_name, report.get("environment_description", ""), ha_verdict],
            malware_family=malware_family,
            mitre_attck=mitre,
            first_seen=self._parse_dt(report.get("analysis_start_time")),
            source_link=f"https://hybrid-analysis.com/sample/{ioc_value}",
            reports_count=1,
            dropped_files=dropped,
            registry_keys=registry_keys,
            network_iocs=network_iocs,
            process_tree=process_tree or None,
            ssdeep=ssdeep or None,
            tlsh=tlsh or None,
            raw_data=report,
        )

    def _parse_dt(self, val: str) -> datetime | None:
        if not val:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
        return None
