import json

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, retry_after_seconds


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


class NvdAdapter(SourceAdapter):
    """NVD CVE record lookup against the official NIST NVD JSON 2.0 API.

    ``GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}`` is
    publicly readable (no key) at ~5 requests/30s. Records without CVSS data
    map to ``unknown``; CVSS base scores drive conservative severity-derived
    verdicts. NVD complements cve.org as a second key-free CVE source.
    """

    name = "NVD"
    supported_types = ["cve"]
    public_without_key = True
    produces_reputation = False
    produces_vulnerability_intelligence = True
    produces_metadata = True
    produces_relationships = True
    provenance_family = "cve_records"
    rate_limit = RateLimitConfig(requests_per_minute=10)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        cve_id = ioc_value.strip().upper()
        client = self._get_client()
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=15,
        )

        if resp.status_code in (429, 503):
            return NormalizedResult(
                ioc=cve_id, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="rate_limited", assessment_domain="vulnerability", tags=["rate_limited"], http_status=resp.status_code,
                retry_after_seconds=retry_after_seconds(resp),
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=cve_id, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="provider_error", assessment_domain="vulnerability", tags=[f"http_{resp.status_code}"],
            )

        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            return NormalizedResult(
                ioc=cve_id, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="malformed_response", assessment_domain="vulnerability", tags=["malformed_response"],
            )
        vulnerabilities = data.get("vulnerabilities") or []
        if not vulnerabilities:
            return NormalizedResult(
                ioc=cve_id, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="record_not_found", assessment_domain="vulnerability", raw_score=0.0, status="not_found",
            )

        record = vulnerabilities[0].get("cve") or {}
        vuln_status = str(record.get("vulnStatus") or "")
        descriptions = record.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descriptions if (d.get("lang") or "").lower().startswith("en") and d.get("value")),
            next((d.get("value", "") for d in descriptions if d.get("value")), ""),
        )

        metrics = record.get("metrics") or {}
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries and isinstance(entries[0], dict) and isinstance(entries[0].get("cvssData"), dict):
                cvss = entries[0]["cvssData"]
                break

        base_score = None
        severity = ""
        if isinstance(cvss, dict):
            try:
                base_score = float(cvss.get("baseScore"))
            except (TypeError, ValueError):
                base_score = None
            severity = str(cvss.get("baseSeverity") or "")

        cwe_values = []
        for weakness in (record.get("weaknesses") or []):
            for desc in (weakness.get("description") or []):
                value = desc.get("value", "")
                if value:
                    cwe_values.append(value)
        cwes = [w.split(":")[-1].strip() if ":" in w else w for w in cwe_values if w]

        references = [
            ref.get("url", "") for ref in (record.get("references") or []) if ref.get("url")
        ]

        tags = []
        if description:
            tags.append("record_found")
        if vuln_status.upper() == "REJECTED":
            tags.append("rejected")
        if record.get("cveTags"):
            tags.append(f"cve_tags:{len(record['cveTags'])}")
        if base_score is not None:
            tags.append(f"cvss:{base_score}")
            tags.append(f"severity:{severity}" if severity else f"severity:{_severity_label(base_score)}")
        for cwe in cwes[:5]:
            tags.append(f"cwe:{cwe}")
        if references:
            tags.append(f"references:{len(references)}")

        verdict = "unknown"
        raw_score = None
        confidence = "high" if base_score is not None else "low"

        return NormalizedResult(
            ioc=cve_id,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            assessment_domain="vulnerability",
            provider_verdict="record_found",
            normalized_verdict="unknown",
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            categories=cwes,
            related_iocs=[(ref, "reference") for ref in references[:10]],
            first_seen=record.get("published"),
            last_seen=record.get("lastModified"),
            source_link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            reports_count=None,
            vulnerability_status=vuln_status.lower() or None,
            severity=(severity or (_severity_label(base_score) if base_score is not None else "informational")).lower(),
            cvss_score=base_score,
            cvss_vector=(cvss or {}).get("vectorString") or (cvss or {}).get("vector") if isinstance(cvss, dict) else None,
            cwe=cwes,
            affected_products=[],
            published_at=record.get("published"),
            modified_at=record.get("lastModified"),
            exploit_status="unknown",
            references=references,
            source_record_id=cve_id,
            source_independence_group="cve_record",
            raw_data={
                "cve_id": cve_id,
                "description": description[:500],
                "cvss": cvss,
                "cwes": cwe_values,
                "references": references[:20],
                "published": record.get("published"),
                "lastModified": record.get("lastModified"),
            },
        )
