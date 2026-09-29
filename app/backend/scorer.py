"""Provider-aware, explainable IOC evidence aggregation.

Provider ``raw_score`` values are deliberately preserved for display, but are
never added together here. Each adapter result is converted to an
``EvidenceObservation`` with a source role, type-aware weight, normalized
signal, and an explanation before the IOC-level decision is made.
"""

from datetime import datetime, timezone
import math
import re

from app.backend.adapters.base import (
    CompositeScore,
    EnrichmentData,
    EvidenceObservation,
    IOCAssessment,
    NormalizedResult,
    ProviderHealth,
    SourceWeight,
    normalize_provider_verdict,
)
from app.backend.config import settings
from app.backend.domain_router import assessment_domain_for, route_assessment_domain
from app.backend.evidence import evidence_freshness, normalize_provider_result
from app.backend.thresholds import (
    MALICIOUS_HIGH,
    MALICIOUS_MEDIUM,
    MIN_SOURCES_HIGH_CONFIDENCE,
    SUSPICIOUS,
)


# These are reliability weights for evidence, not provider score scales.
SOURCE_WEIGHTS = {
    "VirusTotal": 1.00,
    "AbuseIPDB": 0.8,
    "ThreatFox": 0.9,
    "MalwareBazaar": 0.9,
    "urlscan.io": 0.7,
    "CVE": 1.0,
    "Tria.ge": 0.9,
    "Hybrid Analysis": 0.9,
    "AlienVault OTX": 0.7,
    "GreyNoise": 0.4,
    "OpenPhish": 0.8,
    "URLhaus": 0.85,
    "StopForumSpam": 0.5,
}

# Evidence weights used by the new engine. Keep SOURCE_WEIGHTS above stable
# for older imports and dashboards.
_EVIDENCE_WEIGHTS = {
    **SOURCE_WEIGHTS,
    "VirusTotal": 1.00, "ThreatFox": 1.00, "MalwareBazaar": 1.00,
    "URLhaus": 0.95, "OpenPhish": 0.95, "Tria.ge": 0.95,
    "Hybrid Analysis": 0.90, "AlienVault OTX": 0.65, "urlscan.io": 0.65,
    "AbuseIPDB": 0.55, "StopForumSpam": 0.45, "AbstractAPI": 0.50, "Hunter.io": 0.50,
    "Hashlookup": 0.45, "cve.org": 0.85, "NVD": 0.85,
    "GreyNoise": 0.0, "IPinfo": 0.0, "Shodan": 0.0, "Censys": 0.0,
    "Team Cymru": 0.0, "Tor Exit": 0.60,
    "Etherscan": 0.0, "Blockchain.info": 0.0,
    "ChainAbuse": 0.95, "FileScan.io": 0.85,
    "Hudson Rock": 0.85, "HIBP Pwned Passwords": 0.95,
}

# Providers which share an upstream feed are shown independently, but only
# the strongest member of a provenance group counts toward corroboration.
_PROVENANCE_GROUPS = {
    "OpenPhish": "phishing_feeds",
    "URLhaus": "abuse_ch_feeds",
    "ThreatFox": "abuse_ch_feeds",
    "MalwareBazaar": "abuse_ch_feeds",
    "VirusTotal": "multi_engine_aggregate",
    "Tria.ge": "sandbox_reports",
    "Hybrid Analysis": "sandbox_reports",
}

INTELLIGENCE_ONLY = {
    "GreyNoise", "IPinfo", "Shodan", "Censys", "Team Cymru", "Etherscan", "Blockchain.info",
}
SUPPORTING_SOURCES = {"AbuseIPDB", "StopForumSpam", "AbstractAPI", "Hunter.io", "Hashlookup", "LeakCheck.io", "Tor Exit"}
# Backwards-compatible export for integrations that only need the qualitative
# labels. The aggregation engine does not use these values for fusion.
VERDICT_SCORES = {"malicious": 1.0, "suspicious": 0.6, "clean": 0.0, "benign": 0.0, "unknown": 0.0, "error": 0.0}
HEALTH_TAGS = {
    "rate_limited", "timeout", "request_error", "unexpected_response",
    "malformed_response", "feed_unavailable", "no_api_key_configured",
    "daily_quota_exhausted", "weekly_quota_exhausted", "monthly_quota_exhausted", "out_of_credits",
    "circuit_open", "unauthorized", "invalid_api_key", "lite_api_unavailable",
}

_TYPE_WEIGHT = {
    "md5": 1.10, "sha1": 1.10, "sha256": 1.10,
    "url": 1.00, "domain": 0.95, "email": 0.85,
    "ipv4": 0.78, "ipv6": 0.78, "cve": 1.00,
    "btc": 0.70, "eth": 0.70,
    "mutex": 0.85, "named_pipe": 0.85, "registry_key": 0.85,
    "service_name": 0.80, "ssdeep": 0.75,
}

_KNOWN_TEST_HASHES = {
    # EICAR anti-malware test file, intentionally harmless test content.
    "44d88612fea8a8f36de82e1278abb02f": "EICAR",
    "3395856ce81f2b7382dee72602f798b642f14140": "EICAR",
}

WELL_KNOWN_PUBLIC_RESOLVERS = {
    "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",              # Quad9
    "208.67.222.222", "208.67.220.220",                                    # OpenDNS
    "94.140.14.14", "94.140.15.15",                                        # AdGuard
}


def _utc_datetime(value: datetime | None) -> datetime | None:
    """Return a comparable UTC datetime for provider-supplied timestamps."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalise_confidence(value: str | None) -> str:
    return value if value in {"low", "medium", "high"} else "low"


def _time_decay(result: NormalizedResult) -> float:
    reference = _utc_datetime(result.source_timestamp or result.last_seen or result.first_seen)
    if reference is None:
        return 1.0
    now = datetime.now(timezone.utc)
    age_days = max(0.0, (now - reference).total_seconds() / 86400.0)
    return max(0.20, math.exp(-age_days / 730.0))


def _tag_set(result: NormalizedResult) -> set[str]:
    return {str(tag).strip().lower() for tag in (result.tags or []) if str(tag).strip()}


def _health_status(result: NormalizedResult) -> tuple[str, str | None]:
    explicit = str(getattr(result, "execution_state", "") or "").lower()
    if explicit in {"rate_limited", "timeout", "error", "invalid_request", "unavailable", "not_found", "not_applicable", "aborted_due_to_ioc_deadline", "batch_deadline_exceeded"}:
        if explicit == "not_found":
            return explicit, None
        if explicit == "not_applicable":
            return explicit, None
        tags = _tag_set(result)
        return explicit, next(iter(tags & HEALTH_TAGS), explicit)
    tags = _tag_set(result)
    if result.verdict == "error" or result.status == "error":
        return "error", next(iter(tags & HEALTH_TAGS), "provider_error")
    for tag in tags:
        if any(marker in tag for marker in HEALTH_TAGS):
            return "error", tag
    if result.status == "not_found":
        return "not_found", None
    if result.normalized_verdict == "not_found":
        return "not_found", None
    # A provider can successfully answer with no classification.  That is a
    # successful query, but it is not benign evidence.
    return "success", None


def _semantic_verdict(result: NormalizedResult) -> str:
    value = getattr(result, "normalized_verdict", None) or getattr(result, "provider_verdict", None) or result.verdict
    return normalize_provider_verdict(value)


def _role(result: NormalizedResult) -> str:
    if result.source in INTELLIGENCE_ONLY:
        return "context"
    if result.source in SUPPORTING_SOURCES:
        return "supporting"
    return "threat"


def _number_from_tags(tags: set[str], prefix: str) -> int | None:
    for tag in tags:
        if tag.startswith(prefix):
            try:
                return int(float(tag.split(":", 1)[1].strip()))
            except (ValueError, IndexError):
                return None
    return None


def _telemetry(result: NormalizedResult) -> tuple[int | None, int | None]:
    detection_count = result.detection_count
    total_engines = result.total_engines
    raw = result.raw_data if isinstance(result.raw_data, dict) else {}
    if detection_count is None:
        for key in ("malicious", "detection_count", "detections"):
            if isinstance(raw.get(key), (int, float)):
                detection_count = int(raw[key])
                break
    if total_engines is None:
        counts = [raw.get(key) for key in ("malicious", "suspicious", "harmless", "undetected")]
        if all(isinstance(value, (int, float)) for value in counts if value is not None) and any(value is not None for value in counts):
            total_engines = sum(int(value or 0) for value in counts)
    tags = _tag_set(result)
    detection_count = detection_count if detection_count is not None else _number_from_tags(tags, "detections:")
    total_engines = total_engines if total_engines is not None else _number_from_tags(tags, "engines:")
    return detection_count, total_engines


def _signal(result: NormalizedResult, status: str, detection_count: int | None, total_engines: int | None) -> tuple[float, str]:
    """Return a source-local signal in [0, 1], without using raw-score scales."""
    if status != "success" or _role(result) == "context":
        return 0.0, "Contextual metadata does not contribute reputation evidence."
    confidence = _normalise_confidence(result.confidence)
    tags = _tag_set(result)
    verdict = _semantic_verdict(result)

    if verdict in {"clean", "benign", "harmless", "whitelisted", "undetected"}:
        return 0.0, "A found clean result is weak negative evidence; absence is not treated as clean."
    if verdict not in {"malicious", "suspicious"}:
        return 0.0, "Provider returned insufficient evidence."

    if result.source == "VirusTotal" and verdict == "malicious":
        if detection_count is not None and total_engines and total_engines > 0:
            ratio = detection_count / total_engines
            if detection_count >= 10 and ratio >= 0.10:
                return 0.98, f"VirusTotal has {detection_count}/{total_engines} malicious engines."
            if detection_count >= 5 and ratio >= 0.05:
                return 0.82, f"VirusTotal has {detection_count}/{total_engines} malicious engines."
            if detection_count >= 2:
                return 0.58, f"VirusTotal has {detection_count}/{total_engines} malicious engines; corroboration is needed."
            return 0.32, f"VirusTotal has only {detection_count}/{total_engines} malicious engines."
        return {"high": 0.90, "medium": 0.68, "low": 0.38}[confidence], "VirusTotal reported a malicious verdict without engine telemetry."

    if result.source == "AbuseIPDB":
        reports = result.reports_count or 0
        if reports >= 50:
            signal = 0.72
        elif reports >= 10:
            signal = 0.58
        elif reports >= 3:
            signal = 0.45
        else:
            signal = 0.30
        if confidence == "high":
            signal += 0.08
        return min(signal, 0.78), f"AbuseIPDB supplied {reports} reputation report(s); this is supporting evidence, not malware attribution."

    direct = {
        "ThreatFox": 0.92,
        "MalwareBazaar": 0.96,
        "URLhaus": 0.90,
        "OpenPhish": 0.90,
        "Tria.ge": 0.88,
        "Hybrid Analysis": 0.86,
        "cve.org": 0.72,
        "NVD": 0.72,
        "CVE": 0.72,
        "AlienVault OTX": 0.58,
        "urlscan.io": 0.58,
        "StopForumSpam": 0.38,
        "AbstractAPI": 0.50,
        "Hunter.io": 0.50,
        "Hashlookup": 0.20,
        "ChainAbuse": 0.95,
        "FileScan.io": 0.85,
        "LeakCheck.io": 0.45,
    }.get(result.source, 0.45)
    if verdict == "suspicious":
        direct *= 0.62
    if confidence == "high":
        direct = min(1.0, direct + 0.05)
    if any(marker in " ".join(tags) for marker in ("test", "sample", "canary", "eicar")):
        direct *= 0.85
    return direct, f"{result.source} supplied {verdict} evidence with {confidence} confidence."


def _context_values(results: list[NormalizedResult], enrichment: EnrichmentData | None) -> list[str]:
    values: list[str] = []
    for result in results:
        if _role(result) != "context":
            continue
        for value in [*(result.tags or []), *(result.categories or [])]:
            if value and value not in values:
                values.append(value)
    if enrichment:
        geo = enrichment.geoip
        if geo:
            for value in (geo.asn, geo.asn_name, geo.isp, geo.org):
                if value and value not in values:
                    values.append(value)
        if enrichment.reverse_dns:
            values.extend(v for v in enrichment.reverse_dns.hostnames if v not in values)
        if enrichment.dns:
            values.extend(v for v in enrichment.dns.cname if v not in values)
        if enrichment.open_ports:
            values.append(f"open_ports:{','.join(map(str, enrichment.open_ports))}")
    return values[:50]


def _provider_health(results: list[NormalizedResult]) -> list[ProviderHealth]:
    grouped: dict[str, ProviderHealth] = {}
    for result in results:
        state, _ = _health_status(result)
        if state == "not_applicable":
            continue
        health = grouped.setdefault(result.source, ProviderHealth(source=result.source))
        health.last_execution_state = state
        health.retry_count += max(0, int(result.retry_count or 0))
        if result.cached or result.cache_status == "cached":
            health.cache_hit_count += 1
        else:
            health.cache_miss_count += 1
        if result.request_made and not result.cached:
            health.request_count += 1 + max(0, int(result.retry_count or 0))
        if result.latency_ms is not None:
            health.total_latency_ms += max(0.0, float(result.latency_ms))
        if state == "success":
            health.success_count += 1
        elif state == "not_found":
            health.not_found_count += 1
        elif state == "rate_limited":
            health.rate_limit_count += 1
            health.failure_count += 1
        elif state == "timeout":
            health.timeout_count += 1
            health.failure_count += 1
        elif state == "unavailable":
            health.unavailable_count += 1
            health.failure_count += 1
        elif state == "invalid_request":
            health.invalid_request_count += 1
            health.failure_count += 1
        elif state in {"not_applicable", "aborted_due_to_ioc_deadline", "batch_deadline_exceeded"}:
            # Planned but unevaluated combinations are not provider failures
            # and must not contaminate health or coverage.
            pass
        else:
            health.error_count += 1
            health.failure_count += 1
        health.queue_wait_ms += max(0.0, float(result.queue_wait_ms or 0.0))
    for health in grouped.values():
        denominator = health.request_count + health.cache_hit_count
        health.average_latency_ms = round(health.total_latency_ms / denominator, 2) if denominator else 0.0
        health.average_queue_wait_ms = round(health.queue_wait_ms / max(1, health.request_count), 2)
        health.total_latency_ms = round(health.total_latency_ms, 2)
        health.total_latency = health.total_latency_ms
        health.average_latency = health.average_latency_ms
        health.queue_wait = health.queue_wait_ms
    return sorted(grouped.values(), key=lambda item: item.source.lower())


def _legitimate_infrastructure(values: list[str]) -> bool:
    text = " ".join(values).lower()
    return any(term in text for term in (
        "fastly", "github", "cloudflare", "akamai", "microsoft", "google",
        "amazon", "aws", "azure", "cdn", "content delivery",
    ))


def _known_test_artifact(ioc: str, results: list[NormalizedResult]) -> str | None:
    known = _KNOWN_TEST_HASHES.get(ioc.lower())
    if known:
        return known
    text = " ".join(
        [r.malware_family or "" for r in results]
        + [" ".join(r.tags or []) for r in results]
        + [" ".join(r.categories or []) for r in results]
    ).lower()
    if re.search(r"\beicar\b|test[_ -]?artifact|anti[- ]?malware test", text):
        return "EICAR"
    return None


def aggregate_evidence(
    ioc: str,
    ioc_type: str,
    results: list[NormalizedResult],
    enrichment: EnrichmentData | None = None,
) -> IOCAssessment:
    """Build one authoritative, auditable assessment for one IOC."""
    domain = assessment_domain_for(ioc_type, ioc)
    # This is the canonical normalization choke point.  Callers may pass
    # legacy adapter objects, but scoring always consumes normalized evidence.
    results = [normalize_provider_result(result, domain) for result in results]
    chosen: dict[str, NormalizedResult] = {}
    duplicate_count = 0
    for result in results:
        previous = chosen.get(result.source)
        if previous is None:
            chosen[result.source] = result
            continue
        duplicate_count += 1
        prev_status, _ = _health_status(previous)
        current_status, _ = _health_status(result)
        prev_key = (prev_status in {"success", "not_found"}, _semantic_verdict(previous) in {"malicious", "suspicious"})
        current_key = (current_status in {"success", "not_found"}, _semantic_verdict(result) in {"malicious", "suspicious"})
        if current_key > prev_key:
            chosen[result.source] = result

    observations: list[EvidenceObservation] = []
    for result in chosen.values():
        status, health_reason = _health_status(result)
        role = "health" if status in {"rate_limited", "timeout", "error", "invalid_request", "unavailable"} else _role(result)
        semantic_verdict = _semantic_verdict(result)
        detection_count, total_engines = _telemetry(result)
        signal, signal_reason = _signal(result, status, detection_count, total_engines)
        weight = _EVIDENCE_WEIGHTS.get(result.source, 0.50) * _TYPE_WEIGHT.get(ioc_type, 0.80) * _time_decay(result)
        contribution = "excluded" if status not in {"success"} else "neutral"
        if signal > 0:
            contribution = "positive"
        elif status == "success" and semantic_verdict in {"clean", "benign", "whitelisted"} and result.source != "Hashlookup" and role in {"threat", "supporting"}:
            contribution = "negative"
        reason = health_reason or signal_reason
        if status == "not_found":
            reason = "Provider did not find this IOC; absence is not benign evidence."
        elif status == "success" and semantic_verdict in {"unknown", "undetected", "unrated"}:
            reason = "Provider returned insufficient evidence."
        elif role == "context":
            reason = "Infrastructure/context metadata is recorded but cannot increase maliciousness."
        if status == "not_found":
            evidence_class = "non_observation"
        elif status not in {"success"}:
            evidence_class = "provider_status"
        elif contribution == "negative":
            evidence_class = "negative"
        elif role == "context":
            evidence_class = "contextual"
        elif contribution == "positive":
            evidence_class = "supporting" if role == "supporting" else "direct"
        else:
            evidence_class = "contextual"
        observations.append(EvidenceObservation(
            source=result.source,
            status=status,
            execution_state=status,
            verdict=semantic_verdict,
            provider_verdict=result.provider_verdict or result.verdict,
            normalized_verdict=semantic_verdict,
            role=role,
            evidence_class=evidence_class,
            weight=round(weight, 4),
            normalized_signal=round(signal, 4),
            contribution=contribution,
            confidence=_normalise_confidence(result.confidence),
            reason=reason,
            detection_count=detection_count,
            total_engines=total_engines,
            reports_count=result.reports_count,
            first_seen=result.first_seen,
            last_seen=result.last_seen,
            malware_family=result.malware_family,
            tags=list(result.tags or []),
            categories=list(result.categories or []),
            cached=result.cached or result.cache_status == "cached",
            cache_age=result.cache_age,
            observed_at=result.observed_at,
            expires_at=result.expires_at,
            source_timestamp=result.source_timestamp or result.last_seen or result.first_seen,
            provenance=result.provenance_family or _PROVENANCE_GROUPS.get(result.source, result.source),
            assessment_domain=domain,
            evidence_hash=result.evidence_hash,
            source_record_id=result.source_record_id,
            provenance_family=result.provenance_family or _PROVENANCE_GROUPS.get(result.source, result.source),
            source_independence_group=result.source_independence_group,
            duplicate_of=result.duplicate_of,
            metadata={
                "raw_score": result.raw_score,
                "source_link": result.source_link,
                "http_status": result.http_status,
                "retry_count": result.retry_count,
                "retry_after_seconds": result.retry_after_seconds,
                "evidence_items": result.evidence_items,
                "freshness_class": evidence_freshness(result),
            },
        ))

    # Domain-specific objects leave the reputation scorer here.  Provider
    # records remain visible, but their provider vocabulary cannot leak into
    # the IOC reputation verdict.
    if domain == "vulnerability":
        for observation in observations:
            observation.assessment_domain = domain
            observation.evidence_class = "vulnerability"
            observation.contribution = "neutral" if observation.status in {"success", "not_found"} else "excluded"
            observation.normalized_signal = 0.0
        typed = [item for item in chosen.values() if item.execution_state == "success"]
        cvss = next((item.cvss_score for item in typed if item.cvss_score is not None), None)
        epss = next((item.epss_score for item in typed if item.epss_score is not None), None)
        severity = next((item.severity for item in typed if item.severity), None)
        if cvss is not None:
            severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        severity = (severity or "informational").lower()
        evaluated = len([o for o in observations if o.status in {"success", "not_found"}])
        applicable = len([o for o in observations if o.status != "not_applicable"])
        coverage = evaluated / applicable if applicable else 0.0
        risk = max(min((cvss or 0.0) / 10.0, 1.0), min(max(epss or 0.0, 0.0), 1.0))
        records = []
        for item in typed:
            records.append({
                "source": item.source, "vulnerability_status": item.vulnerability_status,
                "severity": item.severity or severity, "cvss_score": item.cvss_score,
                "cvss_vector": item.cvss_vector, "epss_score": item.epss_score,
                "cwe": item.cwe, "affected_products": item.affected_products,
                "published_at": item.published_at, "modified_at": item.modified_at,
                "exploit_status": item.exploit_status, "references": item.references,
                "source_record_id": item.source_record_id,
            })
        reason = f"Vulnerability assessment: {severity} severity"
        if cvss is not None:
            reason += f" (CVSS {cvss:g})"
        if epss is not None:
            reason += f", EPSS {epss:.3f}"
        if any(item.exploit_status == "known_exploited" or "cisa_kev" in item.tags for item in typed):
            reason += "; known exploitation context is present"
        if not typed:
            reason = "Vulnerability metadata is unavailable; no reputation verdict was generated."
        review_reasons = []
        if severity in {"critical", "high"}:
            review_reasons.append(f"{severity.title()} vulnerability requires remediation review")
        if applicable and coverage < 0.5:
            review_reasons.append("Vulnerability provider coverage is incomplete")
        return IOCAssessment(
            ioc=ioc, normalized_ioc=ioc, ioc_type=ioc_type, assessment_domain=domain,
            classification=severity, final_verdict=severity, risk_score=round(risk, 4),
            normalized_score=round(risk * 100.0, 1), confidence_score=round(min(1.0, coverage + (0.2 if typed else 0.0)), 4),
            confidence="high" if len(typed) >= 2 or (typed and coverage >= 0.5) else "medium" if typed else "low",
            evidence_strength=1.0 if typed else 0.0, coverage=round(coverage, 4),
            assessment_status="complete" if applicable and coverage >= 1 else "partial" if applicable else "not_applicable",
            needs_review=bool(review_reasons), review_reasons=review_reasons, freshness="fresh" if typed else "unavailable",
            evidence_counts={"vulnerability": len(typed), "provider_status": len([o for o in observations if o.status not in {"success", "not_found", "not_applicable"}])},
            evidence_summary={"assessment_domain": domain, "severity": severity, "cvss_score": cvss, "epss_score": epss,
                              "expected_providers": applicable, "evaluated_providers": evaluated,
                              "coverage": round(coverage, 4), "threat_evidence_excluded": True},
            provider_breakdown=observations, provider_health=_provider_health(list(chosen.values())),
            vulnerabilities=records, timestamps={"analyzed_at": datetime.now(timezone.utc).isoformat()},
            provider_summary=[{"source": o.source, "execution_state": o.execution_state} for o in observations],
            provider_health_summary=[item.model_dump(mode="json") for item in _provider_health(list(chosen.values()))],
            reason=reason, analyst_review_recommended=bool(review_reasons), analyzed_at=datetime.now(timezone.utc),
        )

    if domain == "attack_technique":
        metadata = (enrichment.extra.get("mitre_attack", {}) if enrichment else {}) or {}
        found = bool(metadata and (metadata.get("title") or metadata.get("name") or metadata.get("description")))
        technique_id = ioc.upper()
        known = {
            "T1059.001": {"name": "PowerShell", "parent": "T1059", "tactics": ["Execution"], "platforms": ["Windows"]},
            "T1105": {"name": "Ingress Tool Transfer", "parent": None, "tactics": ["Command and Control"], "platforms": ["Windows", "Linux", "macOS"]},
        }
        technique = {"technique_id": technique_id, **known.get(technique_id, {})}
        technique.update(metadata)
        reason = f"ATT&CK technique {technique_id} metadata"
        if not found and technique_id not in known:
            reason += " unavailable; the identifier itself is not a reputation verdict."
        return IOCAssessment(
            ioc=ioc, normalized_ioc=ioc, ioc_type=ioc_type, assessment_domain=domain,
            classification="technique_metadata" if found or technique_id in known else "technique_metadata_unavailable",
            final_verdict="technique_metadata" if found or technique_id in known else "technique_metadata_unavailable",
            risk_score=0.0, normalized_score=0.0, confidence_score=0.9 if found or technique_id in known else 0.0,
            confidence="high" if found or technique_id in known else "low", evidence_strength=1.0 if found or technique_id in known else 0.0,
            coverage=1.0 if found or technique_id in known else 0.0, assessment_status="complete" if found or technique_id in known else "unavailable",
            freshness="fresh" if found else "unavailable", evidence_counts={"metadata": 1 if found or technique_id in known else 0},
            provider_breakdown=observations, provider_health=_provider_health(list(chosen.values())),
            reason=reason, analyzed_at=datetime.now(timezone.utc),
        )

    if domain == "credential_exposure" or (domain == "identity_reputation" and ioc_type in {"email", "username", "password"}):
        applicable = [o for o in observations if o.status not in {"not_applicable"}]
        evaluated = [o for o in applicable if o.status in {"success", "not_found"}]
        health_failures = [o for o in applicable if o.status not in {"success", "not_found"}]

        breach_observations = []
        for o in observations:
            if o.status == "success":
                tags_str = " ".join(o.tags).lower()
                has_breach_tag = any(t in tags_str for t in ["compromised", "infostealer", "pwned", "breach"])
                is_flagged = o.verdict in {"malicious", "compromised", "breached"} or bool(o.reports_count and o.reports_count > 0)
                if has_breach_tag or is_flagged:
                    breach_observations.append(o)

        context = _context_values(list(chosen.values()), enrichment)
        coverage = len(evaluated) / len(applicable) if applicable else 0.0

        if breach_observations:
            classification = "breached"
            final_verdict = "breached"
            max_infections = max([o.reports_count or 0 for o in breach_observations] + [1])
            risk = min(1.0, 0.70 + (math.log10(max(max_infections, 1)) / 10.0))
            score = round(risk * 100.0, 1)
            confidence = "high" if len(breach_observations) >= 2 or max_infections >= 3 else "medium"
            reason = f"Credential compromise detected: indicator appeared in breach databases or infostealer malware logs ({len(breach_observations)} source{'s' if len(breach_observations) != 1 else ''} flagged exposure)."
            status_val = "complete" if coverage >= 1.0 else "partial"
        elif evaluated and not health_failures:
            classification = "not_breached"
            final_verdict = "not_breached"
            risk = 0.0
            score = 0.0
            confidence = "high" if len(evaluated) >= 2 else "medium"
            reason = "No breach or infostealer exposure observed across evaluated credential intelligence feeds."
            status_val = "complete" if coverage >= 1.0 else "partial"
        elif evaluated:
            classification = "unknown"
            final_verdict = "unknown"
            risk = 0.0
            score = 0.0
            confidence = "low"
            reason = (
                f"{len(health_failures)} credential intelligence source{'s were' if len(health_failures) != 1 else ' was'} "
                "unavailable, so a clean result cannot be confirmed from the sources that did answer."
            )
            status_val = "partial"
        else:
            classification = "unknown"
            final_verdict = "unknown"
            risk = 0.0
            score = 0.0
            confidence = "low"
            reason = "Credential intelligence is unavailable; no providers returned usable data."
            status_val = "partial" if health_failures else "unavailable"

        freshness_values = [evidence_freshness(r) for r in chosen.values() if _health_status(r)[0] in {"success", "not_found"}]
        freshness = "historical" if freshness_values and all(item == "historical" for item in freshness_values) else "cached" if freshness_values and all(item == "cached" for item in freshness_values) else "fresh" if freshness_values else "unavailable"

        return IOCAssessment(
            ioc=ioc, normalized_ioc=ioc, ioc_type=ioc_type, assessment_domain=domain,
            classification=classification, final_verdict=final_verdict, risk_score=round(risk, 4), normalized_score=score,
            confidence_score=round(min(1.0, coverage + (0.2 if breach_observations else 0.0)), 4),
            confidence=confidence, evidence_strength=1.0 if breach_observations or evaluated else 0.0, coverage=round(coverage, 4),
            assessment_status=status_val,
            freshness=freshness,
            evidence_counts={"breach_findings": len(breach_observations), "providers": len(applicable), "contextual": len(context)},
            evidence_summary={
                "assessment_domain": domain,
                "breached": bool(breach_observations),
                "expected_providers": len(applicable),
                "evaluated_providers": len(evaluated),
                "coverage": round(coverage, 4),
                "unavailable_providers": len(health_failures),
            },
            provider_breakdown=observations, provider_health=_provider_health(list(chosen.values())), context=context,
            reason=reason, analyzed_at=datetime.now(timezone.utc),
            needs_review=bool(breach_observations) or bool(health_failures),
            review_reasons=(
                ["Credential was detected in public breach data or infostealer logs; credential reset recommended."]
                if breach_observations
                else ["One or more credential intelligence sources were unavailable; absence of a finding is not confirmation of safety."]
                if health_failures
                else []
            ),
        )

    if domain in {"infrastructure", "identity_reputation", "artifact_metadata"}:
        applicable = [o for o in observations if o.status not in {"not_applicable"}]
        evaluated = [o for o in applicable if o.status in {"success", "not_found"}]
        context = _context_values(list(chosen.values()), enrichment)
        base_action = route_assessment_domain(ioc_type, ioc).recommended_action

        # BUG-FIX (FC-A): these domains are context-first, but an explicit
        # positive provider verdict (e.g. a provider flagging an ASN, filename,
        # MAC, or other artifact as malicious/suspicious) must not be silently
        # discarded. Read the already-normalized threat/supporting observations
        # and escalate using the same corroboration ladder as ioc_reputation.
        # With no positive signal the verdict stays context_only exactly as
        # before. Only real provider verdicts escalate -- nothing is fabricated,
        # and clean/not-found results never create a benign verdict here.
        positive = [o for o in observations if o.role in {"threat", "supporting"} and o.contribution == "positive"]
        provenance_positive: dict[str, EvidenceObservation] = {}
        for observation in positive:
            key = observation.source_independence_group or observation.provenance_family or observation.provenance or observation.source
            prior = provenance_positive.get(key)
            if prior is None or observation.normalized_signal * observation.weight > prior.normalized_signal * prior.weight:
                provenance_positive[key] = observation
        corroboration = len(provenance_positive)
        positive_strength = sum(o.normalized_signal * o.weight for o in positive)
        max_signal = max((o.normalized_signal for o in positive), default=0.0)
        strong_positive = [o for o in positive if o.normalized_signal >= 0.72]
        strongest = sorted(positive, key=lambda o: o.normalized_signal * o.weight, reverse=True)[:3]

        review_reasons: list[str] = []
        analyst_review = False
        if corroboration >= 2 and len(strong_positive) >= 1 and positive_strength >= 1.10:
            classification = final_verdict = "malicious"
            confidence = "high" if (len(strong_positive) >= 2 or positive_strength >= 1.60) else "medium"
            reason = f"Multiple independent providers report this {ioc_type} as malicious. {base_action}"
            review_reasons.append("High-risk verdict on a context-first domain; confirm the provider evidence.")
        elif corroboration == 1 and len(strong_positive) == 1 and max_signal >= 0.90:
            classification = final_verdict = "malicious"
            confidence = "medium"
            reason = f"One exceptionally strong provider record reports this {ioc_type} as malicious; independent corroboration is limited. {base_action}"
            analyst_review = True
            review_reasons.append("Malicious verdict relies on a single provider record.")
        elif positive:
            classification = final_verdict = "suspicious"
            confidence = "medium" if positive_strength >= 0.45 else "low"
            reason = f"A provider supplied positive threat evidence for this {ioc_type}; this is not conclusive for malicious. {base_action}"
            analyst_review = True
            review_reasons.append("Positive provider evidence on a context-first domain requires analyst confirmation.")
        else:
            classification = final_verdict = "context_only"
            confidence = "medium" if evaluated else "low"
            reason = base_action
            if not applicable:
                reason = f"Context-only indicator ({ioc_type}); no configured provider supports this assessment domain. {reason}"

        score = (0.55 * max_signal + 0.45 * min(positive_strength / 1.20, 1.0)) if positive else 0.0
        normalized_score = round(min(1.0, score) * 100, 1)
        evidence_strength = min(1.0, max_signal * 0.65 + min(positive_strength / 1.2, 1.0) * 0.35) if positive else 0.0
        return IOCAssessment(
            ioc=ioc, normalized_ioc=ioc, ioc_type=ioc_type, assessment_domain=domain,
            classification=classification, final_verdict=final_verdict,
            risk_score=round(normalized_score / 100.0, 4), normalized_score=normalized_score,
            confidence_score=round(len(evaluated) / len(applicable), 4) if applicable else 0.0,
            confidence=confidence, evidence_strength=round(evidence_strength, 4), coverage=round(len(evaluated) / len(applicable), 4) if applicable else 0.0,
            assessment_status="complete" if applicable and len(evaluated) == len(applicable) else "partial" if applicable else "not_applicable",
            freshness="fresh" if evaluated else "unavailable", evidence_counts={"contextual": len(context), "providers": len(applicable), "direct_positive": len(positive)},
            evidence_summary={"assessment_domain": domain, "context_only": final_verdict == "context_only", "expected_providers": len(applicable), "evaluated_providers": len(evaluated), "independent_corroborating_groups": corroboration, "positive_strength": round(positive_strength, 4)},
            provider_breakdown=observations, provider_health=_provider_health(list(chosen.values())), context=context,
            malicious_sources=[o.source for o in positive if o.verdict == "malicious"],
            suspicious_sources=[o.source for o in positive if o.verdict == "suspicious"],
            strongest_evidence=strongest,
            needs_review=bool(positive), review_reasons=review_reasons, analyst_review_recommended=analyst_review,
            reason=reason, analyzed_at=datetime.now(timezone.utc),
        )

    if domain == "security_test_artifact":
        artifact = _known_test_artifact(ioc, list(chosen.values()))
        artifact_observations = []
        for observation in observations:
            if observation.status == "success":
                artifact_observations.append(observation.model_copy(update={
                    "evidence_class": "test_artifact",
                    "contribution": "neutral",
                    "normalized_signal": 0.0,
                    "reason": "Provider detection is expected for this intentional security test artifact and is not live-malware evidence.",
                }))
            else:
                artifact_observations.append(observation)
        applicable = [o for o in observations if o.status != "not_applicable"]
        evaluated = [o for o in applicable if o.status in {"success", "not_found"}]
        artifact_success = [o for o in artifact_observations if o.status == "success"]
        freshness_values = [evidence_freshness(r) for r in chosen.values() if _health_status(r)[0] in {"success", "not_found"}]
        freshness = "historical" if freshness_values and all(item == "historical" for item in freshness_values) else "cached" if freshness_values and all(item == "cached" for item in freshness_values) else "fresh" if freshness_values else "unavailable"
        return IOCAssessment(
            ioc=ioc, normalized_ioc=ioc, ioc_type=ioc_type, assessment_domain=domain,
            classification="known_security_test_artifact", final_verdict="malicious_test_artifact",
            risk_score=0.0, normalized_score=0.0,
            confidence_score=1.0 if artifact else 0.0,
            confidence="high" if artifact else "low", evidence_strength=1.0 if artifact_success else 0.0,
            coverage=round(len(evaluated) / len(applicable), 4) if applicable else 0.0,
            assessment_status="complete" if applicable and len(evaluated) == len(applicable) else "partial" if applicable else "not_applicable",
            freshness=freshness,
            evidence_counts={
                "test_artifact": len(artifact_success),
                "provider_status": len([o for o in observations if o.status not in {"success", "not_found", "not_applicable"}]),
            },
            evidence_summary={
                "assessment_domain": domain,
                "expected_providers": len(applicable),
                "evaluated_providers": len(evaluated),
                "coverage": round(len(evaluated) / len(applicable), 4) if applicable else 0.0,
                "threat_evidence_excluded": True,
            },
            provider_breakdown=artifact_observations,
            provider_health=_provider_health(list(chosen.values())),
            strongest_evidence=artifact_success[:3],
            context=_context_values(list(chosen.values()), enrichment),
            reason="This is the EICAR security test artifact. Antivirus detections are intentional test behavior and must not be interpreted as evidence of live malware.",
            analyst_review_recommended=False,
            provider_summary=[{"source": o.source, "execution_state": o.execution_state, "evidence_class": o.evidence_class} for o in artifact_observations],
            provider_health_summary=[item.model_dump(mode="json") for item in _provider_health(list(chosen.values()))],
            provenance=[{"source": o.source, "provenance_family": o.provenance_family, "source_record_id": o.source_record_id, "evidence_hash": o.evidence_hash} for o in artifact_observations],
            analyzed_at=datetime.now(timezone.utc),
        )

    if ioc in WELL_KNOWN_PUBLIC_RESOLVERS and ioc_type in {"ipv4", "ipv6"}:
        primary_threats = [o for o in observations if o.source in {"VirusTotal", "AbuseIPDB", "ThreatFox", "MalwareBazaar"} and o.contribution == "positive"]
        if not primary_threats:
            # Dampen infostealer client DNS noise for well-known public resolvers
            for i, o in enumerate(observations):
                if o.source in {"Hudson Rock", "LeakCheck.io"} and o.contribution == "positive":
                    observations[i] = o.model_copy(update={
                        "contribution": "neutral",
                        "normalized_signal": 0.0,
                        "role": "context",
                        "reason": f"Well-known public DNS resolver ({ioc}); infostealer client log telemetry is dampened as expected ambient DNS traffic.",
                    })

    threat_obs = [o for o in observations if o.role in {"threat", "supporting"}]
    positive = [o for o in threat_obs if o.contribution == "positive"]
    # ``harmless``, ``undetected``, and ``whitelisted`` are deliberately not
    # collapsed into clean evidence.  Only an explicit meaningful clean or
    # benign classification can support a benign final verdict.
    clean = [o for o in threat_obs if o.status == "success" and o.verdict in {"clean", "benign", "whitelisted"} and o.source != "Hashlookup"]
    context = _context_values(list(chosen.values()), enrichment)
    has_legitimate_context = _legitimate_infrastructure(context)
    positive_strength = sum(o.normalized_signal * o.weight for o in positive)
    clean_strength = sum(o.weight for o in clean)
    max_signal = max((o.normalized_signal for o in positive), default=0.0)
    independent_positive = {o.provenance or o.source for o in positive}
    strong_positive = [o for o in positive if o.normalized_signal >= 0.72]
    artifact = _known_test_artifact(ioc, list(chosen.values()))

    expected_providers = len([o for o in observations if o.status != "not_applicable"])
    evaluated_providers = len([o for o in observations if o.status in {"success", "not_found"}])
    coverage = evaluated_providers / expected_providers if expected_providers else 0.0
    evidence_strength = min(1.0, max_signal * 0.65 + min(positive_strength / 1.2, 1.0) * 0.35)
    provenance_positive: dict[str, EvidenceObservation] = {}
    for observation in positive:
        key = observation.source_independence_group or observation.provenance_family or observation.provenance or observation.source
        prior = provenance_positive.get(key)
        if prior is None or observation.normalized_signal * observation.weight > prior.normalized_signal * prior.weight:
            provenance_positive[key] = observation
    corroboration = len(provenance_positive)

    # This is a new normalized evidence score, not a provider-score average.
    score = 0.0
    if positive:
        score = 0.55 * max_signal + 0.45 * min(positive_strength / 1.20, 1.0)
        if has_legitimate_context and corroboration < 2 and max_signal < 0.85:
            score = max(0.0, score - 0.12)
    normalized_score = round(min(1.0, score) * 100, 1)

    if artifact:
        final_verdict = "malicious_test_artifact"
        confidence = "high"
        reason = f"The hash is identified as the {artifact} anti-malware test artifact; this is a known test file, not ordinary live malware."
        analyst_review = False
    elif corroboration >= 2 and len(strong_positive) >= 1 and positive_strength >= 1.10 and clean_strength < positive_strength * 0.85:
        final_verdict = "malicious"
        confidence = "high" if (len(strong_positive) >= 2 or positive_strength >= 1.60) and coverage >= 0.50 else "medium"
        reason = "Multiple independent high-quality threat sources corroborate malicious evidence."
        analyst_review = False
    elif corroboration == 1 and len(strong_positive) == 1 and max_signal >= 0.90 and clean_strength < positive_strength * 0.75 and not (has_legitimate_context and ioc_type in {"ipv4", "ipv6"}):
        final_verdict = "malicious"
        confidence = "high" if coverage >= 0.50 and expected_providers >= 2 else "medium"
        reason = "One exceptionally strong direct threat record supports malicious; independent corroboration is limited."
        analyst_review = False
    elif positive:
        final_verdict = "suspicious"
        confidence = "medium" if positive_strength >= 0.45 and coverage >= 0.40 else "low"
        if has_legitimate_context and ioc_type in {"ipv4", "ipv6"}:
            reason = "Reputation evidence is present, but it conflicts with legitimate infrastructure context; analyst review is recommended."
        elif len(independent_positive) == 1:
            reason = "A single provider supplied meaningful evidence, but there is not enough independent corroboration for malicious."
        else:
            reason = "Several providers supplied meaningful but non-conclusive evidence."
        analyst_review = True
    elif len(clean) >= 2:
        final_verdict = "benign"
        confidence = "high" if len(clean) >= 3 else "medium"
        reason = "Multiple reputation-oriented providers returned found/clean results and no reliable positive evidence was found."
        analyst_review = False
    else:
        final_verdict = "unknown"
        confidence = "low"
        reason = "No reliable positive evidence was found; not-found, unknown, contextual, and provider-health results are not evidence of benignness."
        analyst_review = False

    def by_source(verdict: str) -> list[str]:
        return [o.source for o in observations if o.verdict == verdict and o.status == "success" and o.role in {"threat", "supporting"}]

    strongest = sorted(positive, key=lambda o: o.normalized_signal * o.weight, reverse=True)[:3]
    supporting = [o for o in positive if o not in strongest][:10]
    conflicting = [o.model_copy(update={"evidence_class": "conflicting"}) for o in observations if (
        (o.contribution == "negative" and positive)
        or (o.role == "context" and has_legitimate_context and positive)
    )][:20]
    families = sorted({r.malware_family.strip() for r in chosen.values() if r.malware_family and r.malware_family.strip()})
    mitre = sorted({tag.upper() for r in chosen.values() for tag in (r.mitre_attck or [])})
    dates = [normalized_date for r in chosen.values() for normalized_date in (
        _utc_datetime(r.first_seen), _utc_datetime(r.last_seen)
    ) if normalized_date is not None]
    cache_observations = [o for o in observations if o.status != "not_applicable"]
    cache_values = [o.cached for o in cache_observations if o.status in {"success", "not_found"}]
    if not cache_values or any(o.status not in {"success", "not_found"} for o in cache_observations):
        cache_status = "unavailable" if not cache_values else "mixed"
    elif all(cache_values):
        cache_status = "cached"
    else:
        cache_status = "fresh"
    provider_health = _provider_health(list(chosen.values()))
    health_failures = [o for o in observations if o.status not in {"success", "not_found", "not_applicable"}]
    deadline_aborts = [o for o in observations if o.status == "aborted_due_to_ioc_deadline"]
    no_evidence = not positive and not clean and final_verdict in {"benign", "unknown", "harmless", "undetected", "context_only"}
    insufficient_coverage = coverage < 0.50 or no_evidence
    if insufficient_coverage and final_verdict in {"benign", "unknown"}:
        analyst_review = analyst_review or final_verdict == "benign"
    needs_review = analyst_review or insufficient_coverage or bool(conflicting)
    review_reasons: list[str] = []
    if conflicting:
        review_reasons.append("Positive, negative, or legitimate infrastructure evidence conflicts")
    if final_verdict in {"malicious", "suspicious"} and corroboration < 2:
        review_reasons.append("High-risk assessment relies on limited independent evidence")
    if insufficient_coverage:
        review_reasons.append(
            "No provider returned usable threat evidence; not-found results are absence of data, not proof of safety"
            if no_evidence
            else "Applicable provider coverage is incomplete"
        )
    if deadline_aborts:
        review_reasons.append("One or more providers were aborted at the IOC deadline")
    freshness_values = [evidence_freshness(r) for r in chosen.values() if _health_status(r)[0] in {"success", "not_found"}]
    freshness = "historical" if freshness_values and all(item == "historical" for item in freshness_values) else "cached" if freshness_values and all(item == "cached" for item in freshness_values) else "fresh" if freshness_values else "unavailable"
    if freshness == "historical" and final_verdict in {"malicious", "suspicious"}:
        review_reasons.append("High-risk intelligence is historical")
    if conflicting:
        conflict_sources = ", ".join(item.source for item in conflicting[:4])
        reason += f" Conflicting/contextual evidence from {conflict_sources} is surfaced for analyst review."
    if final_verdict in {"malicious", "suspicious"} and positive:
        supporting_sources = ", ".join(dict.fromkeys(item.source for item in positive))
        reason += f" Supporting threat sources: {supporting_sources}."
    if final_verdict == "benign":
        reason += " This classification is based on explicit negative provider observations; not-found and undetected results were excluded."

    return IOCAssessment(
        ioc=ioc,
        normalized_ioc=ioc,
        ioc_type=ioc_type,
        final_verdict=final_verdict,
        assessment_domain=domain,
        classification=final_verdict,
        confidence=confidence,
        normalized_score=normalized_score,
        risk_score=round(normalized_score / 100.0, 4),
        confidence_score={"high": 0.9, "medium": 0.6, "low": 0.25}.get(confidence, 0.25),
        evidence_strength=round(evidence_strength, 4),
        coverage=round(coverage, 4),
        assessment_status="aborted_due_to_ioc_deadline" if deadline_aborts else "partial" if health_failures or insufficient_coverage else "complete",
        review_reasons=review_reasons,
        freshness=freshness,
        evidence_counts={
            "direct_positive": len([o for o in observations if o.evidence_class == "direct"]),
            "supporting_positive": len([o for o in observations if o.evidence_class == "supporting"]),
            "negative": len([o for o in observations if o.contribution == "negative"]),
            "conflicting": len(conflicting),
            "contextual": len([o for o in observations if o.evidence_class == "contextual"]),
            "non_observation": len([o for o in observations if o.evidence_class == "non_observation"]),
            "provider_status": len([o for o in observations if o.evidence_class == "provider_status"]),
        },
        needs_review=needs_review,
        cache_status=cache_status,
        evidence_summary={
            "providers_received": len(results),
            "providers_aggregated": len(observations),
            "duplicate_provider_results_ignored": duplicate_count,
            "positive_strength": round(positive_strength, 4),
            "clean_strength": round(clean_strength, 4),
            "reputation_evidence_count": len(positive) + len(clean),
            "evidence_strength": round(evidence_strength, 4),
            "independent_corroborating_groups": corroboration,
            "expected_providers": expected_providers,
            "evaluated_providers": evaluated_providers,
            "coverage": round(coverage, 4),
            "provider_health_failures": len(health_failures),
            "context_only_count": len([o for o in observations if o.role == "context"]),
        },
        provider_breakdown=observations,
        provider_health=provider_health,
        malicious_sources=by_source("malicious"),
        suspicious_sources=by_source("suspicious"),
        clean_sources=by_source("clean"),
        unknown_sources=[o.source for o in observations if o.verdict in {"unknown", "undetected", "unrated"} and o.status in {"success", "not_found"}],
        not_found_sources=[o.source for o in observations if o.status == "not_found"],
        rate_limited_sources=[o.source for o in observations if o.status == "rate_limited"],
        unavailable_sources=[o.source for o in observations if o.status == "unavailable"],
        # Keep the broad legacy error list useful to existing clients while
        # exposing precise rate-limited/unavailable lists alongside it.
        error_sources=[o.source for o in observations if o.status in {"rate_limited", "timeout", "error", "invalid_request"}],
        strongest_evidence=strongest,
        supporting_evidence=supporting,
        conflicting_evidence=conflicting,
        negative_evidence=[o for o in observations if o.contribution == "negative"],
        context=context,
        malware_families=families,
        mitre_attck=mitre,
        first_seen=min(dates) if dates else None,
        last_seen=max(dates) if dates else None,
        reason=reason,
        analyst_review_recommended=analyst_review,
        timestamps={
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "oldest_observation": min(dates).isoformat() if dates else None,
            "newest_observation": max(dates).isoformat() if dates else None,
        },
        provider_summary=[{"source": o.source, "execution_state": o.execution_state, "evidence_class": o.evidence_class, "contribution": o.contribution} for o in observations],
        provider_health_summary=[item.model_dump(mode="json") for item in provider_health],
        provenance=[{"source": o.source, "provenance_family": o.provenance_family, "source_record_id": o.source_record_id, "evidence_hash": o.evidence_hash, "duplicate_of": o.duplicate_of} for o in observations],
        analyzed_at=datetime.now(timezone.utc),
    )


def compute_composite(
    results: list[NormalizedResult],
    ioc: str | None = None,
    ioc_type: str | None = None,
    enrichment: EnrichmentData | None = None,
    assessment: IOCAssessment | None = None,
) -> CompositeScore:
    """Return the compatibility summary shape.

    Existing library callers that pass only ``results`` retain the historic
    shape. The running pipeline passes an explicit ``assessment`` and thus
    exposes the new provider-aware scoring through the same response field.
    """
    if assessment is None:
        if ioc is None and ioc_type is None and enrichment is None:
            return _legacy_compute_composite(results)
        first = results[0] if results else None
        assessment = aggregate_evidence(
            ioc or (first.ioc if first else ""),
            ioc_type or (first.ioc_type if first else "unknown"),
            results,
            enrichment,
        )
    breakdown = [SourceWeight(
        name=o.source,
        weight=o.weight,
        verdict=o.verdict,
        score=o.normalized_signal if o.contribution == "positive" else None,
        confidence=o.confidence,
    ) for o in assessment.provider_breakdown if o.status != "error"]
    if assessment.assessment_domain != "ioc_reputation":
        # CompositeScore is a legacy reputation-shaped field. Keep it neutral
        # for typed domains so CVSS/EPSS, ATT&CK metadata, and artifact context
        # can never be mistaken for an IOC reputation score.
        return CompositeScore(
            score=0.0,
            verdict="unknown",
            confidence=assessment.confidence,
            sources_contributing=0,
            source_breakdown=breakdown,
        )
    # ``clean`` is retained in CompositeScore for old clients. The new
    # authoritative spelling (``benign``/``malicious_test_artifact``) lives in
    # final_assessment.
    legacy_verdict = "clean" if assessment.final_verdict == "benign" else assessment.final_verdict
    positive_weight = sum(o.weight for o in assessment.provider_breakdown if o.contribution == "positive")
    clean_weight = sum(o.weight for o in assessment.provider_breakdown if o.contribution == "negative")
    denominator = positive_weight + clean_weight
    return CompositeScore(
        score=assessment.normalized_score,
        verdict=legacy_verdict,
        confidence=assessment.confidence,
        sources_contributing=len([o for o in assessment.provider_breakdown if o.status == "success" and o.role != "context" and o.contribution in {"positive", "negative"}]),
        source_breakdown=breakdown,
        malicious_sources=len(assessment.malicious_sources),
        suspicious_sources=len(assessment.suspicious_sources),
        clean_sources=len(assessment.clean_sources),
        agreement=round(positive_weight / denominator, 4) if denominator else 0.0,
    )


def _legacy_time_decay(result: NormalizedResult) -> float:
    reference = result.last_seen or result.first_seen
    if reference is None:
        return 1.0
    if reference.tzinfo is not None:
        reference = reference.astimezone().replace(tzinfo=None)
    age_days = (datetime.now() - reference).total_seconds() / 86400.0
    if age_days <= 0:
        return 1.0
    return max(0.2, 1.0 - age_days / 730.0)


def _legacy_found(result: NormalizedResult) -> bool:
    return result.status != "not_found" and result.raw_score is not None


def _legacy_compute_composite(results: list[NormalizedResult]) -> CompositeScore:
    """Compatibility implementation for callers that have no IOC context."""
    scoring_results = [r for r in results if r.source not in INTELLIGENCE_ONLY]
    scoring_results = _legacy_dedupe_by_family(scoring_results)
    cve_override = _legacy_cve_override([r for r in scoring_results if r.source == "CVE"])
    total_weight = 0.0
    weighted_sum = 0.0
    breakdown = []
    for result in scoring_results:
        if result.verdict in ("error", "unknown") or not _legacy_found(result):
            continue
        weight = SOURCE_WEIGHTS.get(result.source, 0.5) * _legacy_time_decay(result)
        score = result.raw_score if result.raw_score is not None else VERDICT_SCORES.get(result.verdict, 0.0)
        weighted_sum += score * weight
        total_weight += weight
        breakdown.append(SourceWeight(
            name=result.source, weight=weight, verdict=result.verdict,
            score=score, confidence=result.confidence,
        ))

    if total_weight == 0:
        return CompositeScore(score=0.0, verdict="unknown", confidence="low", source_breakdown=breakdown)

    final_score = round(weighted_sum / total_weight, 4)
    malicious_count = sum(1 for r in scoring_results if r.verdict == "malicious" and (r.raw_score or 0.0) >= MALICIOUS_MEDIUM)
    suspicious_count = sum(1 for r in scoring_results if r.verdict == "suspicious" and _legacy_found(r))
    clean_count = sum(1 for r in scoring_results if r.verdict == "clean" and _legacy_found(r))
    total_sources = sum(1 for r in scoring_results if r.verdict not in ("error", "unknown") and _legacy_found(r))
    malicious_weight = sum(SOURCE_WEIGHTS.get(r.source, 0.5) * _legacy_time_decay(r) for r in scoring_results if r.verdict == "malicious")
    clean_weight = sum(SOURCE_WEIGHTS.get(r.source, 0.5) * _legacy_time_decay(r) for r in scoring_results if r.verdict == "clean")
    dissent_ok = malicious_weight > clean_weight
    agreement = round(malicious_weight / total_weight, 4) if total_weight else 0.0
    corroborated = malicious_count >= 2
    high_override = corroborated and malicious_count >= settings.scoring_override_count_high and malicious_weight >= settings.scoring_override_min_weight and dissent_ok
    medium_override = corroborated and malicious_count >= settings.scoring_override_count_medium and malicious_weight >= settings.scoring_override_min_weight / 2 and dissent_ok

    if cve_override:
        verdict, confidence = cve_override
    elif final_score >= MALICIOUS_HIGH or high_override:
        verdict, confidence = "malicious", "high"
    elif final_score >= MALICIOUS_MEDIUM or medium_override:
        verdict, confidence = "malicious", "medium"
    elif final_score >= SUSPICIOUS:
        verdict, confidence = "suspicious", "medium"
    elif any(r.verdict == "malicious" and (r.raw_score or 0) > 0 for r in scoring_results):
        verdict, confidence = "suspicious", "low"
    else:
        verdict = "clean"
        confidence = "high" if total_sources >= MIN_SOURCES_HIGH_CONFIDENCE else "medium"

    return CompositeScore(
        score=round(final_score * 100, 1), verdict=verdict, confidence=confidence,
        sources_contributing=len(breakdown), source_breakdown=breakdown,
        malicious_sources=malicious_count, suspicious_sources=suspicious_count,
        clean_sources=clean_count, agreement=agreement,
    )


def _legacy_dedupe_by_family(results: list[NormalizedResult]) -> list[NormalizedResult]:
    best: dict[str, tuple[float, NormalizedResult]] = {}
    for result in results:
        family = (result.malware_family or "").strip().lower()
        if not family:
            continue
        effective = SOURCE_WEIGHTS.get(result.source, 0.5) * _legacy_time_decay(result)
        if family not in best or effective > best[family][0]:
            best[family] = (effective, result)
    selected = [r for r in results if not (r.malware_family or "").strip()]
    selected.extend(r for _, r in best.values())
    return selected


def _legacy_cve_override(results: list[NormalizedResult]) -> tuple[str, str] | None:
    if not results:
        return None
    for result in results:
        if "cisa_kev" in result.tags:
            return "malicious", "high"
    for result in results:
        if result.verdict == "malicious" and result.confidence == "high":
            return "malicious", "high"
        if result.verdict == "suspicious":
            return "suspicious", "medium"
    return None
