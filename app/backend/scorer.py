from datetime import datetime

from app.backend.adapters.base import CompositeScore, NormalizedResult, SourceWeight
from app.backend.thresholds import (
    MALICIOUS_MEDIUM,
    MALICIOUS_HIGH,
    MIN_SOURCES_HIGH_CONFIDENCE,
    SUSPICIOUS,
)

from app.backend.config import settings

INTELLIGENCE_ONLY = {"IPinfo", "Shodan", "Tor Exit", "Censys", "Spur.us", "SecurityTrails"}

SOURCE_WEIGHTS = {
    "VirusTotal": 1.0,
    "AbuseIPDB": 0.8,
    "ThreatFox": 0.9,
    "MalwareBazaar": 0.9,
    "urlscan.io": 0.7,
    "CVE": 1.0,
    "Tria.ge": 0.9,
    "Hybrid Analysis": 0.9,
    "AlienVault OTX": 0.7,
    "GreyNoise": 0.4,
    "PhishTank": 0.8,
    "OpenPhish": 0.8,
    "URLhaus": 0.85,
    "StopForumSpam": 0.5,
}

VERDICT_SCORES = {
    "malicious": 1.0,
    "suspicious": 0.6,
    "clean": 0.0,
    "unknown": 0.0,
    "error": 0.0,
}


def _is_scorable(r: NormalizedResult) -> bool:
    return r.source not in INTELLIGENCE_ONLY


def _is_found(r: NormalizedResult) -> bool:
    return r.status != "not_found" and r.raw_score is not None


def _time_decay(r: NormalizedResult) -> float:
    if r.last_seen is None:
        if r.first_seen is None:
            return 1.0
        reference = r.first_seen
    else:
        reference = r.last_seen
    if reference.tzinfo is not None:
        reference = reference.astimezone().replace(tzinfo=None)
    age_days = (datetime.now() - reference).total_seconds() / 86400.0
    if age_days <= 0:
        return 1.0
    return max(0.2, 1.0 - age_days / 730.0)


def _dedupe_by_family(results: list[NormalizedResult]) -> list[NormalizedResult]:
    best_by_family: dict[str, tuple[float, NormalizedResult]] = {}
    for r in results:
        fam = (r.malware_family or "").strip().lower()
        if not fam:
            continue
        effective = SOURCE_WEIGHTS.get(r.source, 0.5) * _time_decay(r)
        prev = best_by_family.get(fam)
        if prev is None or effective > prev[0]:
            best_by_family[fam] = (effective, r)
    deduped = {id(r): r for r in results if not (r.malware_family or "").strip()}
    for _, r in best_by_family.values():
        deduped[id(r)] = r
    return list(deduped.values())


def compute_composite(results: list[NormalizedResult]) -> CompositeScore:
    scoring_results = [r for r in results if _is_scorable(r)]
    scoring_results = _dedupe_by_family(scoring_results)
    cve_results = [r for r in scoring_results if r.source == "CVE"]
    non_cve_results = [r for r in scoring_results if r.source != "CVE"]

    cve_override = _compute_cve_override(cve_results)

    total_weight = 0.0
    weighted_sum = 0.0
    breakdown = []

    for r in non_cve_results:
        if r.verdict in ("error", "unknown") or not _is_found(r):
            continue
        w = SOURCE_WEIGHTS.get(r.source, 0.5) * _time_decay(r)
        weighted_sum += r.raw_score * w
        total_weight += w
        breakdown.append(
            SourceWeight(name=r.source, weight=w, verdict=r.verdict, score=r.raw_score, confidence=r.confidence)
        )

    for r in cve_results:
        w = SOURCE_WEIGHTS.get(r.source, 1.0) * _time_decay(r)
        weighted_sum += r.raw_score * w
        total_weight += w
        breakdown.append(
            SourceWeight(name=r.source, weight=w, verdict=r.verdict, score=r.raw_score, confidence=r.confidence)
        )

    if total_weight == 0:
        for r in non_cve_results:
            if r.verdict in ("error", "unknown") or not _is_found(r):
                continue
            w = SOURCE_WEIGHTS.get(r.source, 0.5) * _time_decay(r)
            s = VERDICT_SCORES.get(r.verdict, 0.0)
            weighted_sum += s * w
            total_weight += w
            breakdown.append(
                SourceWeight(name=r.source, weight=w, verdict=r.verdict, score=s, confidence=r.confidence)
            )

    if total_weight == 0:
        return CompositeScore(score=0.0, verdict="unknown", confidence="low", source_breakdown=breakdown)

    final_score = round(weighted_sum / total_weight, 4)

    # A provider may label any positive hit malicious even when its detection
    # ratio is tiny. Do not let a 1/100 or 1/200 signal force the whole case to
    # malicious; only count meaningful per-source malicious scores here.
    malicious_count = sum(1 for r in scoring_results if r.verdict == "malicious" and (r.raw_score or 0.0) >= MALICIOUS_MEDIUM)
    total_sources = sum(1 for r in scoring_results if r.verdict not in ("error", "unknown") and _is_found(r))

    malicious_weight = sum(
        SOURCE_WEIGHTS.get(r.source, 0.5) * _time_decay(r)
        for r in scoring_results
        if r.verdict == "malicious"
    )

    if cve_override:
        verdict, confidence = cve_override
    elif final_score >= MALICIOUS_HIGH or (
        malicious_count >= settings.scoring_override_count_high
        and malicious_weight >= settings.scoring_override_min_weight
    ):
        verdict = "malicious"
        confidence = "high"
    elif final_score >= MALICIOUS_MEDIUM or (
        malicious_count >= settings.scoring_override_count_medium
        and malicious_weight >= settings.scoring_override_min_weight / 2
    ):
        verdict = "malicious"
        confidence = "medium"
    elif final_score >= SUSPICIOUS:
        verdict = "suspicious"
        confidence = "medium"
    elif any(r.verdict == "malicious" and (r.raw_score or 0.0) > 0 for r in scoring_results):
        verdict = "suspicious"
        confidence = "low"
    else:
        verdict = "clean"
        confidence = total_sources >= MIN_SOURCES_HIGH_CONFIDENCE and "high" or "medium"

    return CompositeScore(
        score=round(final_score * 100, 1),
        verdict=verdict,
        confidence=confidence,
        sources_contributing=len(breakdown),
        source_breakdown=breakdown,
    )


def _compute_cve_override(cve_results: list[NormalizedResult]) -> tuple[str, str] | None:
    if not cve_results:
        return None
    for r in cve_results:
        if "cisa_kev" in r.tags:
            return ("malicious", "high")
    for r in cve_results:
        if r.verdict == "malicious" and r.confidence == "high":
            return ("malicious", "high")
        if r.verdict == "suspicious":
            return ("suspicious", "medium")
    return None
