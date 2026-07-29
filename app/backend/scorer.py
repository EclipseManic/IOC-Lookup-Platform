from app.backend.adapters.base import CompositeScore, NormalizedResult, SourceWeight

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
    "OpenPhish": 0.5,
    "URLhaus": 0.85,
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


def compute_composite(results: list[NormalizedResult]) -> CompositeScore:
    scoring_results = [r for r in results if _is_scorable(r)]
    cve_results = [r for r in scoring_results if r.source == "CVE"]
    non_cve_results = [r for r in scoring_results if r.source != "CVE"]

    cve_override = _compute_cve_override(cve_results)

    total_weight = 0.0
    weighted_sum = 0.0
    breakdown = []

    for r in non_cve_results:
        if r.verdict in ("error", "unknown") or r.raw_score is None:
            continue
        w = SOURCE_WEIGHTS.get(r.source, 0.5)
        weighted_sum += r.raw_score * w
        total_weight += w
        breakdown.append(
            SourceWeight(name=r.source, weight=w, verdict=r.verdict, score=r.raw_score)
        )

    for r in cve_results:
        w = SOURCE_WEIGHTS.get(r.source, 1.0)
        weighted_sum += r.raw_score * w
        total_weight += w
        breakdown.append(
            SourceWeight(name=r.source, weight=w, verdict=r.verdict, score=r.raw_score)
        )

    if total_weight == 0:
        for r in non_cve_results:
            if r.verdict in ("error", "unknown"):
                continue
            w = SOURCE_WEIGHTS.get(r.source, 0.5)
            s = VERDICT_SCORES.get(r.verdict, 0.0)
            weighted_sum += s * w
            total_weight += w
            breakdown.append(
                SourceWeight(name=r.source, weight=w, verdict=r.verdict, score=s)
            )

    if total_weight == 0:
        return CompositeScore(score=0.0, verdict="unknown", confidence="low", source_breakdown=breakdown)

    final_score = round(weighted_sum / total_weight, 4)

    malicious_count = sum(1 for r in scoring_results if r.verdict == "malicious")
    total_sources = sum(1 for r in scoring_results if r.verdict not in ("error", "unknown"))

    if cve_override:
        verdict, confidence = cve_override
    elif final_score >= 0.7 or malicious_count >= 2:
        verdict = "malicious"
        confidence = "high"
    elif final_score >= 0.4 or malicious_count >= 1:
        verdict = "malicious"
        confidence = "medium"
    elif final_score >= 0.15:
        verdict = "suspicious"
        confidence = "medium"
    else:
        verdict = "clean"
        confidence = total_sources >= 2 and "high" or "medium"

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
