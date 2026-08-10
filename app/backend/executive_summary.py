from app.backend.adapters.base import LookupResponse
from app.backend.thresholds import (
    EPSS_HIGH,
    MALICIOUS_SOURCE_SCORE,
    SUMMARY_CAUTION,
    SUMMARY_NO_THREAT,
    SUMMARY_SIGNIFICANT,
)


def generate_executive_summary(response: LookupResponse) -> str:
    c = response.composite
    score = c.score
    verdict = c.verdict
    confidence = c.confidence

    ss = score
    sentences = []

    ss_label = f"{ss}/100"
    sentences.append(
        f"The indicator {response.normalized} ({response.ioc_type}) received a composite score of {ss_label}, resulting in a verdict of {verdict} with {confidence} confidence."
    )

    malicious = [sw for sw in c.source_breakdown if sw.verdict == "malicious" and sw.score and sw.score >= MALICIOUS_SOURCE_SCORE]
    suspicious = [sw for sw in c.source_breakdown if sw.verdict == "suspicious"]
    clean = [sw for sw in c.source_breakdown if sw.verdict == "clean"]

    factors = []
    if malicious:
        names = [sw.name for sw in malicious[:3]]
        factors.append(f"flagged as malicious by {_join_names(names)}")
    if suspicious and not malicious:
        names = [sw.name for sw in suspicious[:2]]
        factors.append(f"marked suspicious by {_join_names(names)}")
    if clean:
        names = [sw.name for sw in clean[:2]]
        factors.append(f"reported clean by {_join_names(names)}")

    if factors:
        sentences.append("Key contributing sources: " + "; ".join(factors) + ".")

    cve_info = response.enrichment.cve if response.enrichment else None
    if cve_info and cve_info.is_in_kev:
        sentences.append(
            "This CVE is listed in the CISA Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild."
        )
    elif cve_info and cve_info.epss_score and cve_info.epss_score >= EPSS_HIGH:
        sentences.append(
            f"The CVE has a high EPSS exploit probability of {cve_info.epss_score*100:.1f}%, suggesting active exploitation is likely."
        )

    breach_info = response.enrichment.breach if response.enrichment else None
    if breach_info and breach_info.breach_count and breach_info.breach_count > 0:
        sentences.append(
            f"Associated with {breach_info.breach_count} known data {'breaches' if breach_info.breach_count > 1 else 'breach'}, indicating prior compromise exposure."
        )

    if not response.results and response.enrichment and response.enrichment.extra:
        sentences.append(
            "No reputation provider currently covers this IOC type; the result contains contextual enrichment and should not be interpreted as clean."
        )

    if score >= SUMMARY_SIGNIFICANT and verdict == "malicious":
        sentences.append("This indicator presents a significant threat and should be blocked or monitored closely.")
    elif score >= SUMMARY_CAUTION and verdict in ("malicious", "suspicious"):
        sentences.append("This indicator warrants further investigation and caution.")
    elif score < SUMMARY_NO_THREAT and verdict == "clean":
        sentences.append("No threat indicators were identified for this indicator at this time.")

    if len(sentences) > 4:
        sentences = sentences[:4]

    return " ".join(sentences)


def _join_names(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"
