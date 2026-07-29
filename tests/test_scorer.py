import sys
sys.path.insert(0, ".")

from datetime import datetime

from app.backend.adapters.base import NormalizedResult
from app.backend.scorer import compute_composite


def _result(source, verdict, raw_score=None, confidence="low"):
    return NormalizedResult(
        ioc="8.8.8.8", ioc_type="ipv4", source=source,
        verdict=verdict, raw_score=raw_score, confidence=confidence,
    )


def test_all_malicious():
    results = [
        _result("VirusTotal", "malicious", 0.95, "high"),
        _result("AbuseIPDB", "malicious", 0.85, "high"),
        _result("ThreatFox", "malicious", 1.0, "high"),
    ]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.score >= 70
    assert c.confidence == "high"


def test_mixed_verdicts():
    results = [
        _result("VirusTotal", "malicious", 0.9, "high"),
        _result("AbuseIPDB", "suspicious", 0.4, "medium"),
        _result("ThreatFox", "clean", 0.0, "low"),
    ]
    c = compute_composite(results)
    assert c.verdict in ("malicious", "suspicious")


def test_all_clean():
    results = [
        _result("VirusTotal", "clean", 0.0, "low"),
        _result("AbuseIPDB", "clean", 0.0, "low"),
    ]
    c = compute_composite(results)
    assert c.verdict == "clean"
    assert c.score < 15


def test_single_source():
    results = [_result("VirusTotal", "malicious", 0.95, "high")]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.sources_contributing == 1


def test_empty_results():
    c = compute_composite([])
    assert c.verdict == "unknown"
    assert c.score == 0.0


def test_error_results_skipped():
    results = [
        _result("VirusTotal", "error", None),
        _result("AbuseIPDB", "error", None),
    ]
    c = compute_composite(results)
    assert c.verdict == "unknown"
    assert c.score == 0.0


def test_one_error_one_malicious():
    results = [
        _result("VirusTotal", "error", None),
        _result("AbuseIPDB", "malicious", 0.9, "high"),
    ]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.score >= 50


def test_source_breakdown():
    results = [
        _result("VirusTotal", "malicious", 1.0, "high"),
        _result("ThreatFox", "clean", 0.0, "low"),
    ]
    c = compute_composite(results)
    assert len(c.source_breakdown) == 2


def test_confidence_high():
    results = [
        _result("VirusTotal", "malicious", 1.0, "high"),
        _result("AbuseIPDB", "malicious", 0.9, "high"),
        _result("ThreatFox", "malicious", 1.0, "high"),
    ]
    c = compute_composite(results)
    assert c.confidence == "high"


def test_score_range():
    results = [
        _result("VirusTotal", "malicious", 0.5, "medium"),
        _result("AbuseIPDB", "suspicious", 0.3, "medium"),
    ]
    c = compute_composite(results)
    assert 0 <= c.score <= 100


def test_unknown_verdict():
    results = [_result("VirusTotal", "unknown", None)]
    c = compute_composite(results)
    assert c.verdict == "unknown"
