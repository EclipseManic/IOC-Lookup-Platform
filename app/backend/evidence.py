"""Provider-independent semantic evidence normalization.

Adapters preserve raw payloads.  This module turns nested detections and
provider metadata into auditable evidence items before scoring.  A provider's
top-level response is never allowed to bypass this step.
"""

import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.backend.adapters.base import NormalizedResult, normalize_provider_verdict


_MALICIOUS = re.compile(r"\b(malicious|malware|trojan|virus|ransom|stealer|backdoor|botnet|phish|azorult|cobalt\s+strike|agenttesla|eicar)\b", re.I)
_SUSPICIOUS = re.compile(r"\b(suspicious|harmful|risk|unwanted|injection|credential|steal|exfiltrat|exploit)\b", re.I)
_NEGATIVE = re.compile(r"\b(clean|benign|harmless|whitelist(?:ed)?)\b", re.I)


def _jsonish(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    for loader in (json.loads, ast.literal_eval):
        try:
            return loader(text)
        except (ValueError, SyntaxError, TypeError):
            continue
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).lower()


def _value_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} { _value_text(item) }" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_value_text(item) for item in value)
    return str(value or "")


def _iter_vendor_payloads(result: NormalizedResult) -> list[tuple[str, Any]]:
    raw = result.raw_data if isinstance(result.raw_data, dict) else {}
    candidates: list[tuple[str, Any]] = []
    for key in ("vendor_intel", "vendor_intelligence", "vendors", "vendor_detections"):
        payload = raw.get(key)
        if isinstance(payload, dict):
            candidates.extend((str(name), value) for name, value in payload.items())
        elif isinstance(payload, list):
            candidates.extend(("vendor", value) for value in payload)
    for tag in result.tags or []:
        match = re.match(r"vendor[_:](?:([^:]+)):\s*(.*)$", str(tag), re.I | re.S)
        if match:
            candidates.append((match.group(1).strip(), _jsonish(match.group(2))))
    return candidates


def _classify_payload(payload: Any) -> tuple[str, str, float]:
    text = _value_text(payload)
    if _MALICIOUS.search(text):
        return "direct_positive", "Nested vendor intelligence contains a malicious detection or malware classification.", 0.9
    if _SUSPICIOUS.search(text):
        return "behavioral", "Nested vendor intelligence contains suspicious behavior or a threat rule.", 0.65
    if _NEGATIVE.search(text):
        return "weak_negative", "Nested vendor intelligence contains a negative classification.", 0.3
    return "metadata", "Nested vendor metadata was preserved for analyst review.", 0.2


def extract_nested_evidence(result: NormalizedResult) -> list[dict[str, Any]]:
    """Extract structured vendor evidence and deduplicate exact records."""
    seen: dict[str, dict[str, Any]] = {}
    for vendor, payload in _iter_vendor_payloads(result):
        payload = _jsonish(payload)
        evidence_class, reason, confidence = _classify_payload(payload)
        fingerprint = hashlib.sha256(_canonical({"vendor": vendor, "payload": payload}).encode()).hexdigest()
        source_record_id = None
        if isinstance(payload, dict):
            source_record_id = next((str(payload[key]) for key in ("id", "record_id", "link", "url", "sha256_hash") if payload.get(key)), None)
        source_record_id = source_record_id or f"{result.source}:{vendor}:{fingerprint[:16]}"
        item = {
            "evidence_id": f"{result.source}:{fingerprint[:20]}",
            "source": vendor,
            "provider": result.source,
            "provenance_family": f"{result.source}:{vendor}".lower(),
            "source_record_id": source_record_id,
            "record_fingerprint": fingerprint,
            "source_independence_group": vendor.lower(),
            "evidence_hash": hashlib.sha256(_canonical(payload).encode()).hexdigest(),
            "evidence_class": evidence_class,
            "confidence": confidence,
            "contribution_eligible": evidence_class in {"direct_positive", "behavioral", "weak_negative"},
            "reason": reason,
            "observed_at": result.observed_at.isoformat() if result.observed_at else None,
            "source_timestamp": result.source_timestamp.isoformat() if result.source_timestamp else None,
            "details": payload,
        }
        key = item["evidence_hash"]
        if key not in seen:
            seen[key] = item
        else:
            item["duplicate_of"] = seen[key]["evidence_id"]
    return list(seen.values())


def normalize_provider_result(result: NormalizedResult, assessment_domain: str = "ioc_reputation") -> NormalizedResult:
    """Normalize semantics and nested evidence in-place, retaining provenance."""
    result.assessment_domain = assessment_domain
    if assessment_domain == "vulnerability":
        # Some legacy/provider adapters used reputation vocabulary for a CVE
        # record. Preserve that native claim inside raw_data, but prevent it
        # from reaching the canonical provider observation as malicious or
        # suspicious evidence. CVSS/EPSS/severity are assessed separately.
        native_verdict = str(result.provider_verdict or result.verdict or "").strip().lower()
        if native_verdict in {"malicious", "suspicious", "benign", "clean", "harmless", "whitelisted"}:
            raw_payload = result.raw_data if isinstance(result.raw_data, dict) else {}
            raw_payload.setdefault("provider_native_verdict", result.provider_verdict or result.verdict)
            result.raw_data = raw_payload
            result.provider_verdict = "vulnerability_record" if result.execution_state == "success" else result.execution_state
            result.verdict = "unknown"
            result.normalized_verdict = "unknown"
    # Recover HTTP semantics at the shared boundary. A few adapters expose
    # only an ``http_###`` tag and older adapters incorrectly mapped some
    # client errors to not-found.
    if result.http_status is None:
        for tag in result.tags or []:
            match = re.fullmatch(r"http_(\d{3})", str(tag).strip().lower())
            if match:
                result.http_status = int(match.group(1))
                break
    if result.http_status is not None:
        code = int(result.http_status)
        if code == 404:
            result.execution_state = "not_found"
            result.status = "not_found"
        elif code == 429:
            result.execution_state = "rate_limited"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "rate_limited"]))
        elif code in {401, 403}:
            result.execution_state = "unavailable"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "provider_auth_failure"]))
        elif 400 <= code < 500:
            result.execution_state = "invalid_request"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "invalid_request"]))
        elif code >= 500:
            result.execution_state = "error"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "provider_http_error"]))
    result.provenance_family = result.provenance_family or result.source
    result.source_independence_group = result.source_independence_group or result.provenance_family
    result.provider_verdict = result.provider_verdict or result.verdict or "unknown"
    result.normalized_verdict = normalize_provider_verdict(result.normalized_verdict or result.verdict)
    raw = result.raw_data if isinstance(result.raw_data, dict) else {}
    detection_ratio = raw.get("detection_ratio")
    if (result.detection_count is None or result.total_engines is None) and isinstance(detection_ratio, str):
        match = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", detection_ratio)
        if match:
            result.detection_count = int(match.group(1))
            result.total_engines = int(match.group(2))
    if result.detection_count is None:
        for key in ("malicious", "detection_count", "detections"):
            if isinstance(raw.get(key), (int, float)):
                result.detection_count = int(raw[key])
                break
    if result.total_engines is None:
        counts = [raw.get(key) for key in ("malicious", "suspicious", "harmless", "undetected")]
        if all(isinstance(value, (int, float)) for value in counts if value is not None) and any(value is not None for value in counts):
            result.total_engines = sum(int(value or 0) for value in counts)
    result.source_timestamp = result.source_timestamp or result.last_seen or result.first_seen
    if result.record_fingerprint is None:
        result.record_fingerprint = hashlib.sha256(_canonical({"source": result.source, "ioc": result.ioc, "raw": result.raw_data, "tags": result.tags}).encode()).hexdigest()
    items = extract_nested_evidence(result)
    if items:
        result.evidence_items = items
        positive = [item for item in items if item["evidence_class"] == "direct_positive"]
        suspicious = [item for item in items if item["evidence_class"] in {"behavioral", "direct_positive"}]
        if assessment_domain in {"ioc_reputation", "security_test_artifact"} and result.execution_state == "success":
            if positive and result.normalized_verdict in {"unknown", "not_found", "undetected", "unrated"}:
                result.normalized_verdict = "malicious"
                result.verdict = "malicious"
                result.confidence = "high"
            elif suspicious and result.normalized_verdict in {"unknown", "not_found", "undetected", "unrated"}:
                result.normalized_verdict = "suspicious"
                result.verdict = "suspicious"
                result.confidence = "medium"
        families: list[str] = []
        for item in items:
            details = item.get("details")
            if isinstance(details, dict):
                for key in ("family", "malware_family", "threat_name", "signature", "detection"):
                    value = details.get(key)
                    if isinstance(value, str) and value.strip() and value.strip().lower() not in {x.lower() for x in families}:
                        families.append(value.strip())
            text = _value_text(details)
            for match in re.findall(r"(?:family|malware_family|threat_name|signature|detection)\s*['\"]?[:=]\s*['\"]?([A-Za-z][A-Za-z0-9_. -]{2,40})", text, re.I):
                candidate = match.strip(" '\"")
                if candidate and candidate.lower() not in {x.lower() for x in families}:
                    families.append(candidate)
        if families and not result.malware_family:
            result.malware_family = families[0]
        result.tags = list(dict.fromkeys([*(result.tags or []), f"nested_evidence:{len(items)}"]))
    return result


def evidence_freshness(result: NormalizedResult, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    timestamp = result.source_timestamp or result.last_seen or result.first_seen or result.observed_at
    if timestamp is None:
        return "unavailable"
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (now - timestamp.astimezone(timezone.utc)).total_seconds() / 86400)
    if result.stale or age_days > 90:
        return "historical"
    if result.cached:
        return "cached"
    return "fresh"
