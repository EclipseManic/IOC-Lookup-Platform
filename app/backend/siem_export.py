import json
from datetime import datetime, timezone


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _verdict_severity(verdict: str) -> int:
    return {"malicious": 10, "suspicious": 6, "clean": 1, "unknown": 0}.get(verdict, 0)


def _escape_splunk(val: str) -> str:
    if val is None:
        return ""
    return str(val).replace("=", "\\=").replace('"', '\\"').replace("\n", " ")


def export_splunk(response: dict) -> str:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    score = composite.get("score", 0)
    verdict = composite.get("verdict", "unknown")
    results = response.get("results", [])

    lines = []
    for r in results:
        source = r.get("source", "unknown")
        r_verdict = r.get("verdict", "unknown")
        r_score = r.get("raw_score", 0)
        fields = [
            f"source={_escape_splunk(source)}",
            f"ioc_value={_escape_splunk(ioc_value)}",
            f"ioc_type={_escape_splunk(ioc_type)}",
            f"verdict={_escape_splunk(r_verdict)}",
            f"composite_verdict={_escape_splunk(verdict)}",
            f"raw_score={r_score or ''}",
            f"composite_score={score}",
            f"severity={_verdict_severity(r_verdict)}",
            f"confidence={_escape_splunk(r.get('confidence', ''))}",
            f"malware_family={_escape_splunk(r.get('malware_family', ''))}",
            f"tags={';'.join(r.get('tags', []))}",
            f"mitre_attck={';'.join(r.get('mitre_attck', []))}",
            f"index=ioc_platform",
            f"time={_ts()}",
        ]
        lines.append(" ".join(fields))
    return "\n".join(lines)


def export_ecs(response: dict) -> str:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    score = composite.get("score", 0)
    verdict = composite.get("verdict", "unknown")
    results = response.get("results", [])
    enrichment = response.get("enrichment", {})

    events = []
    base = {
        "@timestamp": _ts(),
        "event": {"kind": "enrichment", "category": ["threat"], "type": ["indicator"]},
        "threat": {"indicator": {"type": ioc_type, "name": ioc_value}},
        "ioc_platform": {"composite_score": score, "composite_verdict": verdict},
    }

    geoip = enrichment.get("geoip", {})
    if geoip:
        base["geo"] = {"country_name": geoip.get("country", "")}
        if geoip.get("city"):
            base["geo"]["city_name"] = geoip["city"]
        if geoip.get("asn"):
            base["as"] = {"number": geoip["asn"]}

    for r in results:
        event = {**base,
            "source": {"address": ioc_value},
            "threat": {
                **base["threat"],
                "indicator": {
                    **base["threat"]["indicator"],
                    "provider": r.get("source", "unknown"),
                },
            },
            "event": {
                **base["event"],
                "severity": _verdict_severity(r.get("verdict", "unknown")),
            },
            "ioc_platform": {
                **base["ioc_platform"],
                "source": r.get("source", ""),
                "source_verdict": r.get("verdict", ""),
                "source_score": r.get("raw_score"),
            },
        }
        if r.get("tags"):
            event["tags"] = [t for t in r["tags"] if t]
        if r.get("malware_family"):
            event["malware"] = {"family": r["malware_family"]}
        events.append(event)

    return "\n".join(json.dumps(e, default=str) for e in events)


def export_leef(response: dict) -> str:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    score = composite.get("score", 0)
    verdict = composite.get("verdict", "unknown")
    results = response.get("results", [])

    lines = []
    for r in results:
        src = r.get("source", "unknown")
        pairs = [
            ("devTime", _ts()),
            ("cat", "IOC Lookup"),
            ("severity", str(_verdict_severity(r.get("verdict", "unknown")))),
            ("iocValue", ioc_value),
            ("iocType", ioc_type),
            ("source", src),
            ("verdict", r.get("verdict", "unknown")),
            ("compositeVerdict", verdict),
            ("compositeScore", str(score)),
            ("rawScore", str(r.get("raw_score", ""))),
            ("confidence", r.get("confidence", "")),
            ("malwareFamily", r.get("malware_family", "")),
        ]
        kv = "\t".join(f"{k}={v}" for k, v in pairs)
        lines.append(f"LEEF:2.0|IOC Platform|ioc-platform|0.2.0|IOC Lookup|{kv}")
    return "\n".join(lines)


SIEM_FORMATS = {"splunk": export_splunk, "ecs": export_ecs, "leef": export_leef}


def export_siem(response: dict, fmt: str = "splunk") -> str:
    exporter = SIEM_FORMATS.get(fmt)
    if not exporter:
        raise ValueError(f"Unsupported SIEM format: {fmt}. Use: {', '.join(SIEM_FORMATS)}")
    return exporter(response)
