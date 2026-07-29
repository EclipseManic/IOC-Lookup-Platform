import uuid
from datetime import datetime, timezone

_MISP_ATTR_TYPE_MAP = {
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email-dst",
    "cve": "vulnerability",
}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _misp_id(prefix: str = "") -> str:
    return f"{prefix or 'MISP'}--{uuid.uuid4()}"


def _tag_from_verdict(verdict: str) -> str:
    m = {"malicious": "tlp:red", "suspicious": "tlp:amber", "clean": "tlp:green", "unknown": "tlp:white"}
    return m.get(verdict, "tlp:white")


def build_misp_event(response: dict) -> dict:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    score = composite.get("score", 0)
    verdict = composite.get("verdict", "unknown")
    results = response.get("results", [])
    enrichment = response.get("enrichment", {})

    event_id = _misp_id("Event")
    attributes: list[dict] = []
    objects: list[dict] = []

    attr_id = _misp_id("Attribute")
    attributes.append({
        "id": attr_id,
        "type": _MISP_ATTR_TYPE_MAP.get(ioc_type, "text"),
        "category": "Network activity",
        "value": ioc_value,
        "comment": f"IOC Platform lookup — {verdict} (score: {score})",
        "to_ids": True,
        "timestamp": _ts(),
    })

    for r in results:
        source = r.get("source", "Unknown")
        r_verdict = r.get("verdict", "unknown")
        r_score = r.get("raw_score", "")

        atype = _MISP_ATTR_TYPE_MAP.get(ioc_type, "text")
        category = "External analysis" if atype in ("md5", "sha1", "sha256") else "Network activity"
        if r_verdict == "malicious":
            category = "Payload delivery"

        attributes.append({
            "id": _misp_id("Attribute"),
            "type": atype,
            "category": category,
            "value": ioc_value,
            "comment": f"{source}: {r_verdict}" + (f" (score: {r_score})" if r_score else ""),
            "to_ids": True,
            "timestamp": _ts(),
        })

    geoip = enrichment.get("geoip", {})
    if geoip and geoip.get("country"):
        obj_id = _misp_id("Object")
        geo_obj = {
            "id": obj_id,
            "name": "geo-ip",
            "meta-category": "network",
            "description": f"GeoIP: {geoip.get('country', '')}",
            "attributes": [],
        }
        if geoip.get("country"):
            geo_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "country",
                "value": geoip["country"],
            })
        if geoip.get("city"):
            geo_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "city",
                "value": geoip["city"],
            })
        if geoip.get("asn"):
            geo_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "asn",
                "value": geoip["asn"],
            })
        objects.append(geo_obj)

    whois = enrichment.get("whois", {})
    if whois and whois.get("registrar"):
        obj_id = _misp_id("Object")
        whois_obj = {
            "id": obj_id,
            "name": "whois",
            "meta-category": "network",
            "description": "WHOIS record",
            "attributes": [],
        }
        if whois.get("registrar"):
            whois_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "registrar",
                "value": whois["registrar"],
            })
        if whois.get("creation_date"):
            whois_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "datetime", "object_relation": "creation-date",
                "value": whois["creation_date"],
            })
        if whois.get("org"):
            whois_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "org",
                "value": whois["org"],
            })
        objects.append(whois_obj)

    event = {
        "Event": {
            "id": event_id,
            "uuid": uuid.uuid4().hex,
            "info": f"IOC Platform lookup: {ioc_value} ({ioc_type})",
            "published": False,
            "analysis": 2,
            "timestamp": _ts(),
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "threat_level_id": 1 if verdict == "malicious" else 2 if verdict == "suspicious" else 4,
            "distribution": 3,
            "Tag": [{"name": _tag_from_verdict(verdict)}],
            "Attribute": attributes,
            "Object": objects,
        }
    }
    return event
