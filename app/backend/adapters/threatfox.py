from datetime import datetime

import re

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class ThreatFoxAdapter(SourceAdapter):
    name = "ThreatFox"
    supported_types = ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]
    # ThreatFox currently returns HTTP 401 without an Auth-Key.
    public_without_key = False
    rate_limit = RateLimitConfig(requests_per_minute=60)

    def __init__(self):
        self.api_key = settings.threatfox_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        headers = {}
        if is_valid_api_key(self.api_key):
            headers["Auth-Key"] = self.api_key
        resp = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ioc_value},
                headers=headers or None,
                timeout=15,
            )

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"],
            )
        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        data = resp.json()
        qs = data.get("query_status", "")

        if qs == "no_result":
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
            )

        if qs != "ok" or not data.get("data"):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=0.0, status="not_found",
            )

        entries = data["data"]
        if not isinstance(entries, list):
            entries = [entries]

        all_tags = set()
        all_families = set()
        first = None
        last = None
        related = []
        refs = set()
        all_mitre = set()
        categories = set()
        all_reporters = set()
        iocs_count = len(entries)

        max_confidence = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            confidence_level = entry.get("confidence_level", 0)
            if isinstance(confidence_level, (int, float)) and confidence_level > max_confidence:
                max_confidence = confidence_level
            t = entry.get("tags", "")
            if isinstance(t, str):
                for tag in t.split(","):
                    tag = tag.strip()
                    if tag:
                        all_tags.add(tag)
            elif isinstance(t, list):
                all_tags.update(t)

            fam = entry.get("malware", "")
            if fam:
                all_families.add(fam)

            fs = entry.get("first_seen")
            if fs:
                dt = self._parse_dt(fs)
                if dt and (first is None or dt < first):
                    first = dt
            ls = entry.get("last_seen")
            if ls:
                dt = self._parse_dt(ls)
                if dt and (last is None or dt > last):
                    last = dt

            ref = entry.get("reference", "")
            if ref:
                refs.add(ref)

            ioc_val = entry.get("ioc", "")
            if ioc_val and ioc_val.lower() != ioc_value.lower():
                related.append((ioc_val, "same_malware"))

            ml = entry.get("malware_printable", "")
            if ml:
                categories.add(ml)

            reporter = entry.get("reporter", "")
            if reporter:
                all_reporters.add(reporter)
                all_tags.add(f"reported_by: {reporter}")

            ioc_id = entry.get("ioc_id", "")
            if ioc_id:
                all_tags.add(f"threatfox_ioc_id: {ioc_id}")

            aliases = entry.get("malware_alias", "")
            if aliases:
                if isinstance(aliases, str):
                    for a in aliases.split(","):
                        a = a.strip()
                        if a:
                            all_tags.add(f"alias: {a}")
                elif isinstance(aliases, list):
                    for a in aliases:
                        if a:
                            all_tags.add(f"alias: {a}")

            malpedia = entry.get("malware_malpedia", {})
            if malpedia and isinstance(malpedia, dict):
                url = malpedia.get("url", "")
                if url:
                    all_tags.add(f"malpedia: {url}")

        for tag in all_tags:
            if re.match(r"^(TA\d{4}|T\d{4}(\.\d{3})?)$", tag, re.IGNORECASE):
                all_mitre.add(tag.upper())

        confidence_factor = max_confidence / 100.0 if max_confidence > 0 else 1.0
        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict="malicious",
            confidence="high" if iocs_count > 2 else "medium",
            raw_score=confidence_factor,
            tags=sorted(all_tags),
            categories=sorted(categories),
            malware_family=", ".join(sorted(all_families)) or None,
            mitre_attck=sorted(all_mitre),
            first_seen=first,
            last_seen=last,
            related_iocs=related,
            source_link=next(iter(refs), None) or f"https://threatfox.abuse.ch/browse.php?search={ioc_value}",
            reports_count=iocs_count,
        )

    def _parse_dt(self, val: str) -> datetime | None:
        if not val:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
        return None
