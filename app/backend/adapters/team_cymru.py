import ipaddress

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter

_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
_IPV4_ZONE = "v4.fullbogons.cymru.com"
_IPV6_ZONE = "v6.fullbogons.cymru.com"


def _reverse_name(ioc_value: str, ioc_type: str) -> str:
    """Build the Team Cymru reversed-octet/nibble DNS query name.

    IPv4: reverse octets, e.g. 192.168.1.1 -> 1.1.168.192.v4.fullbogons.cymru.com
    IPv6: reverse nibbles of the fully-expanded address (no colon compression).
    """
    if ioc_type == "ipv4":
        octets = ioc_value.split(".")
        return ".".join(reversed(octets)) + f".{_IPV4_ZONE}"
    exploded = ipaddress.IPv6Address(ioc_value).exploded.replace(":", "")
    return ".".join(reversed(exploded)) + f".{_IPV6_ZONE}"


class TeamCymruAdapter(SourceAdapter):
    """Team Cymru bogon reference, key-free, queried via Cloudflare DoH TXT.

    A TXT answer means the address is within a bogon prefix (the TXT value is
    the offending prefix). No TXT answer means the address is not a bogon.
    """

    name = "Team Cymru"
    supported_types = ["ipv4", "ipv6"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=30)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        query_name = _reverse_name(ioc_value, ioc_type)
        client = self._get_client()
        resp = await client.get(
            _DOH_ENDPOINT,
            params={"name": query_name, "type": "TXT"},
            headers={"accept": "application/dns-json"},
            timeout=10,
        )

        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"http_{resp.status_code}"],
            )

        data = resp.json()
        doh_status = int(data.get("Status", 0) or 0)
        if doh_status not in (0, 3):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=[f"doh_status:{doh_status}"],
            )

        prefixes = [
            str(a.get("data", "")).strip().strip('"')
            for a in (data.get("Answer") or [])
            if a.get("type") == 16 and a.get("data")
        ]

        if prefixes:
            prefix = prefixes[0]
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="suspicious", raw_score=0.3, confidence="medium",
                tags=["bogon", f"bogon_prefix:{prefix}"],
                source_link="https://www.team-cymru.com/bogon-reference-dns",
            )

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="clean", raw_score=0.0, confidence="low",
            tags=["not_bogon"],
            source_link="https://www.team-cymru.com/bogon-reference-dns",
        )