import httpx
from httpx import AsyncClient, Limits, Timeout

_SHARED_CLIENT: AsyncClient | None = None
_CLIENT_REFCOUNT = 0

DEFAULT_TIMEOUT = Timeout(10.0, connect=5.0, read=15.0)
SIZE_LIMIT = 10 * 1024 * 1024  # 10 MB response limit

ADAPTER_TIMEOUTS: dict[str, Timeout] = {
    "VirusTotal": Timeout(10.0, connect=5.0, read=20.0),
    "AbuseIPDB": Timeout(5.0, connect=3.0, read=10.0),
    "GreyNoise": Timeout(5.0, connect=3.0, read=10.0),
    "Shodan": Timeout(10.0, connect=5.0, read=20.0),
    "AlienVault OTX": Timeout(10.0, connect=5.0, read=15.0),
    "PhishTank": Timeout(5.0, connect=3.0, read=10.0),
    "URLhaus": Timeout(5.0, connect=3.0, read=10.0),
    "SecurityTrails": Timeout(10.0, connect=5.0, read=15.0),
    "MalwareBazaar": Timeout(10.0, connect=5.0, read=15.0),
    "ThreatFox": Timeout(10.0, connect=5.0, read=15.0),
    "Tria.ge": Timeout(10.0, connect=5.0, read=20.0),
    "Hybrid Analysis": Timeout(10.0, connect=5.0, read=20.0),
    "Spur.us": Timeout(10.0, connect=5.0, read=15.0),
    "Tor Exit": Timeout(5.0, connect=3.0, read=10.0),
    "Censys": Timeout(10.0, connect=5.0, read=20.0),
    "IPinfo": Timeout(5.0, connect=3.0, read=10.0),
    "urlscan.io": Timeout(10.0, connect=5.0, read=20.0),
}


def get_client() -> AsyncClient:
    global _SHARED_CLIENT
    if _SHARED_CLIENT is None:
        _SHARED_CLIENT = AsyncClient(
            limits=Limits(max_connections=100, max_keepalive_connections=20),
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
        )
    return _SHARED_CLIENT


def get_timeout(adapter_name: str) -> Timeout:
    return ADAPTER_TIMEOUTS.get(adapter_name, DEFAULT_TIMEOUT)


async def close_client():
    global _SHARED_CLIENT
    if _SHARED_CLIENT:
        await _SHARED_CLIENT.aclose()
        _SHARED_CLIENT = None
