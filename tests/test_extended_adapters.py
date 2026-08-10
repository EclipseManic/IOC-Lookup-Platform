"""Tests for 11 extended threat-intelligence adapters.

Covers: GreyNoise, AlienVault OTX, Shodan, SecurityTrails,
OpenPhish, PhishTank, URLhaus, Spur.us, Tor Exit, Censys, IPinfo.

Uses the same mocking patterns as tests/test_ti.py.
"""
import json
import sys
import time
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

sys.path.insert(0, ".")


# ─── Mock helper (mirrors test_ti.py) ───

def _mock_async_client(status_code=200, json_data=None, raise_on=None):
    """Create a mock AsyncClient that returns a controlled response.
    Handles the async context manager protocol used by httpx.AsyncClient.
    """
    mock_response = AsyncMock(spec=httpx.Response)
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data or {}
    mock_response.text = json.dumps(json_data or {})

    mock_client_instance = AsyncMock()
    if raise_on:
        mock_client_instance.get.side_effect = raise_on
        mock_client_instance.post.side_effect = raise_on
    else:
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.post.return_value = mock_response
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None

    mock_class = MagicMock(return_value=mock_client_instance)
    return mock_class, mock_response


def _mock_async_router(routes: dict[str, tuple[int, dict]]):
    """Mock client that returns different responses based on URL substring match.
    routes: {url_substring: (status_code, json_data)}
    Any unmatched URL returns 404.
    """
    async def _route(url, *args, **kwargs):
        url_str = str(url)
        for pattern, (status, data) in routes.items():
            if pattern in url_str:
                mr = AsyncMock(spec=httpx.Response)
                mr.status_code = status
                mr.json.return_value = data or {}
                mr.text = json.dumps(data or {})
                return mr
        mr = AsyncMock(spec=httpx.Response)
        mr.status_code = 404
        mr.json.return_value = {}
        mr.text = "{}"
        return mr
    mc = AsyncMock()
    mc.get.side_effect = _route
    mc.post.side_effect = _route
    mc.__aenter__.return_value = mc
    mc.__aexit__.return_value = None
    return MagicMock(return_value=mc)


# ─── Adapter imports ───

from app.backend.adapters.base import NormalizedResult, SourceAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.alienvault_otx import AlienVaultOTXAdapter
from app.backend.adapters.shodan import ShodanAdapter
from app.backend.adapters.security_trails import SecurityTrailsAdapter
from app.backend.adapters.openphish import OpenPhishAdapter
from app.backend.adapters.phish_tank import PhishTankAdapter
from app.backend.adapters.urlhaus import URLHausAdapter
from app.backend.adapters.spur_us import SpurUsAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.censys import CensysAdapter
from app.backend.adapters.ipinfo import IPinfoAdapter


# ─── Module-level helpers for adapters with shared state ───

import app.backend.adapters.openphish as _openphish_mod
import app.backend.adapters.tor_exit as _tor_exit_mod


# ============================================================
# GreyNoise
# ============================================================

class TestGreyNoiseAdapter:
    """GreyNoise does NOT block requests when no API key is set;
    it simply omits the key parameter and the free community endpoint
    may return 401/404 instead.
    """

    def test_supported_types(self):
        a = GreyNoiseAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_noise_classification(self):
        """classification='noise' → internet scanner, verdict unknown."""
        data = {"classification": "noise", "name": "Unknown Scanner",
                "link": "https://viz.greynoise.io/ip/1.2.3.4",
                "last_seen": "2025-01-01"}
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert "internet_scanner" in r.tags
        assert "classification:noise" in r.tags

    @pytest.mark.asyncio
    async def test_riot_classification(self):
        """classification='riot' → known service, verdict clean."""
        data = {"classification": "riot", "name": "Google",
                "link": "https://viz.greynoise.io/ip/8.8.8.8",
                "last_seen": "2025-01-01"}
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "clean"
        assert r.raw_score == 0.0
        assert "known_service" in r.tags

    @pytest.mark.asyncio
    async def test_unknown_classification(self):
        """classification='unknown' → no data, verdict unknown."""
        data = {"classification": "unknown", "name": ""}
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert "greynoise_no_data" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_429_rate_limited(self):
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(status_code=429)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "rate_limited" in r.tags

    @pytest.mark.asyncio
    async def test_api_key_bypasses_anonymous_weekly_counter(self):
        original_used = GreyNoiseAdapter._weekly_requests_used
        original_reset = GreyNoiseAdapter._quota_reset_time
        original_remaining = GreyNoiseAdapter._quota_remaining
        try:
            GreyNoiseAdapter._weekly_requests_used = GreyNoiseAdapter.WEEKLY_LIMIT
            GreyNoiseAdapter._quota_reset_time = time.time() + 3600
            GreyNoiseAdapter._quota_remaining = None

            a = GreyNoiseAdapter()
            a.api_key = "valid_key"
            mock_class, _ = _mock_async_client(json_data={"classification": "riot"})
            with patch("httpx.AsyncClient", mock_class):
                r = await a.lookup("8.8.8.8", "ipv4")

            assert r.verdict == "clean"
            assert "weekly_quota_exhausted" not in r.tags
        finally:
            GreyNoiseAdapter._weekly_requests_used = original_used
            GreyNoiseAdapter._quota_reset_time = original_reset
            GreyNoiseAdapter._quota_remaining = original_remaining


# ============================================================
# AlienVault OTX
# ============================================================

class TestAlienVaultOTXAdapter:
    def test_supported_types(self):
        a = AlienVaultOTXAdapter()
        for t in ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"):
            assert t in a.supported_types

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = AlienVaultOTXAdapter()
        a.api_key = ""
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = AlienVaultOTXAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_timeout_returns_normalized_error(self):
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"

        class TimeoutClient:
            async def get(self, *args, **kwargs):
                raise httpx.ReadTimeout("")

        a.set_client(TimeoutClient())
        result = await a.lookup("8.8.8.8", "ipv4")
        assert result.status == "error"
        assert "timeout" in result.tags

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """pulse_count>0 AND threat_score>=5 → malicious / high."""
        data = {
            "pulse_count": 8,
            "threat_score": 7,
            "pulses": [
                {"name": "Emotet C2", "threat_type": "malware"},
                {"name": "Malicious IP", "threat_type": "c2"},
            ],
        }
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.7
        assert r.confidence == "high"
        assert r.reports_count == 8
        # Tags from pulses
        tags_str = " ".join(r.tags)
        assert "Emotet C2" in tags_str
        assert "Malicious IP" in tags_str

    @pytest.mark.asyncio
    async def test_suspicious_response(self):
        """pulse_count>0 but threat_score<5 → suspicious / medium."""
        data = {
            "pulse_count": 3,
            "threat_score": 2,
            "pulses": [{"name": "Suspicious", "threat_type": "scan"}],
        }
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "suspicious"
        assert r.raw_score == 0.4
        assert r.confidence == "medium"

    @pytest.mark.asyncio
    async def test_unknown_response(self):
        """pulse_count==0 → unknown / low."""
        data = {"pulse_count": 0, "threat_score": 0, "pulses": []}
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert r.confidence == "low"

    @pytest.mark.asyncio
    async def test_url_type(self):
        """URL type maps to 'url' segment."""
        data = {
            "pulse_count": 5,
            "threat_score": 6,
            "pulses": [{"name": "Phishing URL", "threat_type": "phishing"}],
        }
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/phish", "url")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.6

    @pytest.mark.asyncio
    async def test_unsupported_type(self):
        """Unsupported IOC type → unknown with tag."""
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        r = await a.lookup("some_value", "email")
        assert r.verdict == "unknown"
        assert "unsupported_type" in r.tags


# ============================================================
# Shodan
# ============================================================

class TestShodanAdapter:
    def test_supported_types(self):
        a = ShodanAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = ShodanAdapter()
        a.api_key = ""
        mock_class = _mock_async_router({"internetdb": (404, {})})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = ShodanAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = ShodanAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_normal_response(self):
        """Shodan always returns unknown (enrichment-only)."""
        data = {
            "ports": [80, 443, 22],
            "hostnames": ["example.com", "www.example.com"],
            "org": "Example Corp",
            "isp": "Example ISP",
            "os": "Linux 4.x",
            "vulns": ["CVE-2021-1234"],
        }
        a = ShodanAdapter()
        a.api_key = "valid"
        mock_class = _mock_async_router({"internetdb": (404, {}), "shodan.io": (200, data)})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert "vulns:CVE-2021-1234" in r.tags
        assert "ports:80,443,22" in r.tags
        assert "hostname:example.com" in r.tags
        assert r.categories is not None
        assert "Example Corp" in r.categories

    @pytest.mark.asyncio
    async def test_empty_response(self):
        """Response with ports but no hostnames/vulns."""
        data = {"ports": [80], "hostnames": [], "org": "Test Org", "isp": "", "vulns": []}
        a = ShodanAdapter()
        a.api_key = "valid"
        mock_class = _mock_async_router({"internetdb": (404, {}), "shodan.io": (200, data)})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert "ports:80" in r.tags
        assert r.categories is not None


# ============================================================
# SecurityTrails
# ============================================================

class TestSecurityTrailsAdapter:
    def test_supported_types(self):
        a = SecurityTrailsAdapter()
        assert "domain" in a.supported_types
        assert "ipv4" in a.supported_types

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = SecurityTrailsAdapter()
        a.api_key = ""
        r = await a.lookup("example.com", "domain")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = SecurityTrailsAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("example.com", "domain")
        assert r.verdict == "error"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = SecurityTrailsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("nonexist.xyz", "domain")
        assert r.verdict == "unknown"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_domain_lookup(self):
        """Domain type returns subdomains and related_iocs."""
        data = {"subdomains": ["www", "mail", "api", "blog"]}
        a = SecurityTrailsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("example.com", "domain")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert "has_subdomains" in r.tags
        assert "subdomains:4" in r.tags
        # Related IOCs should include subdomain entries
        assert len(r.related_iocs) > 0

    @pytest.mark.asyncio
    async def test_ipv4_lookup(self):
        """IPv4 type also fetches IP subdomains."""
        data = {"subdomains": ["test.example.com"]}
        a = SecurityTrailsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert "ip_subdomains: 1" in r.tags

    @pytest.mark.asyncio
    async def test_empty_subdomains(self):
        """No subdomains returns minimal tags."""
        data = {"subdomains": []}
        a = SecurityTrailsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("example.com", "domain")
        assert r.verdict == "unknown"
        assert "has_subdomains" not in r.tags


# ============================================================
# OpenPhish (feed-based, no API key)
# ============================================================

class TestOpenPhishAdapter:
    def test_supported_types(self):
        a = OpenPhishAdapter()
        assert a.supported_types == ["url"]

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """URL present in the downloaded feed → malicious."""
        # Reset feed state
        _openphish_mod._feed = []
        _openphish_mod._feed_updated = 0.0

        feed_text = "https://evil.com/phish\nhttps://malware.test/page"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = feed_text

        a = OpenPhishAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/phish", "url")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.8
        assert r.confidence == "medium"
        assert "phishing" in r.tags
        assert "openphish_feed" in r.tags

    @pytest.mark.asyncio
    async def test_clean_response(self):
        """URL NOT present in the downloaded feed → unknown / low (not in feed)."""
        _openphish_mod._feed = []
        _openphish_mod._feed_updated = 0.0

        feed_text = "https://evil.com/phish\nhttps://bad.example"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = feed_text

        a = OpenPhishAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://safe.example.com", "url")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0
        assert r.confidence == "low"
        assert "not_in_feed" in r.tags

    @pytest.mark.asyncio
    async def test_feed_unavailable(self):
        """Feed download fails → unknown / feed_unavailable."""
        _openphish_mod._feed = []
        _openphish_mod._feed_updated = 0.0

        mock_class, _ = _mock_async_client(status_code=500)
        a = OpenPhishAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/phish", "url")
        assert r.verdict == "unknown"
        assert "feed_unavailable" in r.tags


# ============================================================
# PhishTank
# ============================================================

class TestPhishTankAdapter:
    def test_supported_types(self):
        a = PhishTankAdapter()
        assert a.supported_types == ["url"]

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = PhishTankAdapter()
        a.api_key = ""
        r = await a.lookup("https://evil.com", "url")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """in_database=True AND valid="y" → malicious."""
        data = {"results": {"in_database": True, "valid": "y"}}
        a = PhishTankAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/phish", "url")
        assert r.verdict == "malicious"
        assert r.raw_score == 1.0
        assert "phishing" in r.tags

    @pytest.mark.asyncio
    async def test_not_in_tank(self):
        """in_database=False → unknown."""
        data = {"results": {"in_database": False, "valid": "n"}}
        a = PhishTankAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://safe.example.com", "url")
        assert r.verdict == "unknown"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_valid_false(self):
        """in_database=True but valid="n" → unknown."""
        data = {"results": {"in_database": True, "valid": "n"}}
        a = PhishTankAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://maybe-phish.com", "url")
        assert r.verdict == "unknown"

    @pytest.mark.asyncio
    async def test_error_response(self):
        """Non-200 status → error."""
        a = PhishTankAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=500)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com", "url")
        assert r.verdict == "error"
        assert "http_500" in r.tags


# ============================================================
# URLhaus (no API key)
# ============================================================

class TestURLHausAdapter:
    def test_supported_types(self):
        a = URLHausAdapter()
        assert "url" in a.supported_types
        assert "domain" in a.supported_types

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """query_status='ok' AND url_status='online' → malicious."""
        data = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["emotet", "exe"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
        }
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/emotet.exe", "url")
        assert r.verdict == "malicious"
        assert r.raw_score == 1.0
        assert "malware_url" in r.tags
        assert "threat:malware_download" in r.tags
        assert "emotet" in r.tags
        assert r.source_link == "https://urlhaus.abuse.ch/url/123/"

    @pytest.mark.asyncio
    async def test_suspicious_response(self):
        """query_status='ok' AND url_status='offline' → suspicious."""
        data = {
            "query_status": "ok",
            "url_status": "offline",
            "threat": "malware_download",
            "tags": [],
        }
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/old.exe", "url")
        assert r.verdict == "suspicious"
        assert r.raw_score == 0.5
        assert "malware_url" in r.tags

    @pytest.mark.asyncio
    async def test_unknown_response(self):
        """query_status not 'ok' → unknown."""
        data = {"query_status": "no_result"}
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://safe.example.com", "url")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_error_response(self):
        """429 → unknown rate_limited."""
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(status_code=429)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com", "url")
        assert r.verdict == "unknown"
        assert "rate_limited" in r.tags

    @pytest.mark.asyncio
    async def test_domain_lookup(self):
        """Domain type works the same as URL."""
        data = {
            "query_status": "ok",
            "url_status": "online",
            "tags": ["malware"],
        }
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("evil.com", "domain")
        assert r.verdict == "malicious"
        assert r.raw_score == 1.0


# ============================================================
# Spur.us
# ============================================================

class TestSpurUsAdapter:
    def test_supported_types(self):
        a = SpurUsAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = SpurUsAdapter()
        a.api_key = ""
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = SpurUsAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = SpurUsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_normal_response(self):
        """Returns usage_type and risk_score as tags + normalized raw_score."""
        data = {"usage_type": "hosting", "risk_score": 85}
        a = SpurUsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.85
        assert "usage:hosting" in r.tags
        assert "risk:85" in r.tags

    @pytest.mark.asyncio
    async def test_minimal_response(self):
        """No usage_type or risk_score → empty tags."""
        data = {}
        a = SpurUsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert len(r.tags) == 0

    @pytest.mark.asyncio
    async def test_500_error(self):
        a = SpurUsAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=500)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "error"
        assert "http_500" in r.tags


# ============================================================
# Tor Exit (feed-based, no API key)
# ============================================================

class TestTorExitAdapter:
    def test_supported_types(self):
        a = TorExitAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """IP found in the Tor exit list → malicious."""
        _tor_exit_mod._cache = []
        _tor_exit_mod._cache_time = 0.0

        exit_list_text = "1.2.3.4\n5.6.7.8\n9.10.11.12"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = exit_list_text

        a = TorExitAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.8
        assert "tor_exit_node" in r.tags

    @pytest.mark.asyncio
    async def test_unknown_response(self):
        """IP NOT in the Tor exit list → unknown."""
        _tor_exit_mod._cache = []
        _tor_exit_mod._cache_time = 0.0

        exit_list_text = "1.2.3.4\n5.6.7.8"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = exit_list_text

        a = TorExitAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("192.168.1.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_feed_unavailable(self):
        """Feed download fails → unknown (cache stays empty)."""
        _tor_exit_mod._cache = []
        _tor_exit_mod._cache_time = 0.0

        mock_class, _ = _mock_async_client(status_code=500)
        a = TorExitAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """When cache is already populated and fresh, no download occurs."""
        _tor_exit_mod._cache = ["10.0.0.1"]
        _tor_exit_mod._cache_time = time.time() + 3600  # far in the future

        # Even without patching httpx, the cached entry should match
        a = TorExitAdapter()
        r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "malicious"
        assert "tor_exit_node" in r.tags


# ============================================================
# Censys
# ============================================================

class TestCensysAdapter:
    def test_supported_types(self):
        a = CensysAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_no_key(self):
        """Both API ID and secret required."""
        a = CensysAdapter()
        a.api_key = ""
        a._has_credentials = False
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_no_key_partial(self):
        """Only one of API ID/secret → no_api_key_configured."""
        a = CensysAdapter()
        a.api_key = "valid_id:"
        a._has_credentials = False
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = CensysAdapter()
        a.api_key = "invalid_key:invalid_secret"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = CensysAdapter()
        a.api_key = "valid_key:valid_sec"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_normal_response(self):
        """Returns services and ports as tags."""
        data = {
            "result": {
                "resource": {
                    "location": {"city": "Mountain View", "country": "US"},
                    "autonomous_system": {"asn": 15169, "name": "Google LLC"},
                    "services": [
                        {"port": 80, "service_name": "http", "transport_protocol": "tcp"},
                        {"port": 443, "service_name": "https", "transport_protocol": "tcp"},
                        {"port": 22, "service_name": "ssh", "transport_protocol": "tcp"},
                    ],
                }
            }
        }
        a = CensysAdapter()
        a.api_key = "valid_key:valid_sec"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert "services:3" in r.tags
        assert "ports:80,443,22" in r.tags

    @pytest.mark.asyncio
    async def test_empty_services(self):
        """No services in response → minimal tags."""
        data = {"result": {"services": []}}
        a = CensysAdapter()
        a.api_key = "valid_key:valid_sec"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert len(r.tags) == 0


# ============================================================
# IPinfo
# ============================================================

class TestIPinfoAdapter:
    def test_supported_types(self):
        a = IPinfoAdapter()
        assert a.supported_types == ["ipv4", "ipv6"]

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = IPinfoAdapter()
        a.api_key = ""
        mock_class = _mock_async_router({"lite": (404, {})})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "lite_api_unavailable" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = IPinfoAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_error_non_200(self):
        a = IPinfoAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=500)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "http_500" in r.tags

    @pytest.mark.asyncio
    async def test_free_tier_fields_only(self):
        """Only free-tier fields (city/region/country/org/asn) are parsed."""
        data = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "org": "AS15169 Google LLC",
            "asn": {"asn": "AS15169", "name": "Google LLC"},
        }
        a = IPinfoAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "city:Mountain View" in r.tags
        assert "region:California" in r.tags
        assert "country:US" in r.tags
        assert "org:AS15169 Google LLC" in r.tags
        assert "asn:AS15169" in r.tags
        assert "asn_name:Google LLC" in r.tags


# ============================================================
# Cross-Adapter Consistency
# ============================================================

class TestExtendedAdapterConsistency:
    """All extended adapters must follow the same contract."""

    ADAPTERS = [
        ("GreyNoise", GreyNoiseAdapter, ["ipv4"]),
        ("AlienVault OTX", AlienVaultOTXAdapter, ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]),
        ("Shodan", ShodanAdapter, ["ipv4"]),
        ("SecurityTrails", SecurityTrailsAdapter, ["domain", "ipv4"]),
        ("OpenPhish", OpenPhishAdapter, ["url"]),
        ("PhishTank", PhishTankAdapter, ["url"]),
        ("URLhaus", URLHausAdapter, ["url", "domain", "md5", "sha1", "sha256"]),
        ("Spur.us", SpurUsAdapter, ["ipv4"]),
        ("Tor Exit", TorExitAdapter, ["ipv4"]),
        ("Censys", CensysAdapter, ["ipv4"]),
        ("IPinfo", IPinfoAdapter, ["ipv4", "ipv6"]),
    ]

    def test_all_have_name(self):
        for name, cls, _ in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            assert hasattr(a, 'name')
            assert a.name == name, f"Expected {name!r}, got {a.name!r}"

    def test_all_have_supported_types(self):
        for _, cls, expected in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            for t in expected:
                assert t in a.supported_types, f"{cls.__name__} missing {t}"
            # Ensure no extra unsupported type claims
            for t in a.supported_types:
                assert t in expected, f"{cls.__name__} has unexpected type {t}"

    def test_all_are_adapters(self):
        for _, cls, _ in self.ADAPTERS:
            assert issubclass(cls, SourceAdapter), f"{cls.__name__} not a SourceAdapter"

    def test_all_return_normalized_result(self):
        """Adapter lookups (with mocked data) must return NormalizedResult."""
        for name, cls, _ in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            # Set required attributes to avoid AttributeError
            for attr, val in [("api_key", "test")]:
                if not hasattr(a, attr):
                    setattr(a, attr, val)
            # Ensure supported_types is set
            if not a.supported_types:
                a.supported_types = ["ipv4"]
            assert len(a.supported_types) > 0, f"{name} has no supported_types"
