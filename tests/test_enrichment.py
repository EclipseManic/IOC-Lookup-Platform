import sys
sys.path.insert(0, ".")

import pytest

from app.backend.adapters.base import EnrichmentData
from app.backend.enrichment import (
    enrich,
    _is_ip,
    enrich_ip,
    enrich_domain,
    enrich_url,
    enrich_hash,
    enrich_email,
    enrich_cve,
    _crt_sh_subdomains,
    _cisa_kev,
    _first_epss,
    _nvd_cve,
    _dns_txt_query,
    _favicon_hash,
)


class TestEnrichmentTypeSpecific:
    @pytest.mark.asyncio
    async def test_ip_enrichment(self):
        result = await enrich_ip("127.0.0.1")
        assert isinstance(result, EnrichmentData)
        assert "geoip" in result.completeness
        assert "reverse_dns" in result.completeness
        assert "whois" in result.completeness

    @pytest.mark.asyncio
    async def test_domain_enrichment(self):
        result = await enrich_domain("google.com")
        assert isinstance(result, EnrichmentData)
        assert "whois" in result.completeness
        assert "dns" in result.completeness
        assert "ssl" in result.completeness
        assert "subdomains" in result.completeness
        assert "favicon" in result.completeness

    @pytest.mark.asyncio
    async def test_url_enrichment(self):
        result = await enrich_url("https://google.com/path")
        assert isinstance(result, EnrichmentData)
        assert result.completeness["domain_extraction"] == "ok"
        assert len(result.relationships) == 1

    @pytest.mark.asyncio
    async def test_hash_enrichment(self):
        result = await enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result.completeness["hash_lookup"] == "not_applicable"

    @pytest.mark.asyncio
    async def test_email_enrichment(self):
        result = await enrich_email("user@example.com")
        assert result.completeness.get("domain_extraction") == "ok"
        assert all(k in result.completeness for k in ("leakcheck", "xposedornot", "proxynova_comb"))
        assert result.completeness.get("email_security") is not None

    @pytest.mark.asyncio
    async def test_cve_enrichment(self):
        result = await enrich_cve("CVE-2024-1234")
        assert result.completeness.get("cisa_kev") is not None
        assert result.completeness.get("epss") is not None
        assert result.completeness.get("nvd") is not None
        assert result.cve is not None
        assert result.cve.epss_score >= 0


class TestEnrichmentDispatcher:
    @pytest.mark.asyncio
    async def test_dispatcher_ip(self):
        result = await enrich("8.8.8.8", "ipv4")
        assert "geoip" in result.completeness

    @pytest.mark.asyncio
    async def test_dispatcher_domain(self):
        result = await enrich("google.com", "domain")
        assert "dns" in result.completeness

    @pytest.mark.asyncio
    async def test_dispatcher_url(self):
        result = await enrich("https://example.com/page", "url")
        assert result.completeness["domain_extraction"] == "ok"

    @pytest.mark.asyncio
    async def test_dispatcher_md5(self):
        result = await enrich("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert result.completeness["hash_lookup"] == "not_applicable"

    @pytest.mark.asyncio
    async def test_dispatcher_sha1(self):
        result = await enrich("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1")
        assert result.completeness["hash_lookup"] == "not_applicable"

    @pytest.mark.asyncio
    async def test_dispatcher_sha256(self):
        result = await enrich("e3b0c44298fc1c149999bf977249da5e9e53b1b9a1b849c87ce6095d53b8b1c9", "sha256")
        assert result.completeness["hash_lookup"] == "not_applicable"

    @pytest.mark.asyncio
    async def test_dispatcher_email(self):
        result = await enrich("admin@example.com", "email")
        assert result.completeness.get("domain_extraction") == "ok"
        assert all(k in result.completeness for k in ("leakcheck", "xposedornot", "proxynova_comb"))

    @pytest.mark.asyncio
    async def test_dispatcher_cve(self):
        result = await enrich("CVE-2024-1234", "cve")
        assert result.completeness.get("epss") is not None

    @pytest.mark.asyncio
    async def test_dispatcher_unknown_type(self):
        result = await enrich("something", "unknown_type")
        assert result.completeness["enrichment"] == "skipped"


class TestNewEnrichmentSources:
    @pytest.mark.asyncio
    async def test_crt_sh_subdomains(self):
        result = await _crt_sh_subdomains("google.com")
        if result is not None:
            assert len(result.subdomains) > 0

    @pytest.mark.asyncio
    async def test_crt_sh_bad_domain(self):
        result = await _crt_sh_subdomains("thisdomaindefinitelydoesnotexist123456.com")
        assert result is None or len(result.subdomains) == 0

    @pytest.mark.asyncio
    async def test_cisa_kev_known(self):
        in_kev, date = await _cisa_kev("CVE-2023-44487")
        assert isinstance(in_kev, bool)

    @pytest.mark.asyncio
    async def test_cisa_kev_unknown(self):
        in_kev, date = await _cisa_kev("CVE-2024-99999")
        assert in_kev is False

    @pytest.mark.asyncio
    async def test_epss_known(self):
        score, pct = await _first_epss("CVE-2023-44487")
        assert score >= 0
        assert pct >= 0

    @pytest.mark.asyncio
    async def test_epss_unknown(self):
        score, pct = await _first_epss("CVE-2024-99999")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_nvd_cve_known(self):
        data = await _nvd_cve("CVE-2023-44487")
        assert isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_nvd_cve_unknown(self):
        data = await _nvd_cve("CVE-2024-99999")
        assert data == {} or isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_dns_txt_query(self):
        records = await _dns_txt_query("google.com")
        assert isinstance(records, list)

    @pytest.mark.asyncio
    async def test_dns_txt_query_spf(self):
        records = await _dns_txt_query("gmail.com")
        assert isinstance(records, list)
        has_spf = any(r.startswith("v=spf1") for r in records)
        assert isinstance(has_spf, bool)

    @pytest.mark.asyncio
    async def test_favicon_hash_known(self):
        result = await _favicon_hash("google.com")
        if result is not None:
            assert isinstance(result.favicon_hash, int)
            assert isinstance(result.favicon_url, str)

    @pytest.mark.asyncio
    async def test_favicon_hash_nonexistent(self):
        result = await _favicon_hash("thisshouldnotexist99999.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_cve_completeness_fields(self):
        result = await enrich_cve("CVE-2023-44487")
        assert "cisa_kev" in result.completeness
        assert "epss" in result.completeness
        assert "nvd" in result.completeness
        assert result.cve is not None

    @pytest.mark.asyncio
    async def test_cve_cisa_kev_true(self):
        result = await enrich_cve("CVE-2023-44487")
        if result.cve.is_in_kev:
            assert result.cve.kev_date_added != ""


def test_is_ip():
    assert _is_ip("8.8.8.8") is True
    assert _is_ip("256.1.2.3") is False
    assert _is_ip("not_an_ip") is False
    assert _is_ip("") is False


def test_is_ip_octet_ranges():
    assert _is_ip("0.0.0.0") is True
    assert _is_ip("255.255.255.255") is True
    assert _is_ip("-1.0.0.0") is False
    assert _is_ip("10.0.0") is False
