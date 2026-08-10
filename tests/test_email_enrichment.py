import sys
sys.path.insert(0, ".")

from unittest.mock import AsyncMock, patch

import pytest
import httpx

from app.backend.adapters.base import BreachInfo, is_valid_api_key
from app.backend.enrichment import (
    _leakcheck_lookup,
    _xposedornot_lookup,
    _proxynova_comb_lookup,
    enrich_email,
)


def _mock_shared_client(get=None, post=None, get_side_effect=None, post_side_effect=None):
    """Build a mock for the shared HTTP client returned by _get_http_client()."""
    client = AsyncMock()
    if get_side_effect is not None:
        client.get = AsyncMock(side_effect=get_side_effect)
    else:
        client.get = AsyncMock(return_value=get)
    if post_side_effect is not None:
        client.post = AsyncMock(side_effect=post_side_effect)
    else:
        client.post = AsyncMock(return_value=post)
    return client


LC_OK = {
    "success": True,
    "found": 3,
    "result": [
        {"source": {"name": "BreachA", "breach_date": "2022-06"}, "fields": ["email", "password"]},
        {"source": {"name": "BreachB", "breach_date": "2023-01"}, "fields": ["email", "name"]},
    ],
}

XON_OK = {
    "breaches": [
        {"name": "BreachA", "breach_date": "2022-06", "exposed_data": ["Emails", "Passwords"]},
        {"name": "BreachC", "breach_date": "2021-05", "exposed_data": ["Emails", "Addresses"]},
    ]
}

PN_OK = {"records": [{"email": "a@b.com", "password": "x"}, {"email": "a@b.com", "password": "y"}]}


class TestLeakCheckLookup:
    @pytest.fixture(autouse=True)
    def _patch_leakcheck_key(self):
        with patch("app.backend.config.settings") as m:
            m.leakcheck_api_key = "real-key-40-chars-minimum-length-required"
            yield

    @pytest.mark.asyncio
    async def test_success(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get=httpx.Response(200, json=LC_OK))):
            result = await _leakcheck_lookup("a@b.com")
        assert result is not None
        assert result.breach_count == 3
        assert "BreachA" in result.breach_names
        assert result.most_recent_breach == "2023-01"
        assert "password" in result.exposed_data_types
        assert result.source == "leakcheck"

    @pytest.mark.asyncio
    async def test_no_key(self):
        with patch("app.backend.config.settings") as m:
            m.leakcheck_api_key = ""
            result = await _leakcheck_lookup("a@b.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_no_breaches(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get=httpx.Response(404))):
            result = await _leakcheck_lookup("a@b.com")
        assert result is not None
        assert result.breach_count == 0
        assert result.breach_names == []
        assert result.most_recent_breach == ""

    @pytest.mark.asyncio
    async def test_rate_limited(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get=httpx.Response(429))):
            result = await _leakcheck_lookup("a@b.com")
        assert result is None


class TestXposedOrNotLookup:
    @pytest.mark.asyncio
    async def test_success(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get=httpx.Response(200, json=XON_OK))):
            result = await _xposedornot_lookup("a@b.com")
        assert result is not None
        assert result.breach_count == 2
        assert "BreachC" in result.breach_names
        assert result.most_recent_breach == "2022-06"
        assert "Passwords" in result.exposed_data_types
        assert result.source == "xposedornot"

    @pytest.mark.asyncio
    async def test_no_breaches(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get=httpx.Response(404))):
            result = await _xposedornot_lookup("a@b.com")
        assert result is not None
        assert result.breach_count == 0

    @pytest.mark.asyncio
    async def test_rate_limited(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get_side_effect=[
            httpx.Response(429),
            httpx.Response(429),
            httpx.Response(429),
        ])):
            result = await _xposedornot_lookup("a@b.com")
        assert result is None


class TestProxyNovaCombLookup:
    @pytest.mark.asyncio
    async def test_success(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(post=httpx.Response(200, json=PN_OK))):
            result = await _proxynova_comb_lookup("a@b.com")
        assert result is not None
        assert result.breach_count == 2
        assert "proxynova_comb_1" in result.breach_names
        assert result.source == "proxynova_comb_unofficial"

    @pytest.mark.asyncio
    async def test_timeout(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(post_side_effect=httpx.TimeoutException("timeout"))):
            result = await _proxynova_comb_lookup("a@b.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_bad_json(self):
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(post=httpx.Response(200, text="not json"))):
            result = await _proxynova_comb_lookup("a@b.com")
        assert result is None


class TestEnrichEmailMerge:
    @pytest.fixture(autouse=True)
    def _patch_leakcheck_key(self):
        with patch("app.backend.config.settings") as m:
            m.leakcheck_api_key = "real-key-40-chars-minimum-length-required"
            yield m

    @pytest.mark.asyncio
    async def test_all_sources_ok(self):
        lc = BreachInfo(
            breach_count=2, breach_names=["BreachA", "BreachB"],
            most_recent_breach="2023-01", exposed_data_types=["email", "password"],
            source="leakcheck",
        )
        xo = BreachInfo(
            breach_count=2, breach_names=["BreachA", "BreachC"],
            most_recent_breach="2022-06", exposed_data_types=["Emails", "Passwords"],
            source="xposedornot",
        )
        pn = BreachInfo(
            breach_count=1, breach_names=["proxynova_comb_1"],
            source="proxynova_comb_unofficial",
        )
        with (
            patch("app.backend.enrichment._leakcheck_lookup", AsyncMock(return_value=lc)),
            patch("app.backend.enrichment._xposedornot_lookup", AsyncMock(return_value=xo)),
            patch("app.backend.enrichment._proxynova_comb_lookup", AsyncMock(return_value=pn)),
        ):
            result = await _enrich_email_direct("a@b.com")
        assert result.breach is not None
        assert result.completeness["leakcheck"] == "ok"
        assert result.completeness["xposedornot"] == "ok"
        assert result.completeness["proxynova_comb"] == "ok"
        assert result.breach.breach_count == 4  # A, B, C + proxynova_comb_1 deduped
        assert result.breach.source == "multiple"
        assert result.breach.most_recent_breach == "2023-01"
        assert "password" in [t.lower() for t in result.breach.exposed_data_types]

    @pytest.mark.asyncio
    async def test_leakcheck_missing_key(self, _patch_leakcheck_key):
        _patch_leakcheck_key.leakcheck_api_key = ""
        xo = BreachInfo(
            breach_count=2, breach_names=["BreachA", "BreachC"],
            most_recent_breach="2022-06", exposed_data_types=["Emails", "Passwords"],
            source="xposedornot",
        )
        pn = BreachInfo(
            breach_count=1, breach_names=["proxynova_comb_1"],
            source="proxynova_comb_unofficial",
        )
        with (
            patch("app.backend.enrichment._xposedornot_lookup", AsyncMock(return_value=xo)),
            patch("app.backend.enrichment._proxynova_comb_lookup", AsyncMock(return_value=pn)),
        ):
            result = await _enrich_email_direct("a@b.com")
        assert result.breach is not None
        assert result.completeness["leakcheck"] == "not_configured"
        assert result.completeness["xposedornot"] == "ok"
        assert result.breach.breach_count == 3  # A, C + proxynova_comb_1
        assert "BreachA" in result.breach.breach_names
        assert "BreachC" in result.breach.breach_names

    @pytest.mark.asyncio
    async def test_all_three_fail(self):
        with (
            patch("app.backend.enrichment._leakcheck_lookup", AsyncMock(return_value=None)),
            patch("app.backend.enrichment._xposedornot_lookup", AsyncMock(return_value=None)),
            patch("app.backend.enrichment._proxynova_comb_lookup", AsyncMock(return_value=None)),
        ):
            result = await _enrich_email_direct("a@b.com")
        assert result.breach is not None
        assert result.breach.breach_count is None
        assert result.breach.source == "none"
        assert result.completeness["leakcheck"] == "not_configured"
        assert result.completeness["xposedornot"] == "error"
        assert result.completeness["proxynova_comb"] == "unavailable"

    @pytest.mark.asyncio
    async def test_breach_info_shape(self):
        br = BreachInfo(
            breach_count=5,
            breach_names=["A", "B"],
            most_recent_breach="2024-01",
            exposed_data_types=["Emails", "Passwords"],
            source="leakcheck",
        )
        assert br.breach_count == 5
        assert br.breach_names == ["A", "B"]
        assert br.most_recent_breach == "2024-01"
        assert br.exposed_data_types == ["Emails", "Passwords"]
        assert br.source == "leakcheck"

    @pytest.mark.asyncio
    async def test_breach_count_none_when_all_fail(self):
        br = BreachInfo(breach_count=None, source="none")
        assert br.breach_count is None
        assert br.source == "none"


async def _enrich_email_direct(email: str):
    from app.backend.enrichment import enrich_email
    return await enrich_email(email)
