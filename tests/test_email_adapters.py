"""Unit tests for AbstractAPI and Hunter.io email intelligence adapters.

All tests use mocked HTTP clients to ensure 0 external network requests
and 0 consumed API credits.
"""

from unittest.mock import AsyncMock, MagicMock
import pytest

from app.backend.adapters.abstract_api import AbstractAPIAdapter
from app.backend.adapters.hunter_io import HunterIOAdapter
from app.backend.provider_capabilities import build_provider_plan


def _make_mock_client(status_code: int = 200, payload: dict = None, headers: dict = None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {}
    response.headers = headers or {}
    client = AsyncMock()
    client.get.return_value = response
    return client


# ---------------------------------------------------------------------------
# AbstractAPI Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_abstractapi_deliverable_clean():
    client = _make_mock_client(200, {
        "email": "user@corporate.com",
        "deliverability": "DELIVERABLE",
        "quality_score": 0.95,
        "is_valid_format": {"value": True},
        "is_free_email": {"value": False},
        "is_disposable_email": {"value": False},
        "is_role_email": {"value": False},
        "is_catchall_email": {"value": False},
        "is_mx_found": {"value": True},
        "is_smtp_valid": {"value": True},
    })
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("user@corporate.com", "email")
    assert result.verdict == "clean"
    assert result.raw_score == 0.0
    assert "deliverability:deliverable" in result.tags
    # The numeric quality score lives in raw_data, not a tag.
    assert result.raw_data["quality_score"] == 0.95
    assert "abstract:disposable_email" not in result.tags


@pytest.mark.asyncio
async def test_abstractapi_disposable_suspicious():
    client = _make_mock_client(200, {
        "email": "tempuser@10minutemail.com",
        "deliverability": "DELIVERABLE",
        "quality_score": 0.30,
        "is_valid_format": {"value": True},
        "is_free_email": {"value": True},
        "is_disposable_email": {"value": True},
        "is_role_email": {"value": False},
        "is_catchall_email": {"value": False},
        "is_mx_found": {"value": True},
        "is_smtp_valid": {"value": True},
    })
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("tempuser@10minutemail.com", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.65
    assert result.confidence == "high"
    assert "abstract:disposable_email" in result.tags


@pytest.mark.asyncio
async def test_abstractapi_undeliverable_or_invalid():
    client = _make_mock_client(200, {
        "email": "bademail@",
        "deliverability": "UNDELIVERABLE",
        "quality_score": 0.0,
        "is_valid_format": {"value": False},
        "is_mx_found": {"value": False},
    })
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("bademail@", "email")
    assert result.verdict == "suspicious"
    assert "abstract:invalid_format" in result.tags
    assert "abstract:no_mx_record" in result.tags


@pytest.mark.asyncio
async def test_abstractapi_rate_limited():
    client = _make_mock_client(429, {"error": "rate limited"}, headers={"Retry-After": "5"})
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "rate_limited"
    assert "rate_limited" in result.tags
    assert result.retry_after_seconds == 5.0


@pytest.mark.asyncio
async def test_abstractapi_missing_key():
    adapter = AbstractAPIAdapter()
    adapter.api_key = ""
    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "unavailable"
    assert "no_api_key_configured" in result.tags


# ---------------------------------------------------------------------------
# Hunter.io Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hunterio_deliverable_clean():
    client = _make_mock_client(200, {
        "data": {
            "status": "valid",
            "result": "deliverable",
            "score": 98,
            "email": "lead@company.com",
            "disposable": False,
            "gibberish": False,
            "webmail": False,
            "sources": [
                {"domain": "company.com", "uri": "https://company.com/team"},
                {"domain": "linkedin.com", "uri": "https://linkedin.com/in/lead"},
            ],
        }
    })
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("lead@company.com", "email")
    assert result.verdict == "clean"
    assert result.raw_score == 0.0
    assert "hunter:result:deliverable" in result.tags
    # Score and source count are structured values, not tags.
    assert result.raw_data["score"] == 98
    assert result.raw_data["sources_found"] == 2


@pytest.mark.asyncio
async def test_hunterio_gibberish_suspicious():
    client = _make_mock_client(200, {
        "data": {
            "status": "invalid",
            "result": "risky",
            "score": 15,
            "email": "xqzk19875938@spambot.xyz",
            "disposable": False,
            "gibberish": True,
            "webmail": False,
            "sources": [],
        }
    })
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("xqzk19875938@spambot.xyz", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.60
    assert result.confidence == "high"
    assert "hunter:gibberish" in result.tags


@pytest.mark.asyncio
async def test_hunterio_disposable_suspicious():
    client = _make_mock_client(200, {
        "data": {
            "status": "valid",
            "result": "deliverable",
            "score": 40,
            "email": "burner@throwawaymail.com",
            "disposable": True,
            "gibberish": False,
            "webmail": True,
            "sources": [],
        }
    })
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("burner@throwawaymail.com", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.65
    assert "hunter:disposable" in result.tags


@pytest.mark.asyncio
async def test_hunterio_rate_limited():
    client = _make_mock_client(429, {"errors": [{"id": "too_many_requests"}]})
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "rate_limited"
    assert "rate_limited" in result.tags


@pytest.mark.asyncio
async def test_hunterio_missing_key():
    adapter = HunterIOAdapter()
    adapter.api_key = ""
    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "unavailable"
    assert "no_api_key_configured" in result.tags


# ---------------------------------------------------------------------------
# Provider Capabilities & Plan Verification
# ---------------------------------------------------------------------------

def test_email_provider_plan_includes_new_adapters():
    from app.backend.pipeline import _init_adapters
    adapters = _init_adapters()
    plan = build_provider_plan(adapters, "email")
    
    email_providers = [p.provider for p in plan if p.applicable]
    assert "AbstractAPI" in email_providers
    assert "Hunter.io" in email_providers

    # Make sure they do not apply to IP or IPv6 lookups
    ip_plan = build_provider_plan(adapters, "ipv4")
    ip_applicable = [p.provider for p in ip_plan if p.applicable]
    assert "AbstractAPI" not in ip_applicable
    assert "Hunter.io" not in ip_applicable
