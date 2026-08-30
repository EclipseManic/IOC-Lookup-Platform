from datetime import datetime

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.backend.adapters.emailrep_io import EmailRepIOAdapter


def _make_client(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {}
    client = AsyncMock()
    client.get.return_value = response
    return client


@pytest.mark.asyncio
async def test_emailrep_suspicious_flag_is_malicious():
    client = _make_client(200, {
        "email": "bad@example.com",
        "reputation": "high",
        "suspicious": True,
        "references": 5,
        "details": {
            "blacklisted": True,
            "malicious_activity": True,
            "first_seen": "05/24/2019",
            "last_seen": "07/01/2020",
        },
    })
    adapter = EmailRepIOAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("bad@example.com", "email")
    assert result.verdict == "malicious"
    assert result.raw_score == 0.8
    assert any("emailrep:blacklisted" in t for t in result.tags)
    assert result.last_seen == datetime(2020, 7, 1)


@pytest.mark.asyncio
async def test_emailrep_high_reputation_trusted_is_clean():
    client = _make_client(200, {
        "email": "trusted@example.com",
        "reputation": "high",
        "suspicious": False,
        "details": {},
    })
    adapter = EmailRepIOAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("trusted@example.com", "email")
    assert result.verdict == "clean"
    assert result.raw_score == 0.0


@pytest.mark.asyncio
async def test_emailrep_credentials_leaked_is_suspicious():
    client = _make_client(200, {
        "email": "compromised@example.com",
        "reputation": "high",
        "suspicious": False,
        "details": {"credentials_leaked": True, "data_breach": True},
    })
    adapter = EmailRepIOAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("compromised@example.com", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.35


@pytest.mark.asyncio
async def test_emailrep_low_reputation_is_suspicious():
    client = _make_client(200, {
        "email": "sketchy@example.com",
        "reputation": "low",
        "suspicious": False,
        "details": {},
    })
    adapter = EmailRepIOAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("sketchy@example.com", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.3


@pytest.mark.asyncio
async def test_emailrep_no_reputation_is_unknown():
    client = _make_client(200, {
        "email": "nobody@example.com",
        "reputation": "none",
        "suspicious": False,
        "details": {},
    })
    adapter = EmailRepIOAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("nobody@example.com", "email")
    assert result.verdict == "unknown"
    assert result.status == "not_found"


@pytest.mark.asyncio
async def test_emailrep_unauthorized_is_error():
    adapter = EmailRepIOAdapter()
    adapter.set_client(_make_client(401))
    result = await adapter.lookup("x@example.com", "email")
    assert result.verdict == "error"
    assert "unauthorized" in result.tags


@pytest.mark.asyncio
async def test_emailrep_rate_limited():
    adapter = EmailRepIOAdapter()
    adapter.set_client(_make_client(429))
    result = await adapter.lookup("x@example.com", "email")
    assert result.verdict == "unknown"
    assert "rate_limited" in result.tags


@pytest.mark.asyncio
async def test_emailrep_not_found():
    adapter = EmailRepIOAdapter()
    adapter.set_client(_make_client(404))
    result = await adapter.lookup("nobody@example.com", "email")
    assert result.verdict == "unknown"
    assert result.status == "not_found"
    assert result.raw_score == 0.0


@pytest.mark.asyncio
async def test_emailrep_http_error():
    adapter = EmailRepIOAdapter()
    adapter.set_client(_make_client(500))
    result = await adapter.lookup("x@example.com", "email")
    assert result.verdict == "error"
    assert "http_500" in result.tags


@pytest.mark.asyncio
async def test_emailrep_empty_payload_is_unknown():
    adapter = EmailRepIOAdapter()
    adapter.set_client(_make_client(200))
    result = await adapter.lookup("x@example.com", "email")
    assert result.verdict == "unknown"