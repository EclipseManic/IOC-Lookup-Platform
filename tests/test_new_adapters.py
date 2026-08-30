import hashlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.backend.adapters.hibp import HIBPAdapter
from app.backend.adapters.hudson_rock import HudsonRockAdapter
from app.backend.pipeline import ADAPTERS
from app.backend.config import settings


@pytest.mark.asyncio
async def test_hibp_adapter_pwned_hash():
    adapter = HIBPAdapter()
    sha1 = hashlib.sha1(b"password").hexdigest()
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f"{sha1[5:].upper()}:12345\nOTHERHASH:1\n"
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup(sha1, "sha1")
    assert result.source == "HIBP Pwned Passwords"
    assert result.verdict == "malicious"
    assert result.confidence == "high"
    assert result.reports_count == 12345
    assert "compromised_credential" in result.tags
    assert "pwned_password" in result.tags


@pytest.mark.asyncio
async def test_hibp_adapter_clean_hash():
    adapter = HIBPAdapter()
    sha1 = "0" * 40
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ABCDE12345:1\n"
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup(sha1, "sha1")
    assert result.source == "HIBP Pwned Passwords"
    assert result.verdict == "clean"
    assert "not_in_pwned_passwords" in result.tags


@pytest.mark.asyncio
async def test_hibp_adapter_invalid_type():
    adapter = HIBPAdapter()
    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert result.verdict == "unknown"
    assert "unsupported_type" in result.tags


@pytest.mark.asyncio
async def test_hudson_rock_no_key():
    adapter = HudsonRockAdapter()
    adapter.api_key = ""
    result = await adapter.lookup("test@example.com", "email")
    assert result.source == "Hudson Rock"
    assert result.verdict == "unknown"
    assert "no_api_key_configured" in result.tags


@pytest.mark.asyncio
async def test_hudson_rock_with_compromise():
    adapter = HudsonRockAdapter()
    adapter.api_key = "valid-test-key-1234"
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": [
            {
                "stealer_family": "RedLine",
                "credentials_count": 5,
            }
        ]
    }
    
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup("victim@example.com", "email")
    assert result.source == "Hudson Rock"
    assert result.verdict == "malicious"
    assert result.confidence == "high"
    assert "infostealer_compromised" in result.tags
    assert "stealer:RedLine" in result.tags


@pytest.mark.asyncio
async def test_hudson_rock_clean():
    adapter = HudsonRockAdapter()
    adapter.api_key = "valid-test-key-1234"
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": []}
    
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup("clean@example.com", "email")
    assert result.source == "Hudson Rock"
    assert result.verdict == "clean"
    assert "no_infostealer_infection" in result.tags


def test_adapters_registered_in_pipeline():
    adapter_names = [a.name for a in ADAPTERS]
    assert "Hudson Rock" in adapter_names
    assert "HIBP Pwned Passwords" in adapter_names
