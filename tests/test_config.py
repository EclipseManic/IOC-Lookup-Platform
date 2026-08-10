import sys

sys.path.insert(0, ".")

import pytest

from app.backend.config import Settings

VALID_KEYS = {
    "virustotal_api_key": "a" * 40,
    "abuseipdb_api_key": "a" * 40,
    "urlscanio_api_key": "a" * 40,
    "malwarebazaar_api_key": "a" * 40,
    "threatfox_api_key": "a" * 40,
    "nvd_api_key": "a" * 40,
    "leakcheck_api_key": "a" * 40,
    "triage_api_key": "a" * 40,
    "hybridanalysis_api_key": "a" * 40,
    "greynoise_api_key": "a" * 40,
    "alienvault_otx_api_key": "a" * 40,
    "shodan_api_key": "a" * 40,
    "securitytrails_api_key": "a" * 40,
    "phishtank_api_key": "a" * 40,
    "spur_us_api_key": "a" * 40,
    "censys_api_key": "a" * 40,
    "ipinfo_api_key": "a" * 40,
}

ALIAS_KEYS = {
    "virustotal_api_key": "VT_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "urlscanio_api_key": "URL_SCAN_API_KEY",
    "malwarebazaar_api_key": "MB_AUTH_KEY",
    "threatfox_api_key": "THREATFOX_API_KEY",
    "nvd_api_key": "NVD_API_KEY",
    "leakcheck_api_key": "LEAKCHECK_API_KEY",
    "triage_api_key": "TRIAGE_API_KEY",
    "hybridanalysis_api_key": "HA_API_KEY",
    "greynoise_api_key": "GREYNOISE_API_KEY",
    "alienvault_otx_api_key": "OTX_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "securitytrails_api_key": "SECURITYTRAILS_API_KEY",
    "phishtank_api_key": "PHISHTANK_API_KEY",
    "spur_us_api_key": "SPUR_US_API_KEY",
    "censys_api_key": "CENSYS_API_KEY",
    "ipinfo_api_key": "IPINFO_API_KEY",
}


def _settings(**kwargs):
    base = {"database_url": "sqlite+aiosqlite:///./test.db", "_env_file": None}
    base.update(kwargs)
    return Settings(**base)


def test_defaults_applied():
    s = _settings()
    assert s.port == 8000
    assert s.host == "127.0.0.1"
    assert s.app_name == "IOC Platform"
    assert s.enable_active_port_scan is False
    assert s.enable_url_content_fetch is False
    assert s.webhooks_enabled is False


def test_aliases():
    s = _settings(VT_API_KEY="key12345")
    assert s.virustotal_api_key == "key12345"


def test_empty_database_url_raises():
    with pytest.raises(ValueError, match="DATABASE_URL is required"):
        Settings(database_url="", _env_file=None)


def test_non_loopback_host_requires_api_keys():
    with pytest.raises(ValueError, match="API_KEYS is required"):
        _settings(host="0.0.0.0")


def test_non_loopback_host_with_api_keys_is_allowed():
    assert _settings(host="0.0.0.0", api_keys="test-key-123").host == "0.0.0.0"


def test_source_allowlist_is_case_insensitive():
    s = _settings(enabled_sources="OpenPhish, URLhaus")
    assert s.is_source_enabled("openphish")
    assert s.is_source_enabled("URLhaus")
    assert not s.is_source_enabled("VirusTotal")


def test_fail_fast_with_all_keys_passes():
    aliased = {ALIAS_KEYS[k]: v for k, v in VALID_KEYS.items()}
    s = _settings(fail_fast_missing_keys=True, **aliased)
    assert s.fail_fast_missing_keys is True


def test_fail_fast_missing_key_raises():
    aliased = {ALIAS_KEYS[k]: v for k, v in VALID_KEYS.items()}
    aliased["VT_API_KEY"] = ""
    with pytest.raises(ValueError, match="FAIL_FAST_MISSING_KEYS"):
        _settings(fail_fast_missing_keys=True, **aliased)


def test_alias_choices():
    s = Settings(
        _env_file=None,
        database_url="sqlite+aiosqlite:///./test.db",
        ABUSEIPDB_API_KEY="x" * 10,
    )
    assert s.abuseipdb_api_key == "x" * 10


@pytest.mark.parametrize(
    ("value", "expected"),
    [("release", False), ("production", False), ("dev", True), ("development", True)],
)
def test_debug_accepts_common_environment_modes(value, expected):
    s = _settings(debug=value)
    assert s.debug is expected
