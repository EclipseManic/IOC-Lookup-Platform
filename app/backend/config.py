import ipaddress
import os
import re
import sys
from pathlib import Path

from dotenv import dotenv_values
from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.backend.thresholds import (
    MALICIOUS_OVERRIDE_COUNT_HIGH,
    MALICIOUS_OVERRIDE_COUNT_MEDIUM,
    OVERRIDE_MIN_MALICIOUS_WEIGHT,
)

_DEFAULT_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"

_ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REFERENCE_RE = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$")


def _sync_windows_env():
    """Sync fresh user environment variables from Windows Registry into os.environ.
    Ensures newly added/updated API keys in Windows System Settings are picked up immediately.
    """
    if sys.platform != "win32":
        return
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    if isinstance(val, str) and val.strip():
                        os.environ[name] = val.strip()
                    i += 1
                except OSError:
                    break
    except Exception:
        pass


_sync_windows_env()


def _dotenv_map(env_file) -> dict[str, str]:
    """Read raw .env values without touching the process environment."""
    if not env_file:
        return {}
    if isinstance(env_file, (list, tuple)):
        merged: dict[str, str] = {}
        for path in env_file:
            merged.update(dotenv_values(path, interpolate=False) or {})
        return merged
    return dotenv_values(env_file, interpolate=False) or {}


def resolve_credential(alias: str, *, env_file=None, environ: dict | None = None) -> str:
    """Resolve an API key with the system environment first, then the .env file."""
    env = os.environ if environ is None else environ
    dotenv = _dotenv_map(env_file)
    seen: set[str] = set()

    def _resolve(name: str) -> str:
        if name in seen:
            return ""
        seen.add(name)
        system = (env.get(name) or "").strip()
        if system.lower() in ("null", "none", "placeholder", "undefined", "true", "false", "1", "0"):
            system = ""
        if system:
            return system
        raw = (dotenv.get(name) or "").strip()
        if raw.lower() in ("null", "none", "placeholder", "undefined", "true", "false", "1", "0"):
            raw = ""
        if not raw:
            return ""
        m = _REFERENCE_RE.match(raw)
        if m:
            return _resolve(m.group(1) or m.group(2))
        if _ENV_VAR_NAME_RE.match(raw) and (raw in env or raw in dotenv):
            return _resolve(raw)
        return raw

    return _resolve(alias)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent.parent / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = Field(
        "sqlite+aiosqlite:///./data/ioc_platform.db",
        validation_alias=AliasChoices("DATABASE_URL", "database_url"),
    )

    redis_url: str = Field("", alias="REDIS_URL")

    virustotal_api_key: str = Field("", alias="VT_API_KEY")
    vt_rate_per_minute: int = Field(4, alias="VT_RATE_PER_MINUTE")
    abuseipdb_api_key: str = Field("", validation_alias=AliasChoices("ABUSEIPDB_API_KEY", "AbuseDB_API_KEY", "ABUSE_IPDB_API_KEY"))
    urlscanio_api_key: str = Field("", alias="URL_SCAN_API_KEY")
    malwarebazaar_api_key: str = Field("", validation_alias=AliasChoices("MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY"))
    threatfox_api_key: str = Field("", validation_alias=AliasChoices("THREATFOX_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY"))
    urlhaus_api_key: str = Field("", validation_alias=AliasChoices("URLHAUS_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY", "ABUSE_CH_AUTH_KEY", "ABUSE_CH_API_KEY", "ABUSECH_API_KEY"))

    nvd_api_key: str = Field("", alias="NVD_API_KEY")
    hashlookup_enabled: bool = Field(True, alias="HASHLOOKUP_ENABLED")
    triage_api_key: str = Field("", validation_alias=AliasChoices("TRIAGE_API_KEY", "TRIA_GE_API_KEY"))
    hybridanalysis_api_key: str = Field("", alias="HA_API_KEY")

    greynoise_api_key: str = Field("", alias="GREYNOISE_API_KEY")
    emailrep_api_key: str = Field("", alias="EMAILREP_API_KEY")
    alienvault_otx_api_key: str = Field("", validation_alias=AliasChoices("OTX_API_KEY", "ALIENVAULT_OTX_KEY"))
    shodan_api_key: str = Field("", alias="SHODAN_API_KEY")
    censys_api_key: str = Field("", alias="CENSYS_API_KEY")
    ipinfo_api_key: str = Field("", validation_alias=AliasChoices("IPINFO_API_KEY", "IPINFO_ACCESS_TOKEN"))
    etherscan_api_key: str = Field("", alias="ETHERSCAN_API_KEY")
    chainabuse_api_key: str = Field("", validation_alias=AliasChoices("CHAIN_BUSE_API", "CHAINABUSE_API_KEY", "CHAINABUSE_API"))
    filescan_api_key: str = Field("", alias="FILESCAN_API_KEY")
    hudson_api_key: str = Field("", validation_alias=AliasChoices("HUDSON_API_KEY", "HUDSON_ROCK_API_KEY", "HUDSONROCK_API_KEY"))

    log_level: str = Field("INFO", alias="LOG_LEVEL")
    api_keys: str = Field("", alias="API_KEYS")
    fail_fast_missing_keys: bool = Field(False, alias="FAIL_FAST_MISSING_KEYS")
    host: str = Field("127.0.0.1", alias="HOST")
    port: int = Field(8000, alias="PORT")
    disable_auto_open: bool = Field(False, alias="DISABLE_AUTO_OPEN")

    scoring_override_min_weight: float = Field(OVERRIDE_MIN_MALICIOUS_WEIGHT, alias="SCORING_OVERRIDE_MIN_WEIGHT")
    scoring_override_count_high: int = Field(MALICIOUS_OVERRIDE_COUNT_HIGH, alias="SCORING_OVERRIDE_COUNT_HIGH")
    scoring_override_count_medium: int = Field(MALICIOUS_OVERRIDE_COUNT_MEDIUM, alias="SCORING_OVERRIDE_COUNT_MEDIUM")
    cors_origins: str = Field("http://localhost:8000,http://127.0.0.1:8000,http://localhost:5173", alias="CORS_ORIGINS")
    base_url: str = Field("", alias="BASE_URL")
    cache_dir: str = Field("", alias="CACHE_DIR")
    app_name: str = "IOC Platform"
    debug: bool = False
    ioc_timeout: int = Field(60, alias="IOC_TIMEOUT")
    batch_deadline_seconds: int = Field(300, alias="BATCH_DEADLINE_SECONDS")
    ioc_deadline_seconds: float = Field(60.0, alias="IOC_DEADLINE_SECONDS")
    provider_timeout_seconds: float = Field(20.0, alias="PROVIDER_TIMEOUT_SECONDS")
    queue_wait_timeout_seconds: float = Field(10.0, alias="QUEUE_WAIT_TIMEOUT_SECONDS")
    network_timeout_seconds: float = Field(15.0, alias="NETWORK_TIMEOUT_SECONDS")
    batch_semaphore_limit: int = Field(10, alias="BATCH_SEMAPHORE_LIMIT")
    max_batch_iocs: int = Field(100, alias="MAX_BATCH_IOCS")
    enable_active_port_scan: bool = Field(False, alias="ENABLE_ACTIVE_PORT_SCAN")
    enable_url_content_fetch: bool = Field(False, alias="ENABLE_URL_CONTENT_FETCH")
    webhooks_enabled: bool = Field(False, alias="WEBHOOKS_ENABLED")
    enabled_sources: str = Field("", alias="ENABLED_SOURCES")
    history_retention_days: int = Field(30, alias="HISTORY_RETENTION_DAYS")
    lookup_rate_limit_per_minute: int = Field(30, alias="LOOKUP_RATE_LIMIT_PER_MINUTE")
    lookup_rate_window: int = Field(60, alias="LOOKUP_RATE_WINDOW")
    lookup_global_rate_limit_per_minute: int = Field(300, alias="LOOKUP_GLOBAL_RATE_LIMIT_PER_MINUTE")
    trust_proxy: bool = Field(False, alias="TRUST_PROXY")

    def __init__(self, **values):
        if "database_url" in values:
            values["DATABASE_URL"] = values.pop("database_url")
        super().__init__(**values)
        self._active_env_file = values.get("_env_file", str(_DEFAULT_ENV_FILE))
        self._resolve_api_keys()
        self._validate_required()

    def is_source_enabled(self, source_name: str) -> bool:
        allowed = {name.strip().lower() for name in self.enabled_sources.split(",") if name.strip()}
        return not allowed or source_name.lower() in allowed

    @field_validator("debug", mode="before")
    @classmethod
    def _parse_debug_mode(cls, value):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "production", "prod"}:
                return False
            if normalized in {"development", "develop", "dev"}:
                return True
        return value

    @field_validator("history_retention_days")
    @classmethod
    def _validate_retention_days(cls, value: int) -> int:
        if value < 1:
            raise ValueError("HISTORY_RETENTION_DAYS must be >= 1")
        return value

    def _resolve_api_keys(self):
        for field_name, info in type(self).model_fields.items():
            if not field_name.endswith("_api_key"):
                continue
            alias = info.validation_alias
            if alias is None:
                continue
            choices = list(alias.choices) if isinstance(alias, AliasChoices) else [str(alias)]
            resolved = ""
            for name in choices:
                resolved = resolve_credential(name, env_file=self._active_env_file)
                if resolved:
                    break
            if resolved:
                setattr(self, field_name, resolved)
            else:
                curr = getattr(self, field_name, "")
                if curr and curr.strip().lower() in ("null", "none", "placeholder"):
                    setattr(self, field_name, "")

    def _validate_required(self):
        if not self.database_url:
            raise ValueError("DATABASE_URL is required — set it in .env or environment")
        if self.fail_fast_missing_keys:
            from app.backend.adapters.base import is_valid_api_key

            missing = []
            for name in _API_KEY_FIELDS:
                value = getattr(self, name)
                if not is_valid_api_key(value or ""):
                    missing.append(name)
            if missing:
                raise ValueError(
                    "FAIL_FAST_MISSING_KEYS is enabled but the following API keys are "
                    f"missing or placeholders: {', '.join(missing)}"
                )
        if not _is_loopback_host(self.host) and not self.api_keys.strip():
            raise ValueError("API_KEYS is required when HOST is not a loopback address")
        return self


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


_API_KEY_FIELDS = (
    "virustotal_api_key",
    "abuseipdb_api_key",
    "urlscanio_api_key",
    "malwarebazaar_api_key",
    "threatfox_api_key",
    "urlhaus_api_key",
    "nvd_api_key",
    "triage_api_key",
    "hybridanalysis_api_key",
    "greynoise_api_key",
    "alienvault_otx_api_key",
    "shodan_api_key",
    "censys_api_key",
    "ipinfo_api_key",
    "emailrep_api_key",
)


settings = Settings()
