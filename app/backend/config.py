import ipaddress
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.backend.thresholds import (
    MALICIOUS_OVERRIDE_COUNT_HIGH,
    MALICIOUS_OVERRIDE_COUNT_MEDIUM,
    OVERRIDE_MIN_MALICIOUS_WEIGHT,
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent.parent / ".env"),
        env_file_encoding="utf-8",
        # Environment variables not used by this version are ignored. This
        # also keeps explicit Python field names usable when an aliased
        # variable (for example DATABASE_URL) exists in the environment.
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = Field(
        "sqlite+aiosqlite:///./data/ioc_platform.db",
        validation_alias=AliasChoices("DATABASE_URL", "database_url"),
    )

    virustotal_api_key: str = Field("", alias="VT_API_KEY")
    vt_rate_per_minute: int = Field(4, alias="VT_RATE_PER_MINUTE")
    abuseipdb_api_key: str = Field("", validation_alias=AliasChoices("ABUSEIPDB_API_KEY", "AbuseDB_API_KEY"))
    urlscanio_api_key: str = Field("", alias="URL_SCAN_API_KEY")
    malwarebazaar_api_key: str = Field("", alias="MB_AUTH_KEY")
    threatfox_api_key: str = Field("", alias="THREATFOX_API_KEY")

    nvd_api_key: str = Field("", alias="NVD_API_KEY")
    leakcheck_api_key: str = Field("", alias="LEAKCHECK_API_KEY")
    hashlookup_enabled: bool = Field(True, alias="HASHLOOKUP_ENABLED")
    triage_api_key: str = Field("", validation_alias=AliasChoices("TRIAGE_API_KEY", "TRIA_GE_API_KEY"))
    hybridanalysis_api_key: str = Field("", alias="HA_API_KEY")

    greynoise_api_key: str = Field("", alias="GREYNOISE_API_KEY")
    alienvault_otx_api_key: str = Field("", validation_alias=AliasChoices("OTX_API_KEY", "ALIENVAULT_OTX_KEY"))
    shodan_api_key: str = Field("", alias="SHODAN_API_KEY")
    securitytrails_api_key: str = Field("", alias="SECURITYTRAILS_API_KEY")
    phishtank_api_key: str = Field("", alias="PHISHTANK_API_KEY")
    spur_us_api_key: str = Field("", alias="SPUR_US_API_KEY")
    censys_api_key: str = Field("", alias="CENSYS_API_KEY")
    ipinfo_api_key: str = Field("", validation_alias=AliasChoices("IPINFO_API_KEY", "IPINFO_ACCESS_TOKEN"))

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
    jwt_secret: str = Field("dev-secret-change-in-production", alias="JWT_SECRET")
    app_name: str = "IOC Platform"
    debug: bool = False
    ioc_timeout: int = Field(60, alias="IOC_TIMEOUT")
    batch_semaphore_limit: int = Field(10, alias="BATCH_SEMAPHORE_LIMIT")
    max_batch_iocs: int = Field(100, alias="MAX_BATCH_IOCS")
    enable_active_port_scan: bool = Field(False, alias="ENABLE_ACTIVE_PORT_SCAN")
    enable_url_content_fetch: bool = Field(False, alias="ENABLE_URL_CONTENT_FETCH")
    webhooks_enabled: bool = Field(False, alias="WEBHOOKS_ENABLED")
    enabled_sources: str = Field("", alias="ENABLED_SOURCES")

    def __init__(self, **values):
        # Pydantic Settings gives an environment alias precedence over a
        # programmatic field name. Normalize the latter to the alias first so
        # explicit Settings(database_url=...) remains deterministic.
        if "database_url" in values:
            values["DATABASE_URL"] = values.pop("database_url")
        super().__init__(**values)

    def is_source_enabled(self, source_name: str) -> bool:
        """Apply the optional comma-separated provider allowlist."""
        allowed = {name.strip().lower() for name in self.enabled_sources.split(",") if name.strip()}
        return not allowed or source_name.lower() in allowed

    @field_validator("debug", mode="before")
    @classmethod
    def _parse_debug_mode(cls, value):
        """Accept common environment names as well as boolean values.

        Some development tools export ``DEBUG=release`` or
        ``DEBUG=production`` globally. Treat those values as disabled instead
        of preventing the application from starting.
        """
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "production", "prod"}:
                return False
            if normalized in {"development", "develop", "dev"}:
                return True
        return value

    @model_validator(mode="after")
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
    """Return whether a bind host is restricted to the local machine."""
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
    "nvd_api_key",
    "leakcheck_api_key",
    "triage_api_key",
    "hybridanalysis_api_key",
    "greynoise_api_key",
    "alienvault_otx_api_key",
    "shodan_api_key",
    "securitytrails_api_key",
    "phishtank_api_key",
    "spur_us_api_key",
    "censys_api_key",
    "ipinfo_api_key",
)


settings = Settings()
