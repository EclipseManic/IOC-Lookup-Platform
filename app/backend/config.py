from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = "sqlite+aiosqlite:///./data/ioc_platform.db"

    virustotal_api_key: str = Field("", alias="VT_API_KEY")
    abuseipdb_api_key: str = Field("", validation_alias=AliasChoices("ABUSEIPDB_API_KEY", "AbuseDB_API_KEY"))
    urlscanio_api_key: str = Field("", alias="URL_SCAN_API_KEY")
    malwarebazaar_api_key: str = Field("", alias="MB_AUTH_KEY")
    threatfox_api_key: str = Field("", alias="THREATFOX_API_KEY")

    nvd_api_key: str = Field("", alias="NVD_API_KEY")
    leakcheck_api_key: str = Field("", alias="LEAKCHECK_API_KEY")
    triage_api_key: str = Field("", validation_alias=AliasChoices("TRIA_GE_API_KEY", "TRIAGE_API_KEY"))
    hybridanalysis_api_key: str = Field("", alias="HA_API_KEY")

    greynoise_api_key: str = Field("", alias="GREYNOISE_API_KEY")
    alienvault_otx_api_key: str = Field("", validation_alias=AliasChoices("OTX_API_KEY", "ALIENVAULT_OTX_KEY"))
    shodan_api_key: str = Field("", alias="SHODAN_API_KEY")
    securitytrails_api_key: str = Field("", alias="SECURITYTRAILS_API_KEY")
    phishtank_api_key: str = Field("", alias="PHISHTANK_API_KEY")
    spur_us_api_key: str = Field("", alias="SPUR_US_API_KEY")
    censys_api_key: str = Field("", alias="CENSYS_API_KEY")
    ipinfo_api_key: str = Field("", validation_alias=AliasChoices("IPINFO_API_KEY", "IPINFO_ACCESS_TOKEN"))

    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = Field("", alias="JWT_SECRET")
    app_name: str = "IOC Platform"
    debug: bool = True


settings = Settings()
