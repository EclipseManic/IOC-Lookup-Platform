from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

import httpx
from httpx import Timeout

from pydantic import BaseModel, Field, model_validator


class RateLimitConfig(BaseModel):
    requests_per_minute: int = 30
    requests_per_day: int = 1000
    timeout_seconds: float = 10.0
    connect_timeout: float = 5.0


class NormalizedResult(BaseModel):
    ioc: str
    ioc_type: str
    source: str
    verdict: str
    status: str = "found"  # found | not_found | error
    raw_score: Optional[float] = None
    confidence: str = "low"
    tags: list[str] = []
    categories: list[str] = []
    malware_family: Optional[str] = None
    mitre_attck: list[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_iocs: list[tuple[str, str]] = []
    source_link: Optional[str] = None
    reports_count: Optional[int] = None
    reports: list[dict] = []
    raw_data: dict = {}
    samples: list[str] = []
    dropped_files: list[str] = []
    registry_keys: list[str] = []
    network_iocs: list[tuple[str, str]] = []
    process_tree: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _coerce_none_lists(cls, data):
        if isinstance(data, dict):
            # Provider payloads are not a stable schema. Keep optional
            # enrichment metadata from turning one malformed upstream field
            # into a failed IOC analysis.
            for field_name in ("tags", "categories", "mitre_attck", "samples", "dropped_files", "registry_keys"):
                values = data.get(field_name)
                if values is None:
                    data[field_name] = []
                elif isinstance(values, (list, tuple, set)):
                    data[field_name] = [value.strip() for value in values if isinstance(value, str) and value.strip()]
                elif isinstance(values, str) and values.strip():
                    data[field_name] = [values.strip()]
                else:
                    data[field_name] = []

            for field_name in ("related_iocs", "network_iocs"):
                values = data.get(field_name)
                if not isinstance(values, (list, tuple, set)):
                    data[field_name] = []
                    continue
                data[field_name] = [
                    (str(value[0]).strip(), str(value[1]).strip())
                    for value in values
                    if isinstance(value, (list, tuple)) and len(value) >= 2 and value[0] is not None and value[1] is not None
                    and str(value[0]).strip() and str(value[1]).strip()
                ]

            for field_name in ("reports",):
                if not isinstance(data.get(field_name), list):
                    data[field_name] = []
        return data

    @model_validator(mode="after")
    def _normalize_lists(self):
        has_data = bool(
            self.tags or self.categories or self.mitre_attck or self.related_iocs
            or self.samples or self.source_link is not None or self.reports_count is not None
            or self.malware_family or self.process_tree or self.raw_score is not None
        )
        if self.verdict == "error":
            self.status = "error"
        elif self.status == "found" and self.verdict == "unknown" and not has_data:
            self.status = "not_found"
        return self


class GeoIPInfo(BaseModel):
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    abuse_email: Optional[str] = None
    org: Optional[str] = None


class DNSInfo(BaseModel):
    a: list[str] = []
    aaaa: list[str] = []
    mx: list[str] = []
    ns: list[str] = []
    txt: list[str] = []
    cname: list[str] = []


class SSLInfo(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    fingerprint: Optional[str] = None
    subject_alt_names: list[str] = []
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    days_remaining: Optional[int] = None


class ReverseDNSInfo(BaseModel):
    hostnames: list[str] = []


class SubdomainInfo(BaseModel):
    subdomains: list[str] = []


class PassiveDNSInfo(BaseModel):
    records: list[dict] = []


class CVEInfo(BaseModel):
    is_in_kev: bool = False
    kev_date_added: str = ""
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cvss_vector: str = ""
    cvss_attack_vector: str = ""
    cvss_complexity: str = ""
    cvss_privileges_required: str = ""
    cvss_user_interaction: str = ""
    cwe: list[str] = []
    references: list[str] = []
    public_exploits_exist: bool = False
    exploit_sources: list[str] = []
    poc_available: bool = False
    affected_products: list[str] = []


class BreachInfo(BaseModel):
    breach_count: Optional[int] = 0
    breach_names: list[str] = []
    most_recent_breach: str = ""
    exposed_data_types: list[str] = Field(default_factory=list)
    source: str = ""


class FaviconInfo(BaseModel):
    favicon_hash: int = 0
    favicon_url: str = ""


class EmailSecurityInfo(BaseModel):
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"


class EnrichmentData(BaseModel):
    geoip: Optional[GeoIPInfo] = None
    open_ports: list[int] = []
    whois: Optional[WhoisInfo] = None
    dns: Optional[DNSInfo] = None
    ssl: Optional[SSLInfo] = None
    reverse_dns: Optional[ReverseDNSInfo] = None
    subdomains: Optional[SubdomainInfo] = None
    cve: Optional[CVEInfo] = None
    breach: Optional[BreachInfo] = None
    favicon: Optional[FaviconInfo] = None
    email_security: Optional[EmailSecurityInfo] = None
    passive_dns: Optional[PassiveDNSInfo] = None
    redirect_chain: list[dict] = []
    url_preview: dict = {}
    extra: dict = {}
    relationships: list[dict] = []
    completeness: dict[str, str] = {}
    analysis_notes: list[str] = []


class SourceWeight(BaseModel):
    name: str
    weight: float = 1.0
    verdict: str
    score: Optional[float] = None
    confidence: Optional[str] = None


class CompositeScore(BaseModel):
    score: float = 0.0
    verdict: str = "unknown"
    confidence: str = "low"
    sources_contributing: int = 0
    source_breakdown: list[SourceWeight] = []


class LookupResponse(BaseModel):
    input: str
    normalized: str
    ioc_type: str
    composite: CompositeScore
    enrichment: EnrichmentData = EnrichmentData()
    results: list[NormalizedResult] = []
    relationships: list[dict] = []
    executive_summary: str = ""


_PLACEHOLDER_KEYS = {"", "true", "false", "1", "0", "yes", "no", "y", "n", "t", "f", "placeholder", "your_api_key", "api_key", "test", "dummy", "key"}


def is_valid_api_key(key: str) -> bool:
    return key.strip().lower() not in _PLACEHOLDER_KEYS and len(key.strip()) >= 4


class SourceAdapter(ABC):
    name: str = ""
    supported_types: list[str] = []
    public_without_key: bool = False
    rate_limit: RateLimitConfig = RateLimitConfig()
    _client: httpx.AsyncClient | None = None

    def set_client(self, client: httpx.AsyncClient):
        self._client = client

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        from app.backend.http_client import get_timeout
        t = get_timeout(self.name)
        return httpx.AsyncClient(timeout=t)

    def _check_circuit(self) -> bool:
        from app.backend.circuit_breaker import get_breaker
        return get_breaker(self.name).allow_request()

    def _record_success(self):
        from app.backend.circuit_breaker import get_breaker
        get_breaker(self.name).record_success()

    def _record_failure(self):
        from app.backend.circuit_breaker import get_breaker
        get_breaker(self.name).record_failure()

    @abstractmethod
    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        ...
