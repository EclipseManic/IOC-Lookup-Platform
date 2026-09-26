import asyncio
import ipaddress
import json
import random
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.backend.cache import TASK_TTL, CacheLayer, cache_key, cache_ttl
from app.backend.config import settings
from app.backend.http_client import get_client
from app.backend.rate_limiter import RateLimiter
from app.backend.adapters.cve_org import CveOrgAdapter
from app.backend.adapters.hashlookup import HashlookupAdapter
from app.backend.adapters.abstract_api import AbstractAPIAdapter
from app.backend.adapters.hunter_io import HunterIOAdapter
from app.backend.adapters.team_cymru import TeamCymruAdapter
from app.backend.adapters.nvd import NvdAdapter
from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.alienvault_otx import AlienVaultOTXAdapter
from app.backend.adapters.base import (
    CompositeScore,
    EnrichmentData,
    InfostealerIntel,
    IOCAssessment,
    LookupResponse,
    NormalizedResult,
    ProviderHealth,
    WebPreviewInfo,
)
from app.backend.adapters.censys import CensysAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.hybrid_analysis import HybridAnalysisAdapter
from app.backend.adapters.ipinfo import IPinfoAdapter
from app.backend.adapters.malware_bazaar import MalwareBazaarAdapter
from app.backend.adapters.openphish import OpenPhishAdapter
from app.backend.adapters.stop_forum_spam import StopForumSpamAdapter
from app.backend.adapters.shodan import ShodanAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.triage import TriageAdapter
from app.backend.adapters.urlhaus import URLHausAdapter
from app.backend.adapters.urlscan_io import UrlScanIOAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.adapters.etherscan import EtherscanAdapter
from app.backend.adapters.chainabuse import ChainAbuseAdapter
from app.backend.adapters.filescan import FileScanAdapter
from app.backend.adapters.blockchain_info import BlockchainInfoAdapter
from app.backend.adapters.hudson_rock import HudsonRockAdapter
from app.backend.adapters.hibp import HIBPAdapter
from app.backend.classifier import SUPPORTED_IOC_TYPES, is_password_digest, normalize_ioc, password_digest
from app.backend.domain_router import route_assessment_domain
from app.backend.evidence import normalize_provider_result
from app.backend.provider_capabilities import build_provider_plan
from app.backend.enrichment import enrich, normalize_cve_enrichment
from app.backend.executive_summary import generate_executive_summary
from app.backend.logger import get_logger
from app.backend.scorer import aggregate_evidence, compute_composite

logger = get_logger("pipeline")

_ADAPTERS_CACHE: list | None = None


def _init_adapters():
    global _ADAPTERS_CACHE
    if _ADAPTERS_CACHE is not None:
        return _ADAPTERS_CACHE
    client = get_client()
    adapters = [
        MalwareBazaarAdapter(),
        ThreatFoxAdapter(),
        VirusTotalAdapter(),
        AbuseIPDBAdapter(),
        UrlScanIOAdapter(),
        TriageAdapter(),
        HybridAnalysisAdapter(),
        GreyNoiseAdapter(),
        AlienVaultOTXAdapter(),
        ShodanAdapter(),
        OpenPhishAdapter(),
        URLHausAdapter(),
        TorExitAdapter(),
        CensysAdapter(),
        IPinfoAdapter(),
        StopForumSpamAdapter(),
        AbstractAPIAdapter(),
        HunterIOAdapter(),
        TeamCymruAdapter(),
        CveOrgAdapter(),
        NvdAdapter(),
        HashlookupAdapter(),
        EtherscanAdapter(),
        ChainAbuseAdapter(),
        FileScanAdapter(),
        BlockchainInfoAdapter(),
        HudsonRockAdapter(),
        HIBPAdapter(),
    ]
    for a in adapters:
        a.set_client(client)
    _ADAPTERS_CACHE = adapters
    return adapters


ADAPTERS = _init_adapters()

PIPELINE_TIMEOUT = 60.0
ADAPTER_TIMEOUT = 20.0
@dataclass
class StageInfo:
    name: str
    status: str = "pending"  # pending | running | done | error | skipped
    message: str = ""
    progress: float = 0.0


@dataclass
class AnalysisTask:
    task_id: str
    status: str = "pending"  # pending | classifying | querying | enriching | scoring | done | error
    progress: float = 0.0
    stages: list[StageInfo] = field(default_factory=list)
    ioc_value: str = ""
    ioc_type: str = ""
    password_prehashed: bool = False
    normalized: str = ""
    assessment_domain: str = "ioc_reputation"
    provider_plan: list[dict] = field(default_factory=list)
    results: list[NormalizedResult] = field(default_factory=list)
    composite: Optional[object] = None
    final_assessment: Optional[IOCAssessment] = None
    provider_health: list[ProviderHealth] = field(default_factory=list)
    enrichment: Optional[EnrichmentData] = None
    relationships: list[dict] = field(default_factory=list)
    executive_summary: str = ""
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self):
        def _dump(obj):
            if obj is None:
                return None
            if hasattr(obj, "model_dump"):
                return obj.model_dump(mode="json")
            return obj

        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress": self.progress,
            "stages": [{"name": s.name, "status": s.status, "message": s.message, "progress": s.progress} for s in self.stages],
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "password_prehashed": self.password_prehashed,
            "normalized": self.normalized,
            "assessment_domain": self.assessment_domain,
            "provider_plan": self.provider_plan,
            "results": [_dump(r) for r in self.results],
            "composite": _dump(self.composite),
            "final_assessment": _dump(self.final_assessment),
            "provider_health": [_dump(h) for h in self.provider_health],
            "enrichment": _dump(self.enrichment),
            "relationships": self.relationships,
            "executive_summary": self.executive_summary,
            "error": self.error,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisTask":
        stages = [
            StageInfo(name=s["name"], status=s.get("status", "pending"), message=s.get("message", ""), progress=s.get("progress", 0.0))
            for s in data.get("stages", [])
        ]
        results = [NormalizedResult.model_validate(r) for r in data.get("results", [])]
        composite = CompositeScore.model_validate(data["composite"]) if data.get("composite") else None
        final_assessment = IOCAssessment.model_validate(data["final_assessment"]) if data.get("final_assessment") else None
        provider_health = [ProviderHealth.model_validate(h) for h in data.get("provider_health", [])]
        enrichment = EnrichmentData.model_validate(data["enrichment"]) if data.get("enrichment") else None
        return cls(
            task_id=data["task_id"],
            status=data.get("status", "pending"),
            progress=data.get("progress", 0.0),
            stages=stages,
            ioc_value=data.get("ioc_value", ""),
            ioc_type=data.get("ioc_type", ""),
            password_prehashed=data.get("password_prehashed", False),
            normalized=data.get("normalized", ""),
            assessment_domain=data.get("assessment_domain", "ioc_reputation"),
            provider_plan=data.get("provider_plan", []),
            results=results,
            composite=composite,
            final_assessment=final_assessment,
            provider_health=provider_health,
            enrichment=enrichment,
            relationships=data.get("relationships", []),
            executive_summary=data.get("executive_summary", ""),
            error=data.get("error"),
            created_at=data.get("created_at", time.time()),
        )


def task_response_payload(task: AnalysisTask) -> dict:
    return LookupResponse(
        input=task.ioc_value,
        task_id=task.task_id,
        normalized=task.normalized or task.ioc_value,
        ioc_type=task.ioc_type or "unknown",
        password_prehashed=task.password_prehashed or (
            task.ioc_type == "password" and bool(re.fullmatch(r"[a-f0-9]{40}", task.normalized or "", re.IGNORECASE))
        ),
        composite=task.composite or CompositeScore(),
        final_assessment=task.final_assessment,
        provider_health=task.provider_health,
        enrichment=task.enrichment or EnrichmentData(),
        results=task.results,
        relationships=task.relationships,
        executive_summary=task.executive_summary,
    ).model_dump(mode="json")


_tasks: dict[str, AnalysisTask] = {}
_task_queues: dict[str, asyncio.Queue] = {}
_running_tasks: dict[str, asyncio.Task] = {}
_lock = asyncio.Lock()
_dict_lock = threading.Lock()
_cache_locks: dict[str, asyncio.Lock] = {}


def _lock_for(key: str) -> asyncio.Lock:
    lock = _cache_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _cache_locks[key] = lock
    return lock

cache: CacheLayer | None = None
rate_limiter: RateLimiter | None = None


def set_cache(cache_instance: CacheLayer | None):
    global cache
    cache = cache_instance


def get_cache() -> CacheLayer | None:
    return cache


def set_rate_limiter(limiter: RateLimiter | None):
    global rate_limiter
    rate_limiter = limiter


def get_rate_limiter() -> RateLimiter | None:
    return rate_limiter


async def _update_stage(task: AnalysisTask, stage_name: str, status: str, message: str = "", progress: float = 0.0):
    for s in task.stages:
        if s.name == stage_name:
            s.status = status
            if message:
                s.message = message
            if progress:
                s.progress = progress
            break


def _result_metadata(result: NormalizedResult, *, started: float, retry_count: int = 0, request_made: bool = True) -> NormalizedResult:
    """Attach execution/cache-independent audit metadata to a provider result."""
    if result.observed_at is None:
        result.observed_at = datetime.now(timezone.utc)
    result.source_timestamp = result.source_timestamp or result.last_seen or result.first_seen
    result.latency_ms = round(max(0.0, (time.monotonic() - started) * 1000.0), 2)
    result.retry_count = max(int(result.retry_count or 0), retry_count)
    result.request_made = request_made
    return result


def _failure_result(ioc: str, ioc_type: str, source: str, state: str, tag: str, *, retry_count: int = 0, retry_after: float | None = None, request_made: bool = False, started: float | None = None) -> NormalizedResult:
    result = NormalizedResult(
        ioc=ioc,
        ioc_type=ioc_type,
        source=source,
        verdict="unknown",
        execution_state=state,
        tags=[tag],
        retry_count=retry_count,
        retry_after_seconds=retry_after,
        request_made=request_made,
    )
    if started is not None:
        result.latency_ms = round(max(0.0, (time.monotonic() - started) * 1000.0), 2)
    return result


def _retryable_result(result: NormalizedResult) -> bool:
    state = result.execution_state
    if state in {"rate_limited", "timeout"}:
        return True
    if state != "error":
        return False
    tags = {str(tag).lower() for tag in (result.tags or [])}
    return any(
        tag == "request_error" or tag.startswith("http_5")
        for tag in tags
    )


def _retry_delay(result: NormalizedResult, retry_number: int, adapter) -> float:
    retry_after = result.retry_after_seconds
    if retry_after is not None and retry_after >= 0:
        return min(float(retry_after), float(getattr(adapter.rate_limit, "max_backoff_seconds", 8.0)))
    base = float(getattr(adapter.rate_limit, "backoff_factor", 0.5))
    ceiling = float(getattr(adapter.rate_limit, "max_backoff_seconds", 8.0))
    return min(ceiling, base * (2 ** max(0, retry_number - 1))) * random.uniform(0.8, 1.2)


def _finalize_assessment(task: AnalysisTask, assessment: IOCAssessment) -> IOCAssessment:
    """Attach the complete plan while keeping synthetic N/A rows out of evidence."""
    task_plan = list(task.provider_plan or [])
    # The capability declaration is already available from /api/sources. A
    # batch assessment only needs the decision that was made for this IOC;
    # embedding the full rate/retry policy once per provider and IOC inflated
    # exports without adding evidence.
    assessment.provider_plan = [
        {
            key: item.get(key)
            for key in ("provider", "ioc_type", "assessment_domain", "applicable", "operation", "reason")
            if key in item
        }
        for item in task_plan
    ]
    assessment.provider_breakdown = [
        observation for observation in assessment.provider_breakdown
        if observation.execution_state != "not_applicable"
    ]
    if assessment.evidence_counts:
        assessment.evidence_counts["provider_status"] = len([
            observation for observation in assessment.provider_breakdown
            if observation.execution_state not in {"success", "not_found"}
        ])
    assessment.evidence_summary["providers_aggregated"] = len(assessment.provider_breakdown)
    assessment.evidence_summary["not_applicable_providers"] = len([
        item for item in task_plan if not item.get("applicable", True)
    ])
    assessment.provider_summary = [
        item for item in assessment.provider_summary
        if item.get("execution_state") != "not_applicable"
    ]
    assessment.provenance = [
        item for item in assessment.provenance
        if item.get("source") in {observation.source for observation in assessment.provider_breakdown}
    ]
    return assessment


async def run_analysis(
    ioc_value: str,
    task_id: Optional[str] = None,
    fp_override: bool = False,
    ioc_type_override: str | None = None,
    ioc_deadline: float | None = None,
    bypass_cache: bool = False,
    password_prehashed: bool = False,
) -> AnalysisTask:
    tid = task_id or uuid.uuid4().hex[:12]
    configured_deadline = ioc_deadline if ioc_deadline is not None else getattr(settings, "ioc_deadline_seconds", PIPELINE_TIMEOUT)
    deadline = time.monotonic() + max(0.1, float(configured_deadline))
    stages = [
        StageInfo("Classify & Normalize"),
        StageInfo("MalwareBazaar"),
        StageInfo("ThreatFox"),
        StageInfo("VirusTotal"),
        StageInfo("AbuseIPDB"),
        StageInfo("urlscan.io"),
        StageInfo("Tria.ge"),
        StageInfo("Hybrid Analysis"),
        StageInfo("GreyNoise"),
        StageInfo("AlienVault OTX"),
        StageInfo("Shodan"),
        StageInfo("OpenPhish"),
        StageInfo("URLhaus"),
        StageInfo("Tor Exit"),
        StageInfo("Censys"),
        StageInfo("IPinfo"),
        StageInfo("StopForumSpam"),
        StageInfo("AbstractAPI"),
        StageInfo("Hunter.io"),
        StageInfo("Team Cymru"),
        StageInfo("Hashlookup"),
        StageInfo("CVE Intelligence"),
        StageInfo("Enrichment"),
        StageInfo("Scoring & Relations"),
    ]

    normalized_info = normalize_ioc(ioc_value, expected_type=ioc_type_override)
    normalized = normalized_info.value
    ioc_type = ioc_type_override or normalized_info.ioc_type
    if ioc_type == "password" and password_prehashed and not is_password_digest(normalized):
        password_prehashed = False
    if ioc_type == "password" and normalized:
        safe_ioc_value = password_digest(normalized, already_digest=password_prehashed)
    elif normalized_info.valid:
        safe_ioc_value = normalized
    else:
        safe_ioc_value = ""

    task = AnalysisTask(
        task_id=tid,
        ioc_value=safe_ioc_value,
        stages=stages,
        status="pending",
        password_prehashed=password_prehashed,
    )

    with _dict_lock:
        _tasks[tid] = task
    async with _lock:
        if cache is not None:
            await cache.save_task(tid, task.to_dict(), TASK_TTL)

    _register_running(tid)
    try:
        task.status = "classifying"
        task.progress = 2.0
        await _update_stage(task, "Classify & Normalize", "running", "Normalizing IOC value")
        await _emit_stage_event(task, "Classify & Normalize", "running", "Normalizing IOC value")

        if not normalized:
            raise ValueError("Empty IOC after normalization")
        if ioc_type not in SUPPORTED_IOC_TYPES:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        if ioc_type_override and ioc_type not in normalized_info.candidate_types:
            raise ValueError(f"IOC value does not validate as {ioc_type}")
        if ioc_type == "password":
            normalized = password_digest(normalized, already_digest=password_prehashed)
        task.ioc_type = ioc_type
        task.normalized = normalized
        task.assessment_domain = route_assessment_domain(ioc_type, normalized).domain
        task.provider_plan = [item.as_dict() for item in build_provider_plan(ADAPTERS, ioc_type, normalized)]

        await _update_stage(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)
        await _emit_stage_event(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)

        if ioc_type in ("ipv4", "ipv6"):
            try:
                addr = ipaddress.ip_address(normalized)
                if not addr.is_global or addr.is_reserved or addr.is_unspecified:
                    private_result = NormalizedResult(
                        ioc=normalized, ioc_type=ioc_type, source="reserved_ip",
                        verdict="unknown", execution_state="unavailable",
                        request_made=False, tags=["private_ip", "no_external_lookup"],
                    )
                    task.results = [private_result]
                    task.enrichment = EnrichmentData(
                        completeness={"external_reputation": "skipped"},
                        analysis_notes=["Private, reserved, or unspecified address; no external reputation lookup was performed."],
                    )
                    task.final_assessment = aggregate_evidence(
                        normalized, ioc_type, task.results, task.enrichment,
                    )
                    task.final_assessment = _finalize_assessment(task, task.final_assessment)
                    task.provider_health = task.final_assessment.provider_health
                    task.final_assessment.reason = "This is a private, reserved, or unspecified address; external reputation was not queried."
                    task.composite = compute_composite(
                        task.results,
                        ioc=normalized,
                        ioc_type=ioc_type,
                        enrichment=task.enrichment,
                        assessment=task.final_assessment,
                    )
                    task.status = "done"
                    task.progress = 100.0
                    _unregister_running(tid)
                    return task

            except ValueError:
                pass

        from app.backend.adapters.base import is_valid_api_key

        plan = build_provider_plan(ADAPTERS, ioc_type, normalized)
        applicable_names = {item.provider for item in plan if item.applicable}
        matching = [a for a in ADAPTERS if a.name in applicable_names]

        # Keep explicit unavailable records for relevant providers.  A source
        # that is disabled, unconfigured, or quota-blocked must be visible in
        # the audit trail instead of silently disappearing from coverage.
        unavailable_results: list[NormalizedResult] = [
            NormalizedResult(
                ioc=normalized, ioc_type=ioc_type, source=item.provider,
                verdict="unknown", provider_verdict="not_applicable", normalized_verdict="unknown",
                execution_state="not_applicable", status="not_applicable", assessment_domain=task.assessment_domain,
                request_made=False, tags=["unsupported_provider_type"],
            )
            for item in plan if not item.applicable
        ]
        key_filtered = []
        for a in matching:
            if not settings.is_source_enabled(a.name):
                unavailable_results.append(_failure_result(
                    normalized, ioc_type, a.name, "unavailable", "disabled_by_policy",
                    request_made=False,
                ))
                for s in task.stages:
                    if s.name == a.name:
                        s.status = "skipped"
                        s.message = "Disabled by source policy"
                        s.progress = 1.0
                continue
            key = getattr(a, 'api_key', None)
            if (
                key is not None
                and not is_valid_api_key(key)
                and not getattr(a, "public_without_key", False)
            ):
                unavailable_results.append(_failure_result(
                    normalized, ioc_type, a.name, "unavailable", "no_api_key_configured",
                    request_made=False,
                ))
                for s in task.stages:
                    if s.name == a.name:
                        s.status = "skipped"
                        s.message = "No API key"
                        s.progress = 1.0
            else:
                key_filtered.append(a)
        matching = key_filtered

        for s in task.stages:
            if s.name == "CVE Intelligence":
                continue
            if s.name not in ("Classify & Normalize", "Enrichment", "Scoring & Relations"):
                adapter_match = any(a.name == s.name for a in matching)
                if not adapter_match:
                    s.status = "skipped"
                    s.progress = 1.0

        task.status = "querying"
        coros = [(a, normalized, ioc_type) for a in matching]

        result_map: dict[str, NormalizedResult] = {r.source: r for r in unavailable_results}
        pipeline_timed_out = False

        async def run_adapter(adapter, ioc_value, ioc_type):
            stage_name = adapter.name
            ck = cache_key(adapter.name, ioc_type, ioc_value)
            async def _execute():
                await _update_stage(task, stage_name, "running", f"Querying {adapter.name}")
                started = time.monotonic()

                if not adapter._check_circuit():
                    nr = _failure_result(
                        normalized, ioc_type, adapter.name, "unavailable", "circuit_open",
                        request_made=False, started=started,
                    )
                    result_map[adapter.name] = nr
                    await _update_stage(task, stage_name, "skipped", "Provider unavailable (circuit open)", 1.0)
                    await _emit_stage_event(task, stage_name, "skipped", "Provider unavailable (circuit open)", 1.0)
                    await _emit_result_event(task, nr)
                    return

                attempts = 0
                max_retries = max(0, int(getattr(adapter.rate_limit, "max_retries", 2)))
                final_result: NormalizedResult | None = None
                while True:
                    slot_acquired = False
                    queue_started = time.monotonic()
                    try:
                        if rate_limiter is not None:
                            slot_cm = rate_limiter.provider_slot(
                                adapter.name,
                                getattr(adapter.rate_limit, "concurrency_limit", 2),
                                timeout=float(getattr(settings, "queue_wait_timeout_seconds", 10.0)),
                            )
                        else:
                            from contextlib import nullcontext
                            slot_cm = nullcontext()
                        # The slot is held only for the actual provider call;
                        # waiting/backoff never blocks unrelated providers.
                        with_slot = hasattr(slot_cm, "__aenter__")
                        if with_slot:
                            async with slot_cm:
                                slot_acquired = True
                                queue_wait_ms = (time.monotonic() - queue_started) * 1000.0
                                if rate_limiter is not None and hasattr(rate_limiter, "wait_for_interval"):
                                    queue_wait_ms += await rate_limiter.wait_for_interval(
                                        adapter.name,
                                        float(getattr(adapter.rate_limit, "minimum_interval_seconds", 0.0)),
                                        timeout=float(getattr(settings, "queue_wait_timeout_seconds", 10.0)),
                                    )
                                if rate_limiter is not None:
                                    if hasattr(rate_limiter, "acquire_provider"):
                                        decision = await rate_limiter.acquire_provider(
                                            adapter.name,
                                            adapter.rate_limit.requests_per_minute,
                                            adapter.rate_limit.requests_per_day,
                                            timeout=0.0,
                                        )
                                    else:
                                        allowed = await rate_limiter.acquire(
                                            adapter.name, adapter.rate_limit.requests_per_minute, 60,
                                        )
                                        from app.backend.rate_limiter import RateLimitDecision
                                        decision = RateLimitDecision(allowed, reason="rate_limited" if not allowed else "")
                                    if not decision.allowed:
                                        # ── Adaptive rate-limit waiting ─────
                                        # Instead of immediately failing, wait
                                        # for the rate-limit window to expire
                                        # and then retry the provider call.
                                        wait_secs = decision.retry_after_seconds or float(
                                            getattr(adapter.rate_limit, "minimum_interval_seconds", 15.0)
                                        )
                                        max_wait = float(getattr(adapter.rate_limit, "max_backoff_seconds", 60.0))
                                        wait_secs = min(wait_secs, max_wait)
                                        if time.monotonic() + wait_secs < deadline:
                                            limit_tag = decision.reason or "rate_limited"
                                            logger.info(
                                                "Rate-limited on %s for %s — waiting %.1fs (attempt %s/%s)",
                                                adapter.name, normalized, wait_secs, attempts + 1, max_retries,
                                            )
                                            await _update_stage(
                                                task, stage_name, "running",
                                                f"Rate-limited — waiting {wait_secs:.0f}s…",
                                            )
                                            await _emit_stage_event(
                                                task, stage_name, "running",
                                                f"Rate-limited — waiting {wait_secs:.0f}s…",
                                            )
                                            await asyncio.sleep(wait_secs)
                                            attempts += 1
                                            continue  # retry the while loop
                                        # Deadline would be exceeded — give up.
                                        limit_tag = decision.reason or "rate_limited"
                                        final_result = _failure_result(
                                            normalized, ioc_type, adapter.name, "rate_limited", limit_tag,
                                            retry_count=attempts,
                                            retry_after=decision.retry_after_seconds,
                                            request_made=False,
                                            started=started,
                                        )
                                        break
                                remaining = max(0.1, deadline - time.monotonic())
                                provider_timeout = min(
                                    remaining,
                                    float(getattr(settings, "provider_timeout_seconds", ADAPTER_TIMEOUT)),
                                    float(getattr(adapter.rate_limit, "timeout_seconds", ADAPTER_TIMEOUT)),
                                )
                                result = await asyncio.wait_for(
                                    adapter.lookup(ioc_value, ioc_type),
                                    timeout=provider_timeout,
                                )
                        else:
                            queue_wait_ms = 0.0
                            remaining = max(0.1, deadline - time.monotonic())
                            result = await asyncio.wait_for(
                                adapter.lookup(ioc_value, ioc_type),
                                timeout=min(float(getattr(settings, "provider_timeout_seconds", ADAPTER_TIMEOUT)), remaining),
                            )
                        if isinstance(result, Exception):
                            raise result
                        if not isinstance(result, NormalizedResult):
                            result = NormalizedResult.model_validate(result)
                        result = normalize_provider_result(result, task.assessment_domain)
                        result.queue_wait_ms = round(queue_wait_ms, 2)
                        result.network_latency_ms = result.latency_ms
                        result = _result_metadata(result, started=started, retry_count=attempts)
                        final_result = result
                        if _retryable_result(result) and attempts < max_retries:
                            # Do not retry before a server-provided
                            # Retry-After deadline.  If that deadline exceeds
                            # this provider's retry budget, return the
                            # rate-limited observation instead.
                            retry_after = result.retry_after_seconds
                            max_backoff = float(getattr(adapter.rate_limit, "max_backoff_seconds", 8.0))
                            if retry_after is not None and retry_after > max_backoff:
                                break
                            attempts += 1
                            delay = _retry_delay(result, attempts, adapter)
                            if time.monotonic() + delay >= deadline:
                                break
                            logger.info("Retrying provider %s for %s (attempt %s/%s)", adapter.name, normalized, attempts, max_retries)
                            await asyncio.sleep(delay)
                            continue
                        break
                    except asyncio.TimeoutError:
                        timeout_state = "timeout" if slot_acquired else "unavailable"
                        timeout_tag = "timeout" if slot_acquired else "queue_wait_timeout"
                        final_result = _failure_result(
                            normalized, ioc_type, adapter.name, timeout_state, timeout_tag,
                            retry_count=attempts, request_made=slot_acquired, started=started,
                        )
                        if slot_acquired and attempts < max_retries:
                            attempts += 1
                            delay = _retry_delay(final_result, attempts, adapter)
                            if time.monotonic() + delay < deadline:
                                await asyncio.sleep(delay)
                                continue
                        break
                    except httpx.TimeoutException:
                        final_result = _failure_result(
                            normalized, ioc_type, adapter.name, "timeout", "timeout",
                            retry_count=attempts, request_made=True, started=started,
                        )
                        if attempts < max_retries:
                            attempts += 1
                            delay = _retry_delay(final_result, attempts, adapter)
                            if time.monotonic() + delay < deadline:
                                await asyncio.sleep(delay)
                                continue
                        break
                    except (httpx.RequestError, ConnectionError, OSError):
                        final_result = _failure_result(
                            normalized, ioc_type, adapter.name, "error", "request_error",
                            retry_count=attempts, request_made=True, started=started,
                        )
                        if attempts < max_retries:
                            attempts += 1
                            delay = _retry_delay(final_result, attempts, adapter)
                            if time.monotonic() + delay < deadline:
                                await asyncio.sleep(delay)
                                continue
                        break
                    except Exception as ex:
                        error_kind = ex.__class__.__name__
                        final_result = _failure_result(
                            normalized, ioc_type, adapter.name, "error", "adapter_exception",
                            retry_count=attempts, request_made=True, started=started,
                        )
                        final_result.tags.append(f"exception_type:{error_kind}")
                        break

                result = final_result or _failure_result(
                    normalized, ioc_type, adapter.name, "error", "provider_error",
                    retry_count=attempts, request_made=False, started=started,
                )
                result.assessment_domain = task.assessment_domain
                result.queue_wait_ms = round(locals().get("queue_wait_ms", 0.0), 2)
                result = normalize_provider_result(result, task.assessment_domain)
                result_map[adapter.name] = result
                if result.execution_state in {"error", "timeout", "rate_limited", "unavailable"}:
                    adapter._record_failure()
                else:
                    adapter._record_success()
                logger.info(
                    "Provider lookup source=%s state=%s latency_ms=%s retries=%s cache_hit=%s http_status=%s",
                    adapter.name, result.execution_state, result.latency_ms, result.retry_count,
                    result.cached, result.http_status,
                )
                # Cache successful answers, including not_found answers.  A
                # health failure or rate-limit or error is NEVER cached because it
                # is not valid IOC intelligence and would poison future scans.
                _is_error_result = (
                    result.execution_state not in {"success", "not_found"}
                    or bool(getattr(result, "error", None))
                    or any(t in (result.tags or []) for t in ("error", "rate_limited", "timeout", "circuit_breaker", "failed", "service_unavailable"))
                )
                if cache is not None and not _is_error_result:
                    ttl = int(getattr(adapter.rate_limit, "cache_ttl_seconds", None) or cache_ttl(adapter.name, ioc_type))
                    cache_now = datetime.now(timezone.utc)
                    result.cache_key = ck
                    result.cache_created_at = cache_now
                    result.retrieved_at = cache_now
                    result.expires_at = cache_now + timedelta(seconds=ttl)
                    result.source_timestamp = result.source_timestamp or result.last_seen or result.first_seen
                    result.cache_status = "fresh"
                    result.freshness_class = "fresh"
                    result.stale = False
                    result.cache_metadata.cached = False
                    result.cache_metadata.cache_key = ck
                    result.cache_metadata.cache_created_at = cache_now
                    result.cache_metadata.retrieved_at = cache_now
                    result.cache_metadata.observed_at = result.observed_at
                    result.cache_metadata.expires_at = result.expires_at
                    result.cache_metadata.source_timestamp = result.source_timestamp
                    await cache.set(ck, result.model_dump(mode="json"), ttl)
                stage_status = "done" if result.execution_state in {"success", "not_found"} else "error"
                stage_message = (
                    f"{adapter.name} done"
                    if stage_status == "done"
                    else f"{result.execution_state.replace('_', ' ').capitalize()}"
                )
                await _update_stage(task, stage_name, stage_status, stage_message, 1.0)
                await _emit_stage_event(task, stage_name, stage_status, stage_message, 1.0)
                await _emit_result_event(task, result)
                if stage_status == "error":
                    await _emit_error_event(task, stage_name, stage_message)

                completed = sum(1 for s in task.stages if s.status in ("done", "error", "skipped"))
                total_stages = len(task.stages)
                task.progress = 5.0 + (completed / total_stages) * 55.0 if total_stages > 0 else 60.0

            if cache is not None and not bypass_cache:
                async with _lock_for(ck):
                    cache_entry = await cache.get_entry(ck) if hasattr(cache, "get_entry") else None
                    cached_stale = False
                    if cache_entry is not None:
                        cached, cached_stale = cache_entry
                    else:
                        cached = await cache.get(ck)
                    if cached is not None:
                        result = NormalizedResult(**cached)
                        # Older cache entries may have been written before
                        # execution states were explicit. Never reuse an error,
                        # rate-limit, or health failure. Purge it from cache
                        # and run a fresh live scan instead.
                        cached_is_error = (
                            result.execution_state not in {"success", "not_found"}
                            or bool(getattr(result, "error", None))
                            or any(t in (result.tags or []) for t in ("error", "rate_limited", "timeout", "circuit_breaker", "failed", "service_unavailable"))
                        )
                        if cached_is_error:
                            await cache.delete(ck)
                            cached = None
                        elif not cached_stale:
                            if "cached" not in result.tags:
                                result.tags = list(result.tags or []) + ["cached"]
                            result.cached = True
                            result.cache_status = "cached"
                            # These fields describe this lookup, not the
                            # original request that populated the cache.
                            result.request_made = False
                            result.latency_ms = 0.0
                            result.network_latency_ms = 0.0
                            result.queue_wait_ms = 0.0
                            result.retrieved_at = datetime.now(timezone.utc)
                            cache_reference = result.cache_created_at or result.retrieved_at or result.observed_at
                            if cache_reference is not None:
                                if cache_reference.tzinfo is None:
                                    cache_reference = cache_reference.replace(tzinfo=timezone.utc)
                                result.cache_age = max(0.0, (result.retrieved_at - cache_reference).total_seconds())
                            result.freshness_class = "cached"
                            result.stale = False
                            result.cache_metadata.cached = True
                            result.cache_metadata.cache_key = ck
                            result.cache_metadata.cache_age = result.cache_age
                            result.cache_metadata.retrieved_at = result.retrieved_at
                            result.cache_metadata.freshness_class = "cached"
                            result.cache_metadata.stale = False
                            result.cache_metadata.status = "cached"
                            result_map[adapter.name] = result
                            await _update_stage(task, stage_name, "done", f"{adapter.name} (cached)", 1.0)
                            await _emit_stage_event(task, stage_name, "done", f"{adapter.name} (cached)", 1.0)
                            await _emit_result_event(task, result)
                            return
                    await _execute()
                    if cached is not None and cached_stale:
                        live_res = result_map.get(adapter.name)
                        if live_res and live_res.execution_state in {"error", "timeout", "rate_limited"}:
                            stale_res = NormalizedResult(**cached)
                            if "cached" not in stale_res.tags:
                                stale_res.tags = list(stale_res.tags or []) + ["cached"]
                            stale_res.cached = True
                            stale_res.cache_status = "stale"
                            stale_res.freshness_class = "historical"
                            stale_res.stale = True
                            stale_res.retrieved_at = datetime.now(timezone.utc)
                            cache_reference = stale_res.cache_created_at or stale_res.observed_at
                            if cache_reference is not None:
                                if cache_reference.tzinfo is None:
                                    cache_reference = cache_reference.replace(tzinfo=timezone.utc)
                                stale_res.cache_age = max(0.0, (stale_res.retrieved_at - cache_reference).total_seconds())
                            stale_res.cache_metadata.cached = True
                            stale_res.cache_metadata.cache_key = ck
                            stale_res.cache_metadata.cache_age = stale_res.cache_age
                            stale_res.cache_metadata.retrieved_at = stale_res.retrieved_at
                            stale_res.cache_metadata.freshness_class = "historical"
                            stale_res.cache_metadata.stale = True
                            stale_res.cache_metadata.status = "stale"
                            result_map[adapter.name] = stale_res
            else:
                await _execute()

        runners = [
            asyncio.create_task(run_adapter(adapter, value, indicator_type))
            for adapter, value, indicator_type in coros
        ]
        # A provider timeout is isolated inside run_adapter.  Only tasks that
        # are still pending when the IOC deadline expires are aborted; completed
        # observations are never relabeled as orchestration failures.
        if runners:
            done, pending = await asyncio.wait(runners, timeout=max(0.1, deadline - time.monotonic()))
            await asyncio.gather(*done, return_exceptions=True)
            if pending:
                pipeline_timed_out = True
                for runner in pending:
                    runner.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for adapter in matching:
                    if adapter.name not in result_map:
                        result_map[adapter.name] = _failure_result(
                            normalized, ioc_type, adapter.name,
                            "aborted_due_to_ioc_deadline", "aborted_due_to_ioc_deadline",
                            request_made=False,
                        )
                for s in task.stages:
                    if s.status == "running":
                        s.status = "skipped"
                        s.message = "Aborted due to IOC deadline"
                        s.progress = 1.0

        if pipeline_timed_out:
            task.results = [result_map[a.name] for a in matching if a.name in result_map]
            task.results.extend(unavailable_results)
            task.enrichment = EnrichmentData(
                completeness={"pipeline": "partial"},
                analysis_notes=["Pipeline timeout: the assessment uses only provider results completed before the deadline."],
            )
            task.final_assessment = aggregate_evidence(normalized, ioc_type, task.results, task.enrichment)
            task.final_assessment = _finalize_assessment(task, task.final_assessment)
            task.final_assessment.reason = "Partial provider results were available before the IOC deadline; pending providers were aborted without changing completed observations."
            task.composite = compute_composite(
                task.results, ioc=normalized, ioc_type=ioc_type,
                enrichment=task.enrichment, assessment=task.final_assessment,
            )
            task.provider_health = task.final_assessment.provider_health
            task.status = "done"
            task.error = "Pipeline timeout exceeded; partial result"
            task.progress = 100.0
            logger.warning("Pipeline timed out for %s", normalized)
            await _emit_error_event(task, "Pipeline", "Pipeline timeout exceeded")
            await _update_stage(task, "Scoring & Relations", "done", "Partial result scored", 1.0)
            await _emit_done_event(task)
        else:
            task.results = [result_map[a.name] for a in matching if a.name in result_map]
            task.results.extend(unavailable_results)

            task.status = "enriching"
            task.progress = 65.0
            await _update_stage(task, "Enrichment", "running", f"Running type-specific enrichment for {ioc_type}")

            enrichment = EnrichmentData()
            try:
                remaining = max(1.0, deadline - time.monotonic())
                enrichment = await asyncio.wait_for(enrich(normalized, ioc_type), timeout=remaining)
            except asyncio.TimeoutError:
                logger.warning("Enrichment timed out for %s (%s)", normalized, ioc_type)
                await _emit_error_event(task, "Enrichment", "Enrichment timed out")
            except Exception as ex:
                logger.warning("Enrichment failed for %s (%s): %s", normalized, ioc_type, ex)
                await _emit_error_event(task, "Enrichment", f"Enrichment failed: {ex}")
            task.enrichment = enrichment
            if not matching:
                enrichment.analysis_notes.append(
                    f"No reputation adapter currently supports {ioc_type}; public structural or contextual enrichment was still collected."
                )
            elif not task.results:
                enrichment.analysis_notes.append(
                    "Supporting sources were selected, but none returned a usable result."
                )

            # --- Propagate Structured Intelligence from Adapter Results ---
            if task.enrichment is not None:
                for r in task.results:
                    # 1. urlscan.io -> WebPreviewInfo
                    if r.source == "urlscan.io" and isinstance(r.raw_data, dict):
                        wp_raw = r.raw_data.get("web_preview")
                        if wp_raw and isinstance(wp_raw, dict) and not task.enrichment.web_preview:
                            try:
                                scan_uuid = wp_raw.get("scan_uuid")
                                proxied_url = f"/api/screenshot?scan_id={scan_uuid}" if scan_uuid else None
                                task.enrichment.web_preview = WebPreviewInfo(
                                    screenshot_url=proxied_url,
                                    page_title=wp_raw.get("page_title"),
                                    server=wp_raw.get("server"),
                                    language=wp_raw.get("language"),
                                    domain_age_days=wp_raw.get("domain_age_days"),
                                    tls_issuer=wp_raw.get("tls_issuer"),
                                    tls_valid_days=wp_raw.get("tls_valid_days"),
                                    asn_name=wp_raw.get("asn_name"),
                                    detected_brands=wp_raw.get("detected_brands", []) or [],
                                    detected_technologies=wp_raw.get("detected_technologies", []) or [],
                                    mime_type=wp_raw.get("mime_type"),
                                    scan_uuid=scan_uuid,
                                )
                            except Exception as exc:
                                logger.debug("Failed to construct WebPreviewInfo: %s", exc)

                    # 2. Hudson Rock -> InfostealerIntel
                    if r.source == "Hudson Rock" and isinstance(r.raw_data, dict):
                        if not task.enrichment.infostealer:
                            try:
                                families_raw = r.raw_data.get("stealer_families", {})
                                families_dict = families_raw if isinstance(families_raw, dict) else {}
                                dates_list = r.raw_data.get("dates_compromised", [])
                                date_range = f"{dates_list[0]} to {dates_list[-1]}" if dates_list else None
                                task.enrichment.infostealer = InfostealerIntel(
                                    total_employee_compromises=r.raw_data.get("total_infections", 0) or 0,
                                    total_client_compromises=r.raw_data.get("total_user_services", 0) or 0,
                                    top_corporate_services=r.raw_data.get("top_corporate_services", []) or [],
                                    top_external_services=r.raw_data.get("top_external_services", []) or [],
                                    stealer_families=families_dict,
                                    password_strength_weak_pct=r.raw_data.get("password_strength_weak_pct"),
                                    password_strength_strong_pct=r.raw_data.get("password_strength_strong_pct"),
                                    total_compromised_urls=r.raw_data.get("total_compromised_urls"),
                                    date_range=date_range,
                                )
                            except Exception as exc:
                                logger.debug("Failed to construct InfostealerIntel: %s", exc)

                    # 3. AbuseIPDB -> abuse_reports
                    if r.source == "AbuseIPDB" and isinstance(r.raw_data, dict):
                        reports = r.raw_data.get("reports", []) or []
                        if reports and not task.enrichment.abuse_reports:
                            task.enrichment.abuse_reports = reports[:20]

                    # 4. AlienVault OTX -> malware_urls & associated_hashes
                    if r.source == "AlienVault OTX" and isinstance(r.raw_data, dict):
                        mal_urls = r.raw_data.get("malware_urls", []) or []
                        if mal_urls and not task.enrichment.malware_urls:
                            task.enrichment.malware_urls = mal_urls[:25]
                        assoc_hashes = r.raw_data.get("associated_hashes", []) or []
                        if assoc_hashes and not task.enrichment.associated_hashes:
                            task.enrichment.associated_hashes = assoc_hashes[:15]

            await _update_stage(task, "Enrichment", "done", "Enrichment complete", 1.0)
            await _emit_stage_event(task, "Enrichment", "done", "Enrichment complete", 1.0)

            if ioc_type == "cve" and enrichment and enrichment.cve:
                await _update_stage(task, "CVE Intelligence", "running", "Normalizing CVE enrichment data")
                try:
                    cve_result = normalize_cve_enrichment(enrichment.cve, normalized)
                    task.results.append(cve_result)
                    await _update_stage(task, "CVE Intelligence", "done", "CVE analysis complete", 1.0)
                except Exception as exc:
                    await _update_stage(task, "CVE Intelligence", "error", str(exc)[:80], 1.0)
            else:
                await _update_stage(task, "CVE Intelligence", "skipped", "Not a CVE IOC", 1.0)

            task.status = "scoring"
            task.progress = 85.0
            await _update_stage(task, "Scoring & Relations", "running", "Computing composite score")

            if fp_override:
                task.results.insert(
                    0,
                    NormalizedResult(
                        ioc=normalized, ioc_type=task.ioc_type or "unknown",
                        source="User Feedback",
                        verdict="clean", raw_score=0.0, confidence="high",
                        tags=["user_marked_fp"],
                    ),
                )

            final_assessment = aggregate_evidence(
                normalized,
                task.ioc_type or "unknown",
                task.results,
                enrichment,
            )
            final_assessment = _finalize_assessment(task, final_assessment)
            if fp_override:
                final_assessment.final_verdict = "benign"
                final_assessment.confidence = "high"
                final_assessment.normalized_score = 0.0
                final_assessment.reason = "The IOC was explicitly marked false positive by an analyst."
                final_assessment.analyst_review_recommended = False
                final_assessment.needs_review = False
            composite = compute_composite(
                task.results,
                ioc=normalized,
                ioc_type=task.ioc_type or "unknown",
                enrichment=enrichment,
                assessment=final_assessment,
            )
            logger.info(
                "IOC assessment ioc=%s verdict=%s score=%s evidence_strength=%s coverage=%s needs_review=%s",
                normalized, final_assessment.final_verdict, final_assessment.normalized_score,
                final_assessment.evidence_strength, final_assessment.coverage,
                final_assessment.needs_review,
            )
            for observation in final_assessment.provider_breakdown:
                logger.info(
                    "Evidence contribution source=%s state=%s provider_verdict=%s normalized_verdict=%s contribution=%s weight=%s signal=%s",
                    observation.source, observation.execution_state, observation.provider_verdict,
                    observation.normalized_verdict, observation.contribution,
                    observation.weight, observation.normalized_signal,
                )

            relationships = []
            relationship_keys: set[str] = set()
            for r in task.results:
                for rel_ioc, rel_type in r.related_iocs:
                    rel_ioc_clean = str(rel_ioc).strip()
                    if not rel_ioc_clean or rel_ioc_clean.lower() in {"other", "unknown", "none", "n/a", "null"}:
                        continue
                    fingerprint = f"{normalized}|{rel_ioc_clean.lower()}|{rel_type.lower()}"
                    if fingerprint in relationship_keys:
                        continue
                    relationship_keys.add(fingerprint)
                    relationships.append({
                        "source_ioc": normalized,
                        "target_ioc": rel_ioc_clean,
                        "relationship": rel_type,
                        "via_source": r.source,
                        "confidence": "medium",
                        "evidence_type": "reference" if rel_type == "reference" else "observed_relationship",
                        "observed_at": (r.observed_at or r.source_timestamp).isoformat() if (r.observed_at or r.source_timestamp) else None,
                        "provenance": r.provenance_family or r.source,
                        "relationship_fingerprint": fingerprint,
                        "evidence_hash": r.evidence_hash,
                    })

            enrichment_rels = enrichment.relationships if enrichment and enrichment.relationships else []
            for relationship in enrichment_rels:
                fingerprint = relationship.get("relationship_fingerprint") or f"{relationship.get('source_ioc', normalized)}|{relationship.get('target_ioc', '')}|{relationship.get('relationship', '')}".lower()
                if fingerprint not in relationship_keys:
                    relationship_keys.add(fingerprint)
                    relationship["relationship_fingerprint"] = fingerprint
                    relationships.append(relationship)

            task.composite = composite
            task.final_assessment = final_assessment
            task.final_assessment.relationships = relationships
            task.provider_health = final_assessment.provider_health
            task.relationships = relationships
            await _update_stage(task, "Scoring & Relations", "done", "Analysis complete", 1.0)

            task.executive_summary = generate_executive_summary(
                LookupResponse(
                    input=task.ioc_value,
                    normalized=task.normalized,
                    ioc_type=task.ioc_type or "unknown",
                    composite=composite,
                    final_assessment=final_assessment,
                    provider_health=task.provider_health,
                    enrichment=task.enrichment or EnrichmentData(),
                    results=task.results,
                    relationships=relationships,
                )
            )

            task.status = "done"
            task.progress = 100.0
            await _emit_done_event(task)

    except asyncio.CancelledError:
        task.status = "cancelled"
        task.error = "Analysis cancelled"
        task.progress = 100.0
        logger.info("Analysis %s cancelled", tid)
        await _emit_done_event(task)
    except Exception as e:
        task.status = "error"
        task.error = str(e)
        task.progress = 100.0

    with _dict_lock:
        _tasks[tid] = task
    async with _lock:
        if cache is not None:
            await cache.save_task(tid, task.to_dict(), TASK_TTL)
            if task.status == "done" and task.ioc_type:
                await cache.set(
                    cache_key("save", task.ioc_type, task.normalized),
                    {"task_id": tid},
                    TASK_TTL,
                )

    if task.status == "done" and task.normalized:
        try:
            from app.backend.database import async_session, upsert_lookup_result
            from app.backend.models import IOC
            from sqlalchemy import select
            async with async_session() as session:
                val = task.normalized
                ioc_type = task.ioc_type or "unknown"
                existing = await session.execute(select(IOC).where(IOC.value == val))
                ioc_obj = existing.scalar_one_or_none()
                if not ioc_obj:
                    ioc_obj = IOC(value=val, ioc_type=ioc_type)
                    session.add(ioc_obj)
                    await session.flush()
                score = getattr(task.composite, "score", 0.0) if task.composite else 0.0
                verdict = getattr(task.composite, "verdict", "unknown") if task.composite else "unknown"
                confidence = getattr(task.composite, "confidence", "low") if task.composite else "low"
                await upsert_lookup_result(
                    session,
                    ioc_id=ioc_obj.id,
                    task_id=tid,
                    composite_score=score,
                    composite_verdict=verdict,
                    composite_confidence=confidence,
                    full_response=json.dumps(task_response_payload(task), default=str),
                    source_count=len(task.results),
                )
        except Exception as exc:
            logger.debug("Failed to auto-persist task %s to SQLite: %s", tid, exc)

    if task.status == "done" and task.normalized:
        try:
            from app.backend.webhooks import queue_lookup_dispatch

            assessment = task.final_assessment
            verdict = (
                assessment.final_verdict
                if assessment is not None
                else getattr(task.composite, "verdict", "unknown")
            )
            score = getattr(task.composite, "score", 0.0) if task.composite else 0.0
            await queue_lookup_dispatch(tid, task.normalized, verdict, score)
        except Exception as exc:
            logger.debug("Webhook completion dispatch skipped for task %s: %s", tid, exc)

    _unregister_running(tid)
    return task


def get_task(task_id: str) -> Optional[AnalysisTask]:
    with _dict_lock:
        task = _tasks.get(task_id)
    if task is not None:
        return task
    return None


async def get_task_redis(task_id: str) -> Optional[AnalysisTask]:
    with _dict_lock:
        task = _tasks.get(task_id)
    if task is not None:
        return task
    if cache is not None:
        try:
            data = await cache.get_task(task_id)
            if data is not None:
                with _dict_lock:
                    _tasks[task_id] = AnalysisTask.from_dict(data)
                    return _tasks[task_id]
        except Exception as exc:
            logger.debug("get_task_redis(%s) cache read failed: %s", task_id, exc)
    return None


async def cleanup_old_tasks(max_age: float = 3600):
    now = time.time()
    with _dict_lock:
        to_remove = [tid for tid, t in _tasks.items() if now - t.created_at > max_age]
        for tid in to_remove:
            _tasks.pop(tid, None)
            _task_queues.pop(tid, None)


# --- SSE streaming ---

SSE_QUEUE_MAXSIZE = 500


def get_task_queue(task_id: str) -> asyncio.Queue:
    with _dict_lock:
        if task_id not in _task_queues:
            _task_queues[task_id] = asyncio.Queue(maxsize=SSE_QUEUE_MAXSIZE)
        return _task_queues[task_id]


def cleanup_task_queue(task_id: str):
    with _dict_lock:
        _task_queues.pop(task_id, None)


async def _emit_event(task_id: str, event: str, data: dict):
    with _dict_lock:
        queue = _task_queues.get(task_id)
    if queue is None:
        return
    try:
        queue.put_nowait((event, data))
    except asyncio.QueueFull:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            queue.put_nowait((event, data))
        except asyncio.QueueFull:
            pass


async def _emit_stage_event(task: AnalysisTask, stage_name: str, status: str, message: str = "", progress: float = 0.0):
    await _emit_event(task.task_id, "stage", {
        "name": stage_name, "status": status, "message": message, "progress": progress,
    })


async def _emit_result_event(task: AnalysisTask, result: NormalizedResult):
    await _emit_event(task.task_id, "result", {
        "source": result.source, "verdict": result.verdict, "score": result.raw_score,
    })


async def _emit_error_event(task: AnalysisTask, stage_name: str, message: str):
    await _emit_event(task.task_id, "task_error", {
        "stage": stage_name, "message": message,
    })


async def _emit_done_event(task: AnalysisTask):
    await _emit_event(task.task_id, "done", {
        "status": task.status, "progress": task.progress,
    })


def _register_running(task_id: str):
    current = asyncio.current_task()
    if current is not None:
        with _dict_lock:
            _running_tasks[task_id] = current


def _unregister_running(task_id: str):
    with _dict_lock:
        _running_tasks.pop(task_id, None)


def cancel_analysis(task_id: str) -> bool:
    """Cancel only the running analysis for this task (used on client disconnect)."""
    with _dict_lock:
        running = _running_tasks.get(task_id)
    if running is None:
        return False
    running.cancel()
    return True
