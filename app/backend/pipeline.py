import asyncio
import ipaddress
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from app.backend.cache import CACHE_TTL, DEFAULT_TTL, TASK_TTL, CacheLayer, cache_key
from app.backend.config import settings
from app.backend.http_client import get_client, get_timeout
from app.backend.rate_limiter import RateLimiter
from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.alienvault_otx import AlienVaultOTXAdapter
from app.backend.adapters.base import (
    CompositeScore,
    EnrichmentData,
    LookupResponse,
    NormalizedResult,
)
from app.backend.adapters.censys import CensysAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.hybrid_analysis import HybridAnalysisAdapter
from app.backend.adapters.ipinfo import IPinfoAdapter
from app.backend.adapters.malware_bazaar import MalwareBazaarAdapter
from app.backend.adapters.openphish import OpenPhishAdapter
from app.backend.adapters.phish_tank import PhishTankAdapter
from app.backend.adapters.security_trails import SecurityTrailsAdapter
from app.backend.adapters.stop_forum_spam import StopForumSpamAdapter
from app.backend.adapters.shodan import ShodanAdapter
from app.backend.adapters.spur_us import SpurUsAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.triage import TriageAdapter
from app.backend.adapters.urlhaus import URLHausAdapter
from app.backend.adapters.urlscan_io import UrlScanIOAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.classifier import SUPPORTED_IOC_TYPES, classify_ioc, is_search_based, refang
from app.backend.enrichment import enrich, normalize_cve_enrichment
from app.backend.executive_summary import generate_executive_summary
from app.backend.logger import get_logger
from app.backend.scorer import compute_composite

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
        SecurityTrailsAdapter(),
        PhishTankAdapter(),
        OpenPhishAdapter(),
        URLHausAdapter(),
        SpurUsAdapter(),
        TorExitAdapter(),
        CensysAdapter(),
        IPinfoAdapter(),
        StopForumSpamAdapter(),
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
    normalized: str = ""
    results: list[NormalizedResult] = field(default_factory=list)
    composite: Optional[object] = None
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
            "normalized": self.normalized,
            "results": [_dump(r) for r in self.results],
            "composite": _dump(self.composite),
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
        enrichment = EnrichmentData.model_validate(data["enrichment"]) if data.get("enrichment") else None
        return cls(
            task_id=data["task_id"],
            status=data.get("status", "pending"),
            progress=data.get("progress", 0.0),
            stages=stages,
            ioc_value=data.get("ioc_value", ""),
            ioc_type=data.get("ioc_type", ""),
            normalized=data.get("normalized", ""),
            results=results,
            composite=composite,
            enrichment=enrichment,
            relationships=data.get("relationships", []),
            executive_summary=data.get("executive_summary", ""),
            error=data.get("error"),
            created_at=data.get("created_at", time.time()),
        )


_tasks: dict[str, AnalysisTask] = {}
_task_queues: dict[str, asyncio.Queue] = {}
_running_tasks: dict[str, asyncio.Task] = {}
_lock = asyncio.Lock()
_dict_lock = threading.Lock()

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


async def run_analysis(
    ioc_value: str,
    task_id: Optional[str] = None,
    fp_override: bool = False,
    ioc_type_override: str | None = None,
) -> AnalysisTask:
    tid = task_id or uuid.uuid4().hex[:12]
    deadline = time.monotonic() + PIPELINE_TIMEOUT
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
        StageInfo("SecurityTrails"),
        StageInfo("PhishTank"),
        StageInfo("URLhaus"),
        StageInfo("Spur.us"),
        StageInfo("Tor Exit"),
        StageInfo("Censys"),
        StageInfo("IPinfo"),
        StageInfo("StopForumSpam"),
        StageInfo("CVE Intelligence"),
        StageInfo("Enrichment"),
        StageInfo("Scoring & Relations"),
    ]

    task = AnalysisTask(task_id=tid, ioc_value=ioc_value, stages=stages, status="pending")

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

        normalized = refang(ioc_value.strip())
        if not normalized:
            raise ValueError("Empty IOC after normalization")

        ioc_type = ioc_type_override or classify_ioc(normalized)
        if ioc_type not in SUPPORTED_IOC_TYPES:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        task.ioc_type = ioc_type
        task.normalized = normalized

        await _update_stage(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)
        await _emit_stage_event(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)

        if ioc_type in ("ipv4", "ipv6"):
            try:
                addr = ipaddress.ip_address(normalized)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                    private_result = NormalizedResult(
                        ioc=normalized, ioc_type=ioc_type, source="reserved_ip",
                        verdict="unknown", tags=["private_ip", "no_external_lookup"],
                    )
                    task.results = [private_result]
                    task.status = "done"
                    task.progress = 100.0
                    _unregister_running(tid)
                    return task
            except ValueError:
                pass

        from app.backend.adapters.base import is_valid_api_key

        matching = [a for a in ADAPTERS if ioc_type in a.supported_types and not is_search_based(ioc_type)]

        key_filtered = []
        for a in matching:
            if not settings.is_source_enabled(a.name):
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

        result_map: dict[str, NormalizedResult] = {}
        pipeline_timed_out = False

        async def run_adapter(adapter, ioc_value, ioc_type):
            stage_name = adapter.name
            ck = cache_key(adapter.name, ioc_type, ioc_value)

            if cache is not None:
                cached = await cache.get(ck)
                if cached is not None:
                    result = NormalizedResult(**cached)
                    if "cached" not in result.tags:
                        result.tags = list(result.tags or []) + ["cached"]
                    result_map[adapter.name] = result
                    await _update_stage(task, stage_name, "done", f"{adapter.name} (cached)", 1.0)
                    await _emit_stage_event(task, stage_name, "done", f"{adapter.name} (cached)", 1.0)
                    await _emit_result_event(task, result)
                    return

            await _update_stage(task, stage_name, "running", f"Querying {adapter.name}")

            if not adapter._check_circuit():
                nr = NormalizedResult(
                    ioc=normalized, ioc_type=ioc_type, source=adapter.name,
                    verdict="unknown", tags=["circuit_open"],
                )
                result_map[adapter.name] = nr
                await _update_stage(task, stage_name, "skipped", "Circuit breaker open", 1.0)
                await _emit_stage_event(task, stage_name, "skipped", "Circuit breaker open", 1.0)
                await _emit_result_event(task, nr)
                return

            if rate_limiter is not None:
                limit = adapter.rate_limit.requests_per_minute
                allowed = await rate_limiter.acquire_blocking(adapter.name, limit, 60, timeout=30)
                if not allowed:
                    nr = NormalizedResult(
                        ioc=normalized, ioc_type=ioc_type, source=adapter.name,
                        verdict="unknown", tags=["rate_limited"],
                    )
                    result_map[adapter.name] = nr
                    await _update_stage(task, stage_name, "skipped", "Rate limited", 1.0)
                    await _emit_stage_event(task, stage_name, "skipped", "Rate limited", 1.0)
                    await _emit_result_event(task, nr)
                    return

            try:
                remaining = max(1.0, deadline - time.monotonic())
                coro = adapter.lookup(ioc_value, ioc_type)
                result = await asyncio.wait_for(coro, timeout=min(ADAPTER_TIMEOUT, remaining))
                if isinstance(result, Exception):
                    raise result
                result_map[adapter.name] = result
                # Provider errors, auth failures, rate limits, and outages
                # are transient availability states. Never cache them or
                # count them as a successful source call.
                if result.verdict == "error" or result.status == "error":
                    adapter._record_failure()
                else:
                    adapter._record_success()
                if cache is not None and result.verdict != "error" and result.status != "error":
                    ttl = CACHE_TTL.get(adapter.name, DEFAULT_TTL)
                    await cache.set(ck, result.model_dump(mode="json"), ttl)
                stage_status = "error" if result.verdict == "error" or result.status == "error" else "done"
                stage_message = "Unavailable" if stage_status == "error" else f"{adapter.name} done"
                await _update_stage(task, stage_name, stage_status, stage_message, 1.0)
                await _emit_stage_event(task, stage_name, stage_status, stage_message, 1.0)
                await _emit_result_event(task, result)
            except asyncio.TimeoutError:
                adapter._record_failure()
                logger.warning("Adapter %s timed out for %s", adapter.name, normalized)
                nr = NormalizedResult(
                    ioc=normalized, ioc_type=ioc_type, source=adapter.name,
                    verdict="error", tags=["timeout"],
                )
                result_map[adapter.name] = nr
                await _update_stage(task, stage_name, "error", "Timed out", 1.0)
                await _emit_stage_event(task, stage_name, "error", "Timed out", 1.0)
                await _emit_result_event(task, nr)
                await _emit_error_event(task, stage_name, "Adapter timed out")
            except Exception as ex:
                adapter._record_failure()
                error_kind = ex.__class__.__name__
                error_detail = str(ex).strip() or error_kind
                logger.warning("Adapter %s failed for %s: %s", adapter.name, normalized, error_detail)
                nr = NormalizedResult(
                    ioc=normalized, ioc_type=ioc_type, source=adapter.name,
                    verdict="error", tags=["adapter_exception", f"exception_type:{error_kind}"],
                )
                result_map[adapter.name] = nr
                await _update_stage(task, stage_name, "error", f"Provider error ({error_kind})", 1.0)
                await _emit_stage_event(task, stage_name, "error", f"Provider error ({error_kind})", 1.0)
                await _emit_result_event(task, nr)
                await _emit_error_event(task, stage_name, f"Adapter failed: {error_kind}")

            completed = sum(1 for s in task.stages if s.status in ("done", "error", "skipped"))
            total_stages = len(task.stages)
            task.progress = 5.0 + (completed / total_stages) * 55.0 if total_stages > 0 else 60.0

        runners = [
            asyncio.create_task(run_adapter(adapter, value, indicator_type))
            for adapter, value, indicator_type in coros
        ]
        try:
            remaining = max(1.0, deadline - time.monotonic())
            await asyncio.wait_for(asyncio.gather(*runners), timeout=remaining)
        except asyncio.TimeoutError:
            pipeline_timed_out = True
            for runner in runners:
                runner.cancel()
            await asyncio.gather(*runners, return_exceptions=True)
            remaining_stages = [s for s in task.stages if s.status == "running"]
            for s in remaining_stages:
                s.status = "error"
                s.message = "Pipeline timeout"

        if pipeline_timed_out:
            task.results = [result_map.get(a.name) for a in matching if a.name in result_map]
            task.status = "error"
            task.error = "Pipeline timeout exceeded"
            task.progress = 100.0
            logger.warning("Pipeline timed out for %s", normalized)
            await _emit_error_event(task, "Pipeline", "Pipeline timeout exceeded")
            await _emit_done_event(task)
        else:
            task.results = [result_map.get(a.name) for a in matching if a.name in result_map]

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

            composite = compute_composite(task.results)

            if fp_override:
                composite = CompositeScore(
                    score=0.0,
                    verdict="clean",
                    confidence="high",
                    sources_contributing=composite.sources_contributing,
                    source_breakdown=composite.source_breakdown,
                )
                task.results.insert(
                    0,
                    NormalizedResult(
                        ioc=normalized, ioc_type=task.ioc_type or "unknown",
                        source="User Feedback",
                        verdict="clean", raw_score=0.0, confidence="high",
                        tags=["user_marked_fp"],
                    ),
                )

            relationships = []
            for r in task.results:
                for rel_ioc, rel_type in r.related_iocs:
                    relationships.append({
                        "source_ioc": normalized,
                        "target_ioc": rel_ioc,
                        "relationship": rel_type,
                        "via_source": r.source,
                    })

            enrichment_rels = enrichment.relationships if enrichment and enrichment.relationships else []
            relationships.extend(enrichment_rels)

            task.composite = composite
            task.relationships = relationships
            await _update_stage(task, "Scoring & Relations", "done", "Analysis complete", 1.0)

            task.executive_summary = generate_executive_summary(
                LookupResponse(
                    input=task.ioc_value,
                    normalized=task.normalized,
                    ioc_type=task.ioc_type or "unknown",
                    composite=composite,
                    enrichment=task.enrichment or EnrichmentData(),
                    results=task.results,
                    relationships=relationships,
                )
            )

            task.status = "done"
            task.progress = 100.0
            await _emit_done_event(task)

    except asyncio.CancelledError:
        task.status = "error"
        task.error = "Analysis cancelled (client disconnected)"
        task.progress = 100.0
        logger.warning("Analysis %s cancelled (client disconnected)", tid)
        await _emit_error_event(task, "Analysis", "Analysis cancelled (client disconnected)")
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
