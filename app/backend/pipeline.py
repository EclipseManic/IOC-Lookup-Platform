import asyncio
import ipaddress
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from app.backend.cache import CACHE_TTL, DEFAULT_TTL, TASK_TTL, CacheLayer, cache_key
from app.backend.webhooks import dispatch_lookup_complete
from app.backend.http_client import get_client, get_timeout
from app.backend.rate_limiter import RateLimiter
from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.alienvault_otx import AlienVaultOTXAdapter
from app.backend.adapters.base import (
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
from app.backend.adapters.shodan import ShodanAdapter
from app.backend.adapters.spur_us import SpurUsAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.triage import TriageAdapter
from app.backend.adapters.urlhaus import URLHausAdapter
from app.backend.adapters.urlscan_io import UrlScanIOAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.classifier import classify_ioc, is_search_based, refang
from app.backend.enrichment import enrich, normalize_cve_enrichment
from app.backend.executive_summary import generate_executive_summary
from app.backend.scorer import compute_composite

def _init_adapters():
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
    ]
    for a in adapters:
        a.set_client(client)
    return adapters

ADAPTERS = _init_adapters()


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
        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress": self.progress,
            "stages": [{"name": s.name, "status": s.status, "message": s.message, "progress": s.progress} for s in self.stages],
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "error": self.error,
            "executive_summary": self.executive_summary,
            "created_at": self.created_at,
        }


_tasks: dict[str, AnalysisTask] = {}
_task_queues: dict[str, asyncio.Queue] = {}
_lock = asyncio.Lock()

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


async def _update_stage(task: AnalysisTask, stage_name: str, status: str, message: str = "", progress: float = 0.0):
    for s in task.stages:
        if s.name == stage_name:
            s.status = status
            if message:
                s.message = message
            if progress:
                s.progress = progress
            break


async def run_analysis(ioc_value: str, task_id: Optional[str] = None) -> AnalysisTask:
    tid = task_id or uuid.uuid4().hex[:12]
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
        StageInfo("CVE Intelligence"),
        StageInfo("Enrichment"),
        StageInfo("Scoring & Relations"),
    ]

    task = AnalysisTask(task_id=tid, ioc_value=ioc_value, stages=stages, status="pending")

    async with _lock:
        _tasks[tid] = task
        if cache is not None:
            await cache.save_task(tid, task.to_dict(), TASK_TTL)

    try:
        task.status = "classifying"
        task.progress = 2.0
        await _update_stage(task, "Classify & Normalize", "running", "Normalizing IOC value")
        await _emit_stage_event(task, "Classify & Normalize", "running", "Normalizing IOC value")

        normalized = refang(ioc_value.strip())
        if not normalized:
            raise ValueError("Empty IOC after normalization")

        ioc_type = classify_ioc(normalized)
        task.ioc_type = ioc_type
        task.normalized = normalized

        await _update_stage(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)
        await _emit_stage_event(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)

        if ioc_type == "ipv4":
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
                    return task
            except ValueError:
                pass

        from app.backend.adapters.base import is_valid_api_key

        matching = [a for a in ADAPTERS if ioc_type in a.supported_types and not is_search_based(ioc_type)]

        key_filtered = []
        for a in matching:
            key = getattr(a, 'api_key', None)
            if key is not None and not is_valid_api_key(key):
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
        coros = [(a, a.lookup(normalized, ioc_type)) for a in matching]

        result_map: dict[str, NormalizedResult] = {}

        async def run_adapter(adapter, coro):
            stage_name = adapter.name
            ck = cache_key(adapter.name, ioc_type, normalized)

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
                result = await coro
                if isinstance(result, Exception):
                    raise result
                result_map[adapter.name] = result
                adapter._record_success()
                if cache is not None:
                    ttl = CACHE_TTL.get(adapter.name, DEFAULT_TTL)
                    await cache.set(ck, result.model_dump(), ttl)
                await _update_stage(task, stage_name, "done", f"{adapter.name} done", 1.0)
                await _emit_stage_event(task, stage_name, "done", f"{adapter.name} done", 1.0)
                await _emit_result_event(task, result)
            except Exception as ex:
                adapter._record_failure()
                nr = NormalizedResult(
                    ioc=normalized, ioc_type=ioc_type, source=adapter.name,
                    verdict="error", tags=[f"exception: {ex}"],
                )
                result_map[adapter.name] = nr
                await _update_stage(task, stage_name, "error", str(ex)[:80], 1.0)
                await _emit_stage_event(task, stage_name, "error", str(ex)[:80], 1.0)
                await _emit_result_event(task, nr)

            completed = sum(1 for s in task.stages if s.status in ("done", "error", "skipped"))
            total_stages = len(task.stages)
            task.progress = 5.0 + (completed / total_stages) * 55.0 if total_stages > 0 else 60.0

        runners = [run_adapter(a, c) for a, c in coros]
        await asyncio.gather(*runners)

        task.results = [result_map.get(a.name) for a in matching if a.name in result_map]

        task.status = "enriching"
        task.progress = 65.0
        await _update_stage(task, "Enrichment", "running", f"Running type-specific enrichment for {ioc_type}")

        enrichment = EnrichmentData()
        try:
            enrichment = await enrich(normalized, ioc_type)
        except Exception:
            pass
        task.enrichment = enrichment
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
        asyncio.ensure_future(dispatch_lookup_complete(
            tid, task.ioc_value,
            task.composite.verdict if task.composite else "unknown",
            task.composite.score if task.composite else 0,
        ))

    except Exception as e:
        task.status = "error"
        task.error = str(e)
        task.progress = 100.0

    async with _lock:
        _tasks[tid] = task
        if cache is not None:
            await cache.save_task(tid, task.to_dict(), TASK_TTL)

    return task


def get_task(task_id: str) -> Optional[AnalysisTask]:
    task = _tasks.get(task_id)
    if task is not None:
        return task
    return None


async def get_task_redis(task_id: str) -> Optional[AnalysisTask]:
    task = _tasks.get(task_id)
    if task is not None:
        return task
    if cache is not None:
        try:
            data = await cache.get_task(task_id)
            if data is not None:
                _tasks[task_id] = AnalysisTask(**data)
                return _tasks[task_id]
        except Exception:
            pass
    return None


async def cleanup_old_tasks(max_age: float = 3600):
    now = time.time()
    to_remove = [tid for tid, t in _tasks.items() if now - t.created_at > max_age]
    for tid in to_remove:
        _tasks.pop(tid, None)
        _task_queues.pop(tid, None)


# --- SSE streaming ---

def get_task_queue(task_id: str) -> asyncio.Queue:
    if task_id not in _task_queues:
        _task_queues[task_id] = asyncio.Queue()
    return _task_queues[task_id]


async def _emit_event(task_id: str, event: str, data: dict):
    queue = _task_queues.get(task_id)
    if queue is not None:
        await queue.put((event, data))


async def _emit_stage_event(task: AnalysisTask, stage_name: str, status: str, message: str = "", progress: float = 0.0):
    await _emit_event(task.task_id, "stage", {
        "name": stage_name, "status": status, "message": message, "progress": progress,
    })


async def _emit_result_event(task: AnalysisTask, result: NormalizedResult):
    await _emit_event(task.task_id, "result", {
        "source": result.source, "verdict": result.verdict, "score": result.raw_score,
    })


async def _emit_done_event(task: AnalysisTask):
    await _emit_event(task.task_id, "done", {
        "status": task.status, "progress": task.progress,
    })
