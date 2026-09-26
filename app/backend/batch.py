import asyncio
import csv
import io
import json
import re
import time
import uuid
from typing import Optional

from app.backend.classifier import classify_ioc, normalize_ioc, parse_typed_ioc, refang
from app.backend.adapters.base import NormalizedResult, ProviderHealth
from app.backend.config import settings
from app.backend.logger import get_logger
from app.backend.pipeline import AnalysisTask, run_analysis
from app.backend.scorer import aggregate_evidence


BATCH_SEMAPHORE_LIMIT = settings.batch_semaphore_limit
IOC_TIMEOUT = settings.ioc_timeout
logger = get_logger("batch")

_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_CREDENTIAL_MARKERS = ("password", "passwd", "secret", "admin", "root", "qwerty", "letmein", "welcome", "login", "auth", "user")
_batch_db_lock: Optional[asyncio.Lock] = None


def _looks_like_ambiguous_credential(value: str) -> bool:
    parsed_type, _ = parse_typed_ioc(value)
    if parsed_type is not None:
        return False
    candidate = value.strip().lower()
    if not candidate or classify_ioc(candidate) == "password":
        return False
    if "@" not in candidate and not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", candidate, re.IGNORECASE):
        return False
    return any(marker in candidate for marker in _CREDENTIAL_MARKERS)


def _get_batch_db_lock() -> asyncio.Lock:
    global _batch_db_lock
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if _batch_db_lock is None or (getattr(_batch_db_lock, "_loop", None) is not None and getattr(_batch_db_lock, "_loop", None) is not loop):
        _batch_db_lock = asyncio.Lock()
    return _batch_db_lock


def normalize_batch_iocs(values: list[str]) -> list[str]:
    """Normalize pasted entries and split lines containing several IOCs.

    Returns a list of cleaned IOC values.  Use
    :func:`normalize_batch_iocs_typed` when the caller needs per-IOC
    type overrides extracted from ``type:value`` prefixes.
    """
    return [value for value, _type_override in normalize_batch_iocs_typed(values)]


def normalize_batch_iocs_typed(values: list[str]) -> list[tuple[str, str | None]]:
    """Normalize pasted entries and return ``(value, type_override)`` tuples.

    When a line uses the ``type:value`` syntax (e.g. ``domain:eclipsemanic.me``),
    the detected type is returned as ``type_override`` so downstream callers
    can forward it to :func:`run_analysis` via ``ioc_type_override``.
    """
    normalized: list[tuple[str, str | None]] = []
    seen: set[str] = set()

    def add(value: str, forced_type: str | None = None) -> None:
        value = refang(value.strip().strip("`'\"<>()[],;"))
        if not value:
            return
        if len(refang(value.strip())) > 2048:
            raise ValueError(f"IOC value too long: {refang(value.strip())[:64]}…")
        if _looks_like_ambiguous_credential(value):
            raise ValueError("Ambiguous credential values must use an explicit type prefix")
        # Detect explicit type prefix (e.g. "domain:eclipsemanic.me")
        if forced_type is None:
            parsed_type, parsed_value = parse_typed_ioc(value)
            if parsed_type is not None:
                forced_type = parsed_type
                value = parsed_value
        # Domains, hashes, and addresses are case-insensitive for lookup
        # purposes.  Canonicalizing the de-duplication key prevents the
        # same provider request from being repeated for ``EXAMPLE.COM``
        # and ``example.com`` while retaining the first display value.
        info = normalize_ioc(value, expected_type=forced_type)
        if forced_type == "password_sha1" and not info.valid:
            raise ValueError("Batch password_sha1 values must be 40-character SHA-1 digests")
        if forced_type is None and info.ioc_type in {"service_name", "mutex", "named_pipe", "registry_key"}:
            raise ValueError("Host-artifact values must use an explicit type prefix")
        if not info.valid:
            # A batch is an execution request, not a raw text archive.
            # Dropping unrecognizable cells prevents CSV/JSON metadata
            # such as "clean", scores, provider names, or headers from
            # becoming fake IOC tasks that fail later in the pipeline.
            return
        value = info.value
        if info.ioc_type == "password" and forced_type in {None, "password", "password_sha1"}:
            if not re.fullmatch(r"[a-f0-9]{40}", value, re.IGNORECASE):
                raise ValueError("Batch password values must be pre-hashed with SHA-1")
            forced_type = "password"
            value = value.lower()
            key = f"password:{value}"
        else:
            key = info.identity_key
        if key in seen:
            return
        seen.add(key)
        normalized.append((value, forced_type))

    for raw in values:
        line = refang(str(raw).strip())
        if not line:
            continue
        links = _MARKDOWN_LINK_RE.findall(line)
        if links:
            for link in links:
                add(link)
            line = _MARKDOWN_LINK_RE.sub(" ", line)
        # Check if the line is a recognized IOC (possibly with typed prefix)
        typed, stripped = parse_typed_ioc(line)
        if typed is not None or classify_ioc(line) != "unknown":
            add(line)
            continue
        candidates = re.findall(r"https?://[^\s<>\]\[()]+|[^\s,;]+", line)
        recognized = [c.strip("`'\"<>()[]") for c in candidates
                      if classify_ioc(c.strip("`'\"<>()[]")) != "unknown"]
        if recognized:
            for candidate in recognized:
                add(candidate)
        else:
            add(line)
    return normalized


class BatchTask:
    def __init__(self, batch_id: str, iocs: list[str], type_overrides: dict[str, str] | None = None):
        self.batch_id = batch_id
        self.iocs = iocs
        self.type_overrides: dict[str, str] = type_overrides or {}
        self.subtasks: list[AnalysisTask] = []
        self.status = "pending"
        self.progress = 0.0
        self.total = len(iocs)
        self.completed = 0
        self.active_iocs: list[str] = []
        self.expected_lookups = 0
        self.completed_lookups = 0
        self.successful_lookups = 0
        self.not_found_lookups = 0
        self.rate_limited_lookups = 0
        self.timeout_lookups = 0
        self.failed_lookups = 0
        self.not_applicable_lookups = 0
        self.batch_deadline_exceeded = 0
        self.provider_health: list[ProviderHealth] = []
        self.error: Optional[str] = None
        self.created_at = time.time()
        self.cancel_event = asyncio.Event()
        self.run_task: Optional[asyncio.Task] = None

    def refresh_metrics(self) -> None:
        health: dict[str, ProviderHealth] = {}
        self.expected_lookups = 0
        self.completed_lookups = 0
        self.successful_lookups = 0
        self.not_found_lookups = 0
        self.rate_limited_lookups = 0
        self.timeout_lookups = 0
        self.failed_lookups = 0
        self.not_applicable_lookups = 0
        self.batch_deadline_exceeded = 0
        for task in self.subtasks:
            assessment = task.final_assessment
            if assessment is not None and assessment.assessment_status == "batch_deadline_exceeded":
                self.batch_deadline_exceeded += 1
            if assessment is not None:
                self.expected_lookups += int(assessment.evidence_summary.get("expected_providers", len(task.results)) or 0)
            else:
                self.expected_lookups += len(task.results)
            for raw_result in task.results:
                if isinstance(raw_result, dict):
                    legacy_result = dict(raw_result)
                    legacy_result.setdefault("ioc", task.normalized or task.ioc_value)
                    legacy_result.setdefault("ioc_type", task.ioc_type or "unknown")
                    result = NormalizedResult.model_validate(legacy_result)
                else:
                    result = raw_result
                state = result.execution_state
                self.completed_lookups += 1
                if state == "not_applicable":
                    self.completed_lookups -= 1
                    self.not_applicable_lookups += 1
                elif state == "success":
                    self.successful_lookups += 1
                elif state == "not_found":
                    self.not_found_lookups += 1
                elif state == "rate_limited":
                    self.rate_limited_lookups += 1
                    self.failed_lookups += 1
                elif state == "timeout":
                    self.timeout_lookups += 1
                    self.failed_lookups += 1
                elif state in {"aborted_due_to_ioc_deadline", "batch_deadline_exceeded"}:
                    self.batch_deadline_exceeded += 1
                else:
                    self.failed_lookups += 1
            for item in task.provider_health:
                target = health.setdefault(item.source, ProviderHealth(source=item.source))
                for field_name in (
                    "request_count", "success_count", "failure_count", "rate_limit_count",
                    "timeout_count", "error_count", "unavailable_count", "not_found_count",
                    "invalid_request_count", "retry_count", "cache_hit_count", "cache_miss_count",
                ):
                    setattr(target, field_name, getattr(target, field_name) + getattr(item, field_name))
                target.total_latency_ms += item.total_latency_ms
                target.queue_wait_ms += item.queue_wait_ms
                target.last_execution_state = item.last_execution_state
        for item in health.values():
            denominator = item.request_count + item.cache_hit_count
            item.total_latency_ms = round(item.total_latency_ms, 2)
            item.average_latency_ms = round(item.total_latency_ms / denominator, 2) if denominator else 0.0
            item.average_queue_wait_ms = round(item.queue_wait_ms / max(1, item.request_count), 2)
            item.total_latency = item.total_latency_ms
            item.average_latency = item.average_latency_ms
            item.queue_wait = item.queue_wait_ms
        self.provider_health = sorted(health.values(), key=lambda item: item.source.lower())

    def to_dict(self):
        self.refresh_metrics()
        return {
            "batch_id": self.batch_id,
            "status": self.status,
            "progress": self.progress,
            "total": self.total,
            "completed": self.completed,
            "active_iocs": list(self.active_iocs),
            "expected_lookups": self.expected_lookups,
            "completed_lookups": self.completed_lookups,
            "successful_lookups": self.successful_lookups,
            "not_found_lookups": self.not_found_lookups,
            "rate_limited_lookups": self.rate_limited_lookups,
            "timeout_lookups": self.timeout_lookups,
            "failed_lookups": self.failed_lookups,
            "not_applicable_lookups": self.not_applicable_lookups,
            "batch_deadline_exceeded": self.batch_deadline_exceeded,
            "provider_health": [item.model_dump(mode="json") for item in self.provider_health],
            "subtasks": [
                {
                    "task_id": t.task_id,
                    "ioc_value": t.ioc_value,
                    "status": t.status,
                    "progress": t.progress,
                    "error": t.error,
                    "final_verdict": t.final_assessment.final_verdict if t.final_assessment else None,
                    "confidence": t.final_assessment.confidence if t.final_assessment else None,
                    "coverage": t.final_assessment.coverage if t.final_assessment else None,
                    "needs_review": t.final_assessment.needs_review if t.final_assessment else None,
                }
                for t in self.subtasks
            ],
            "error": self.error,
        }


_batch_tasks: dict[str, BatchTask] = {}
_batch_runners: dict[str, asyncio.Task] = {}
_batch_queues: dict[str, asyncio.Queue] = {}
_batch_queue_refs: dict[str, int] = {}
_persist_tasks: set[asyncio.Task] = set()
_BATCH_TASKS_MAX = 100


def _schedule_batch_persist(batch: BatchTask) -> None:
    task = asyncio.create_task(_persist_batch(batch))
    _persist_tasks.add(task)

    def done(completed: asyncio.Task) -> None:
        _persist_tasks.discard(completed)
        if not completed.cancelled():
            completed.exception()

    task.add_done_callback(done)


async def shutdown_batch_tasks() -> None:
    runners = list(_batch_runners.values())
    for runner in runners:
        runner.cancel()
    if runners:
        await asyncio.gather(*runners, return_exceptions=True)
    _batch_runners.clear()
    tasks = list(_persist_tasks)
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _persist_tasks.clear()


def start_batch_analysis(
    iocs: list[str],
    *,
    fp_overrides: Optional[set[str]] = None,
    timeout: Optional[float] = None,
    concurrency: Optional[int] = None,
    batch_timeout: Optional[float] = None,
) -> BatchTask:
    """Create a batch immediately and run it in the background."""
    typed_pairs = normalize_batch_iocs_typed(iocs)
    clean_iocs = [value for value, _t in typed_pairs]
    type_overrides = {value: t for value, t in typed_pairs if t is not None}
    requested_limit = concurrency if concurrency is not None else BATCH_SEMAPHORE_LIMIT
    limit = min(requested_limit, BATCH_SEMAPHORE_LIMIT)
    if limit < 1:
        raise ValueError("concurrency must be >= 1")
    if not clean_iocs:
        raise ValueError("No valid IOCs supplied")
    if len(clean_iocs) > settings.max_batch_iocs:
        raise ValueError(f"Maximum {settings.max_batch_iocs} valid IOCs per batch")
    for raw in clean_iocs:
        if len(refang(str(raw).strip())) > 2048:
            raise ValueError(f"IOC value too long: {refang(str(raw).strip())[:64]}…")

    bid = uuid.uuid4().hex[:12]
    batch = BatchTask(bid, clean_iocs, type_overrides=type_overrides)
    _batch_tasks[bid] = batch
    get_batch_queue(bid)
    _remove_oldest_batch()
    # Immediately persist initial batch state to SQLite so it exists even if interrupted

    async def _run_queued_batch() -> None:
        try:
            await run_batch_analysis(
                iocs,
                batch_id=bid,
                fp_overrides=fp_overrides,
                timeout=timeout,
                concurrency=concurrency,
                batch_timeout=batch_timeout,
                type_overrides=type_overrides,
            )
        except Exception as exc:
            batch.status = "error"
            batch.error = str(exc)[:200]
            batch.progress = 100.0
            await _emit_batch_event(bid, "batch_error", {"batch_id": bid, "error": batch.error})
            await _persist_batch(batch)

    runner = asyncio.create_task(_run_queued_batch())
    batch.run_task = runner
    runner.add_done_callback(lambda task: _batch_runners.pop(batch.batch_id, None))
    _batch_runners[batch.batch_id] = runner
    return batch


async def run_batch_analysis(iocs: list[str], batch_id: Optional[str] = None,
                             fp_overrides: Optional[set[str]] = None,
                             timeout: Optional[float] = None,
                             concurrency: Optional[int] = None,
                             batch_timeout: Optional[float] = None,
                             type_overrides: Optional[dict[str, str]] = None) -> BatchTask:
    typed_pairs = normalize_batch_iocs_typed(iocs)
    clean_iocs = [value for value, _t in typed_pairs]
    resolved_overrides = type_overrides or {value: t for value, t in typed_pairs if t is not None}
    for raw in clean_iocs:
        if len(refang(str(raw).strip())) > 2048:
            raise ValueError(f"IOC value too long: {refang(str(raw).strip())[:64]}…")
    bid = batch_id or uuid.uuid4().hex[:12]
    bt = _batch_tasks.get(bid) or BatchTask(bid, clean_iocs, type_overrides=resolved_overrides)
    bt.status = "running"
    _batch_tasks[bid] = bt
    get_batch_queue(bid)
    _remove_oldest_batch()
    await _emit_batch_event(bid, "batch_started", {"batch_id": bid, "total": bt.total})

    ioc_timeout = timeout if timeout is not None else IOC_TIMEOUT
    batch_deadline = time.monotonic() + max(0.1, float(batch_timeout if batch_timeout is not None else getattr(settings, "batch_deadline_seconds", 300)))
    requested_limit = concurrency if concurrency is not None else BATCH_SEMAPHORE_LIMIT
    limit = min(requested_limit, BATCH_SEMAPHORE_LIMIT)
    if limit < 1:
        raise ValueError("concurrency must be >= 1")
    sem = asyncio.Semaphore(limit)

    async def run_one(ioc: str):
        clean_val = ioc.strip()
        ioc_type_override = resolved_overrides.get(clean_val)
        if not ioc_type_override:
            parsed_type, parsed_val = parse_typed_ioc(clean_val)
            if parsed_type is not None:
                ioc_type_override = parsed_type
                clean_val = parsed_val
        async with sem:
            bt.active_iocs.append(clean_val)
            try:
                fp = False
                if fp_overrides:
                    fp = refang(clean_val) in fp_overrides
                kwargs = {"task_id": f"{bid}-{uuid.uuid4().hex[:12]}", "fp_override": fp}
                if ioc_type_override is not None:
                    kwargs["ioc_type_override"] = ioc_type_override
                if ioc_type_override == "password":
                    kwargs["password_prehashed"] = bool(re.fullmatch(r"[a-f0-9]{40}", clean_val, re.IGNORECASE))
                task = await asyncio.wait_for(
                    run_analysis(clean_val, **kwargs),
                    timeout=ioc_timeout,
                )
                if task.status == "error" and task.final_assessment is None:
                    value = refang(clean_val)
                    ioc_type = ioc_type_override or classify_ioc(value)
                    task.results = []
                    task.final_assessment = aggregate_evidence(value, ioc_type, [])
                    task.final_assessment.assessment_status = "unavailable"
                    task.final_assessment.review_reasons = ["IOC analysis did not finish before its deadline"]
                    task.final_assessment.reason = "IOC analysis did not finish before its deadline; no provider verdict was generated."
                    task.error = task.error or "IOC analysis timed out"
                return task
            except asyncio.TimeoutError:
                tid = f"{bid}-{uuid.uuid4().hex[:12]}"
                task = AnalysisTask(
                    task_id=tid,
                    ioc_value=ioc.strip(),
                    status="error",
                    error="IOC analysis timed out",
                )
                task.final_assessment = aggregate_evidence(refang(ioc.strip()), classify_ioc(refang(ioc.strip())), [])
                task.final_assessment.assessment_status = "unavailable"
                task.final_assessment.review_reasons = ["IOC analysis did not finish before its deadline"]
                task.final_assessment.reason = "IOC analysis did not finish before its deadline; no provider verdict was generated."
                return task
            except Exception as exc:
                tid = f"{bid}-{uuid.uuid4().hex[:12]}"
                task = AnalysisTask(
                    task_id=tid,
                    ioc_value=clean_val,
                    status="error",
                    error=str(exc)[:200],
                )
                value = refang(clean_val)
                ioc_type = ioc_type_override or classify_ioc(value)
                task.final_assessment = aggregate_evidence(value, ioc_type, [])
                task.final_assessment.assessment_status = "error"
                task.final_assessment.review_reasons = ["Batch worker failed before provider assessment"]
                return task
            finally:
                if clean_val in bt.active_iocs:
                    bt.active_iocs.remove(clean_val)

    runners = {asyncio.create_task(run_one(ioc)): ioc for ioc in clean_iocs}
    pending = set(runners)
    cancelled = False
    try:
        while pending:
            if bt.cancel_event.is_set():
                cancelled = True
                break
            remaining = max(0.0, batch_deadline - time.monotonic())
            if remaining <= 0:
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for completed_task in done:
                task = await completed_task
                bt.subtasks.append(task)
                bt.completed += 1
                bt.progress = (bt.completed / bt.total) * 100.0
                bt.refresh_metrics()
                await _emit_batch_event(bid, "progress", {
                    "completed": bt.completed, "total": bt.total, "progress": bt.progress,
                    "ioc_value": task.ioc_value, "status": task.status, "error": task.error,
                    "completed_lookups": bt.completed_lookups, "expected_lookups": bt.expected_lookups,
                    "successful_lookups": bt.successful_lookups, "rate_limited_lookups": bt.rate_limited_lookups,
                    "timeout_lookups": bt.timeout_lookups, "failed_lookups": bt.failed_lookups,
                })
                await _persist_batch(bt)
            if bt.cancel_event.is_set():
                cancelled = True
                break
    except asyncio.CancelledError:
        cancelled = True

    if cancelled or bt.cancel_event.is_set():
        for runner in pending:
            runner.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for runner in pending:
            value = runners[runner]
            normalized_value = refang(value.strip())
            parsed_type, parsed_val = parse_typed_ioc(normalized_value)
            if parsed_type is not None:
                normalized_value = parsed_val
                ioc_type = parsed_type
            else:
                ioc_type = resolved_overrides.get(normalized_value) or classify_ioc(normalized_value)
            task = AnalysisTask(
                task_id=f"{bid}-{uuid.uuid4().hex[:12]}",
                ioc_value=normalized_value,
                normalized=normalized_value,
                ioc_type=ioc_type,
                status="error",
                error="Batch cancelled",
            )
            task.final_assessment = aggregate_evidence(normalized_value, ioc_type, [])
            task.final_assessment.assessment_status = "cancelled"
            task.final_assessment.review_reasons = ["Batch cancelled before IOC analysis completed"]
            task.final_assessment.reason = "Batch cancelled; this IOC was not completed and has no provider verdict."
            bt.subtasks.append(task)
            bt.completed += 1
        bt.status = "cancelled"
        bt.error = "Batch cancelled"
        bt.progress = 100.0
        bt.refresh_metrics()
        await _emit_batch_event(bid, "batch_done", {"batch_id": bid, "status": bt.status, "progress": 100.0})
        await _persist_batch(bt)
        return bt

    for runner in pending:
        runner.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    for runner in pending:
        value = runners[runner]
        normalized_value = refang(value.strip())
        parsed_type, parsed_val = parse_typed_ioc(normalized_value)
        if parsed_type is not None:
            normalized_value = parsed_val
            ioc_type = parsed_type
        else:
            ioc_type = resolved_overrides.get(normalized_value) or classify_ioc(normalized_value)
        task = AnalysisTask(
            task_id=f"{bid}-{uuid.uuid4().hex[:12]}",
            ioc_value=normalized_value,
            normalized=normalized_value,
            ioc_type=ioc_type,
            status="error",
            error="Batch deadline exceeded",
        )
        task.final_assessment = aggregate_evidence(normalized_value, ioc_type, [])
        task.final_assessment.assessment_status = "batch_deadline_exceeded"
        task.final_assessment.review_reasons = ["Batch deadline exceeded before IOC analysis completed"]
        task.final_assessment.reason = "Batch deadline exceeded; this IOC was not analyzed and has no provider verdict."
        bt.subtasks.append(task)
        bt.completed += 1
    pending.clear()

    bt.subtasks.sort(key=lambda task: ((task.normalized or task.ioc_value).lower(), task.ioc_type))
    bt.status = "done"
    bt.progress = 100.0
    bt.refresh_metrics()
    await _emit_batch_event(bid, "batch_done", {"batch_id": bid, "status": bt.status, "progress": 100.0})
    await _persist_batch(bt)
    return bt


def get_batch(batch_id: str) -> Optional[BatchTask]:
    return _batch_tasks.get(batch_id)


def discard_batch(batch_id: str) -> None:
    _batch_tasks.pop(batch_id, None)
    _batch_runners.pop(batch_id, None)
    cleanup_batch_queue(batch_id)


# --- Batch SSE streaming ---

BATCH_QUEUE_MAXSIZE = 500


def get_batch_queue(batch_id: str) -> asyncio.Queue:
    if batch_id not in _batch_queues:
        _batch_queues[batch_id] = asyncio.Queue(maxsize=BATCH_QUEUE_MAXSIZE)
    return _batch_queues[batch_id]


def acquire_batch_queue(batch_id: str) -> asyncio.Queue:
    queue = get_batch_queue(batch_id)
    _batch_queue_refs[batch_id] = _batch_queue_refs.get(batch_id, 0) + 1
    return queue


def release_batch_queue(batch_id: str) -> None:
    remaining = max(0, _batch_queue_refs.get(batch_id, 0) - 1)
    if remaining:
        _batch_queue_refs[batch_id] = remaining
    else:
        _batch_queue_refs.pop(batch_id, None)
        cleanup_batch_queue(batch_id)


def cleanup_batch_queue(batch_id: str):
    _batch_queues.pop(batch_id, None)
    _batch_queue_refs.pop(batch_id, None)


async def _emit_batch_event(batch_id: str, event: str, data: dict):
    queue = _batch_queues.get(batch_id)
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


def _remove_oldest_batch():
    while len(_batch_tasks) > _BATCH_TASKS_MAX:
        oldest_key = min(_batch_tasks, key=lambda k: _batch_tasks[k].created_at)
        oldest = _batch_tasks.get(oldest_key)
        if oldest and oldest.status in {"pending", "running"}:
            oldest.cancel_event.set()
        runner = _batch_runners.get(oldest_key)
        if runner is not None and not runner.done():
            runner.cancel()
        _batch_tasks.pop(oldest_key, None)
        _batch_queues.pop(oldest_key, None)



async def _persist_batch(bt: BatchTask, *, required: bool = False) -> None:
    """Save or update a batch in SQLite so it survives server restarts, and persist its IOCs."""
    async with _get_batch_db_lock():
        try:
            from app.backend.database import async_session, retry_sqlite_commit
            from app.backend.models import BatchRecord, IOC
            from sqlalchemy import select

            consolidated = _normalize_batch_payload(
                consolidate_batch_results(bt),
                batch_id=bt.batch_id,
                status=bt.status,
                total=bt.total,
                completed=bt.completed,
                error=bt.error,
            )
            summary = json.dumps(consolidated.get("summary", {}), default=str)
            result_json = json.dumps(consolidated, default=str)
            async with async_session() as session:
                existing = await session.execute(select(BatchRecord).where(BatchRecord.id == bt.batch_id))
                record = existing.scalar_one_or_none()
                if record is None:
                    record = BatchRecord(
                        id=bt.batch_id,
                        status=bt.status,
                        total=bt.total,
                        completed=bt.completed,
                        summary_json=summary,
                        result_json=result_json,
                        error=bt.error,
                    )
                    session.add(record)
                else:
                    record.status = bt.status
                    record.total = bt.total
                    record.completed = bt.completed
                    record.summary_json = summary
                    record.result_json = result_json
                    record.error = bt.error
                await retry_sqlite_commit(session)

            try:
                from app.backend.database import upsert_lookup_result
                from app.backend.pipeline import task_response_payload
                async with async_session() as session:
                    for subtask in bt.subtasks:
                        if subtask.status != "done":
                            continue
                        val = subtask.normalized or subtask.ioc_value
                        if not val:
                            continue
                        ioc_type = subtask.ioc_type or "unknown"
                        score = getattr(subtask.composite, "score", 0.0) if subtask.composite else 0.0
                        verdict = getattr(subtask.composite, "verdict", "unknown") if subtask.composite else "unknown"
                        confidence = getattr(subtask.composite, "confidence", "low") if subtask.composite else "low"
                        ioc_obj = (await session.execute(select(IOC).where(IOC.value == val))).scalar_one_or_none()
                        if not ioc_obj:
                            ioc_obj = IOC(value=val, ioc_type=ioc_type)
                            session.add(ioc_obj)
                            await session.flush()
                        await upsert_lookup_result(
                            session,
                            ioc_id=ioc_obj.id,
                            task_id=subtask.task_id,
                            composite_score=score,
                            composite_verdict=verdict,
                            composite_confidence=confidence,
                            full_response=json.dumps(task_response_payload(subtask), default=str),
                            source_count=len(subtask.results),
                            batch_id=bt.batch_id,
                        )
            except Exception as sub_exc:
                logger.warning("Subtask IOC persistence skipped for batch %s: %s", getattr(bt, "batch_id", "unknown"), type(sub_exc).__name__)
        except Exception as exc:
            logger.warning("Failed to persist batch %s to DB: %s", getattr(bt, "batch_id", "unknown"), type(exc).__name__)
            if required:
                raise


_BATCH_COUNTER_DEFAULTS = {
    "expected_lookups": 0,
    "completed_lookups": 0,
    "successful_lookups": 0,
    "not_found_lookups": 0,
    "rate_limited_lookups": 0,
    "timeout_lookups": 0,
    "failed_lookups": 0,
    "not_applicable_lookups": 0,
    "batch_deadline_exceeded": 0,
}
_BATCH_SUMMARY_DEFAULTS = {
    "malicious": 0,
    "suspicious": 0,
    "clean": 0,
    "unknown": 0,
    "error": 0,
}


def _legacy_batch_row(row: dict) -> tuple[list[dict], dict | None]:
    ioc = str(row.get("normalized") or row.get("input") or row.get("ioc") or "").strip()
    if not ioc:
        return [], None
    ioc_type = str(row.get("ioc_type") or "unknown")
    composite = row.get("composite") if isinstance(row.get("composite"), dict) else {}
    verdict = str(composite.get("verdict") or row.get("verdict") or "unknown")
    confidence = str(composite.get("confidence") or row.get("confidence") or "low")
    try:
        score = float(composite.get("score", row.get("score", 0)) or 0)
    except (TypeError, ValueError):
        score = 0.0
    task_id = row.get("task_id")
    hydrated: list[dict] = []
    sources = row.get("sources") if isinstance(row.get("sources"), list) else []
    for source in sources:
        if not isinstance(source, dict):
            continue
        item = dict(source)
        item.setdefault("ioc", ioc)
        item.setdefault("_ioc", ioc)
        item.setdefault("ioc_type", ioc_type)
        if task_id:
            item.setdefault("task_id", task_id)
        hydrated.append(item)
    if not hydrated:
        hydrated.append({
            **row,
            "ioc": ioc,
            "_ioc": ioc,
            "input": ioc,
            "normalized": ioc,
            "composite": composite,
            "ioc_type": ioc_type,
            "task_id": task_id,
            "source": "historical_aggregate",
            "status": "success",
            "execution_state": "success",
            "verdict": verdict,
            "provider_verdict": verdict,
            "normalized_verdict": verdict,
            "raw_score": score / 100 if score > 1 else score,
            "confidence": confidence,
        })
    assessment = {
        "ioc": ioc,
        "normalized_ioc": ioc,
        "ioc_type": ioc_type,
        "task_id": task_id,
        "assessment_domain": "ioc_reputation",
        "final_verdict": verdict,
        "confidence": confidence,
        "normalized_score": score,
        "risk_score": score,
        "evidence_strength": 0,
        "coverage": 0,
        "needs_review": True,
        "assessment_status": "partial",
        "review_reasons": ["Historical batch record predates per-IOC assessment storage."],
        "evidence_counts": {},
        "cache_status": "unknown",
        "evidence_summary": {},
        "provider_breakdown": [],
        "provider_plan": [],
        "provider_health": [],
        "malicious_sources": [],
        "suspicious_sources": [],
        "clean_sources": [],
        "unknown_sources": [],
        "not_found_sources": [],
        "rate_limited_sources": [],
        "unavailable_sources": [],
        "error_sources": [],
        "strongest_evidence": [],
        "supporting_evidence": [],
        "conflicting_evidence": [],
        "context": [],
        "malware_families": [],
        "mitre_attck": [],
        "relationships": [],
        "reason": "Historical aggregate score restored from a legacy batch record.",
        "analyst_review_recommended": True,
    }
    return hydrated, assessment


def _hydrate_legacy_batch_payload(result: dict) -> dict:
    rows = result.get("results")
    if not isinstance(rows, list):
        return result
    hydrated: list[dict] = []
    assessments = result.get("assessments") if isinstance(result.get("assessments"), list) else []
    synthesized: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if isinstance(row, str):
            items, assessment = _legacy_batch_row({"normalized": row})
            hydrated.extend(items)
            if assessment is not None:
                key = (str(assessment["normalized_ioc"]).lower(), str(assessment["ioc_type"]))
                if key not in seen:
                    seen.add(key)
                    synthesized.append(assessment)
            continue
        if not isinstance(row, dict):
            continue
        if row.get("ioc") or row.get("_ioc"):
            hydrated.append(row)
            continue
        items, assessment = _legacy_batch_row(row)
        hydrated.extend(items)
        if assessment is not None:
            key = (str(assessment["normalized_ioc"]).lower(), str(assessment["ioc_type"]))
            if key not in seen:
                seen.add(key)
                synthesized.append(assessment)
    result["results"] = hydrated
    if not assessments:
        result["assessments"] = synthesized
    return result


def _normalize_batch_payload(payload: object, *, batch_id: str, status: str, total: int, completed: int, error: str | None = None) -> dict:
    result = dict(payload) if isinstance(payload, dict) else {}
    result["batch_id"] = result.get("batch_id") or batch_id
    result["status"] = status or result.get("status") or "unknown"
    result["total"] = int(total) if isinstance(total, int) else int(result.get("total") or 0)
    result["completed"] = int(completed) if isinstance(completed, int) else int(result.get("completed") or 0)
    for key, default in _BATCH_COUNTER_DEFAULTS.items():
        value = result.get(key)
        result[key] = int(value) if isinstance(value, int) else default
    summary = result.get("summary")
    result["summary"] = {
        **_BATCH_SUMMARY_DEFAULTS,
        **(summary if isinstance(summary, dict) else {}),
    }
    for key in ("results", "relationships", "assessments", "active_iocs", "subtasks", "provider_health"):
        if not isinstance(result.get(key), list):
            result[key] = []
    result = _hydrate_legacy_batch_payload(result)
    result["progress"] = float(result.get("progress", 100.0 if result["status"] in {"done", "completed", "cancelled"} else 0.0) or 0.0)
    result["error"] = error if error is not None else result.get("error")
    return result


async def get_all_batches_from_db() -> list[dict]:
    """Return lightweight batch summaries from SQLite, newest first."""
    from app.backend.database import async_session
    from app.backend.models import BatchRecord
    from sqlalchemy import select
    async with async_session() as session:
        stmt = select(BatchRecord).order_by(BatchRecord.created_at.desc()).limit(200)
        result = await session.execute(stmt)
        records = result.scalars().all()
        batches = []
        for r in records:
            try:
                summary = json.loads(r.summary_json or "{}")
            except (TypeError, ValueError):
                summary = {}
            summary = {
                **_BATCH_SUMMARY_DEFAULTS,
                **(summary if isinstance(summary, dict) else {}),
            }
            batches.append({
                "batch_id": r.id,
                "status": r.status,
                "total": r.total,
                "completed": r.completed,
                "summary": summary,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            })
        return batches


async def get_batch_from_db(batch_id: str) -> dict | None:
    """Load full batch result JSON from SQLite."""
    from app.backend.database import async_session
    from app.backend.models import BatchRecord
    from sqlalchemy import select
    async with async_session() as session:
        stmt = select(BatchRecord).where(BatchRecord.id == batch_id)
        result = await session.execute(stmt)
        record = result.scalar_one_or_none()
    if record is None:
        return None
    try:
        result = json.loads(record.result_json or "{}")
    except (TypeError, ValueError):
        result = {}
    return _normalize_batch_payload(
        result,
        batch_id=record.id,
        status=record.status,
        total=record.total,
        completed=record.completed,
        error=record.error,
    )



async def delete_batch_from_db(batch_id: str) -> bool:
    """Delete a batch from SQLite. Returns True if found and deleted."""
    from app.backend.database import async_session
    from app.backend.models import BatchRecord, LookupResult
    from sqlalchemy import delete
    async with async_session() as session:
        await session.execute(delete(LookupResult).where(LookupResult.batch_id == batch_id))
        result = await session.execute(delete(BatchRecord).where(BatchRecord.id == batch_id))
        await session.commit()
        return result.rowcount > 0


def parse_csv(content: str) -> list[str]:
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    if not rows:
        return []

    header = [c.strip().lower() for c in rows[0]]
    header_words = set(w for c in header for w in c.replace("-", "_").split("_"))
    header_keywords = {"ioc", "indicator", "value", "ioc_value", "type", "verdict", "score", "confidence", "source", "note", "malware", "family", "tag"}
    is_header = bool(header) and bool(header_words & header_keywords)

    if is_header:
        indicator_columns = [
            index for index, name in enumerate(header)
            if name in {"ioc", "ioc_value", "indicator", "indicator_value", "value"}
        ]
        if indicator_columns:
            return [
                row[index].strip()
                for row in rows[1:]
                for index in indicator_columns
                if index < len(row) and row[index].strip()
            ]

    iocs = []
    data_rows = rows[1:] if is_header else rows
    for row in data_rows:
        for cell in row:
            cell = cell.strip()
            if cell:
                iocs.append(cell)
    return iocs


def _extract_strings(value, acc: list[str]):
    if isinstance(value, str):
        s = value.strip()
        if s:
            acc.append(s)
    elif isinstance(value, list):
        for item in value:
            _extract_strings(item, acc)
    elif isinstance(value, dict):
        for v in value.values():
            _extract_strings(v, acc)
    elif value is not None:
        s = str(value).strip()
        if s:
            acc.append(s)


def parse_json(content: str) -> list[str]:
    data = json.loads(content)

    def extract(value) -> list[str]:
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, list):
            output: list[str] = []
            for item in value:
                output.extend(extract(item))
            return output
        if isinstance(value, dict):
            for key in ("ioc", "ioc_value", "indicator", "indicator_value", "value"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    return [candidate]
            output: list[str] = []
            for key in ("iocs", "indicators", "values", "data", "results"):
                if key in value:
                    output.extend(extract(value[key]))
            if output:
                return output
            return []
        if isinstance(value, (int, float, bool)):
            return [str(value)]
        return []

    if isinstance(data, dict):
        for key in ("iocs", "indicators", "values", "data"):
            if key in data:
                acc = extract(data[key])
                if acc:
                    return acc
        # Preserve the longstanding ``{"label": "IOC"}`` input shape, but
        # only when every top-level value is scalar. This deliberately avoids
        # walking assessment/result objects where scores, provider names, and
        # status fields must never become synthetic IOC tasks.
        values = list(data.values())
        if values and all(not isinstance(value, (dict, list)) for value in values):
            return extract(values)
        return extract(data)
    return extract(data)


def consolidate_batch_results(batch: BatchTask) -> dict:
    batch.refresh_metrics()
    all_results = []
    all_relations = []
    assessments = []
    # ``summary`` keeps the legacy reputation buckets for existing clients.
    # Domain-aware reporting lives beside it so vulnerability and ATT&CK
    # records cannot be mistaken for reputation verdicts.
    summary = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0, "error": 0}
    assessment_distribution = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0, "context_only": 0, "vulnerability": 0, "attack_technique": 0}
    execution_health = {"applicable_provider_lookups": 0, "successful": 0, "not_found": 0, "rate_limited": 0, "timeout": 0, "errors": 0, "not_applicable": 0, "cached": 0, "partial": 0, "batch_deadline_exceeded": 0}

    for task in batch.subtasks:
        verdict = task.final_assessment.final_verdict if task.final_assessment else (task.composite.verdict if task.composite else ("error" if task.status == "error" else "unknown"))
        domain_bucket = None
        if task.final_assessment and task.final_assessment.assessment_domain == "vulnerability":
            assessment_distribution["vulnerability"] += 1
            domain_bucket = "vulnerability"
        elif task.final_assessment and task.final_assessment.assessment_domain == "attack_technique":
            assessment_distribution["attack_technique"] += 1
            domain_bucket = "attack_technique"
        elif verdict == "context_only":
            assessment_distribution["context_only"] += 1
            domain_bucket = "context_only"
        if domain_bucket == "vulnerability":
            if verdict in {"critical", "high"}:
                summary["malicious"] += 1
            elif verdict in {"medium", "low"}:
                summary["suspicious"] += 1
            else:
                summary["unknown"] += 1
        elif domain_bucket in {"attack_technique", "context_only"}:
            summary["unknown"] += 1
        elif verdict in {"breached", "compromised"}:
            summary["malicious"] += 1
            assessment_distribution["malicious"] += 1
        elif verdict in {"not_breached", "uncompromised", "benign", "clean", "harmless", "whitelisted"}:
            summary["clean"] += 1
            assessment_distribution["benign"] += 1
        elif verdict in {"malicious", "suspicious", "unknown"}:
            summary[verdict] += 1
            assessment_distribution[verdict] += 1
        elif task.status == "error":
            summary["error"] += 1
            assessment_distribution["unknown"] += 1
        else:
            summary["unknown"] += 1
            assessment_distribution["unknown"] += 1

        if task.results:
            for r in task.results:
                r_dict = r if isinstance(r, dict) else r.model_dump()
                state = r.execution_state if hasattr(r, "execution_state") else r_dict.get("execution_state", "error")
                # Keep the plan/count visible on the assessment, but do not
                # emit one synthetic N/A result for every unsupported source.
                if state == "not_applicable":
                    execution_health["not_applicable"] += 1
                    continue
                r_dict.setdefault("ioc", task.ioc_value)
                r_dict.setdefault("task_id", task.task_id)
                all_results.append(r_dict)
                if state != "not_applicable":
                    execution_health["applicable_provider_lookups"] += 1
                if state == "success":
                    execution_health["successful"] += 1
                elif state == "not_found":
                    execution_health["not_found"] += 1
                elif state == "rate_limited":
                    execution_health["rate_limited"] += 1
                elif state in {"timeout", "aborted_due_to_ioc_deadline", "batch_deadline_exceeded"}:
                    execution_health["timeout"] += 1
                elif state != "success":
                    execution_health["errors"] += 1
                if r_dict.get("cached"):
                    execution_health["cached"] += 1

        if task.final_assessment and task.final_assessment.assessment_status == "partial":
            execution_health["partial"] += 1
        if task.final_assessment and task.final_assessment.assessment_status == "batch_deadline_exceeded":
            execution_health["batch_deadline_exceeded"] += 1

        if task.relationships:
            all_relations.extend(task.relationships)
        if task.final_assessment:
            assessment_data = task.final_assessment.model_dump(mode="json")
            assessment_data["task_id"] = task.task_id
            assessments.append(assessment_data)

    return {
        "batch_id": batch.batch_id,
        "total": batch.total,
        "completed": batch.completed,
        "summary": summary,
        "assessment_distribution": assessment_distribution,
        "execution_health": execution_health,
        "results": all_results,
        "relationships": all_relations,
        "assessments": assessments,
        "expected_lookups": batch.expected_lookups,
        "completed_lookups": batch.completed_lookups,
        "successful_lookups": batch.successful_lookups,
        "not_found_lookups": batch.not_found_lookups,
        "rate_limited_lookups": batch.rate_limited_lookups,
        "timeout_lookups": batch.timeout_lookups,
        "failed_lookups": batch.failed_lookups,
        "provider_health": [item.model_dump(mode="json") for item in batch.provider_health],
    }
