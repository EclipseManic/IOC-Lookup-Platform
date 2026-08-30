import asyncio
import csv
import io
import json
import re
import time
import uuid
from typing import Optional

from app.backend.classifier import classify_ioc, normalize_ioc, refang
from app.backend.adapters.base import NormalizedResult, ProviderHealth
from app.backend.config import settings
from app.backend.pipeline import AnalysisTask, run_analysis
from app.backend.scorer import aggregate_evidence


BATCH_SEMAPHORE_LIMIT = settings.batch_semaphore_limit
IOC_TIMEOUT = settings.ioc_timeout

_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def normalize_batch_iocs(values: list[str]) -> list[str]:
    """Normalize pasted entries and split lines containing several IOCs."""
    normalized: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = refang(value.strip().strip("`'\"<>()[],;"))
        if value:
            # Domains, hashes, and addresses are case-insensitive for lookup
            # purposes.  Canonicalizing the de-duplication key prevents the
            # same provider request from being repeated for ``EXAMPLE.COM``
            # and ``example.com`` while retaining the first display value.
            info = normalize_ioc(value)
            if not info.valid:
                # A batch is an execution request, not a raw text archive.
                # Dropping unrecognizable cells prevents CSV/JSON metadata
                # such as "clean", scores, provider names, or headers from
                # becoming fake IOC tasks that fail later in the pipeline.
                return
            value = info.value
            key = info.identity_key
            if key in seen:
                return
            seen.add(key)
            normalized.append(value)

    for raw in values:
        line = refang(str(raw).strip())
        if not line:
            continue
        links = _MARKDOWN_LINK_RE.findall(line)
        if links:
            for link in links:
                add(link)
            line = _MARKDOWN_LINK_RE.sub(" ", line)
        if classify_ioc(line) != "unknown":
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
    def __init__(self, batch_id: str, iocs: list[str]):
        self.batch_id = batch_id
        self.iocs = iocs
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
_batch_queues: dict[str, asyncio.Queue] = {}
_BATCH_TASKS_MAX = 100


def start_batch_analysis(
    iocs: list[str],
    *,
    fp_overrides: Optional[set[str]] = None,
    timeout: Optional[float] = None,
    concurrency: Optional[int] = None,
    batch_timeout: Optional[float] = None,
) -> BatchTask:
    """Create a batch immediately and run it in the background."""
    iocs = normalize_batch_iocs(iocs)
    limit = concurrency if concurrency is not None else BATCH_SEMAPHORE_LIMIT
    if limit < 1:
        raise ValueError("concurrency must be >= 1")
    for raw in iocs:
        if len(refang(str(raw).strip())) > 2048:
            raise ValueError(f"IOC value too long: {refang(str(raw).strip())[:64]}…")

    bid = uuid.uuid4().hex[:12]
    batch = BatchTask(bid, iocs)
    _batch_tasks[bid] = batch
    get_batch_queue(bid)
    _remove_oldest_batch()
    async def _run_queued_batch() -> None:
        try:
            await run_batch_analysis(
                iocs,
                batch_id=bid,
                fp_overrides=fp_overrides,
                timeout=timeout,
                concurrency=concurrency,
                batch_timeout=batch_timeout,
            )
        except Exception as exc:
            batch.status = "error"
            batch.error = str(exc)[:200]
            batch.progress = 100.0
            await _emit_batch_event(bid, "batch_error", {"batch_id": bid, "error": batch.error})

    asyncio.create_task(_run_queued_batch())
    return batch


async def run_batch_analysis(iocs: list[str], batch_id: Optional[str] = None,
                             fp_overrides: Optional[set[str]] = None,
                             timeout: Optional[float] = None,
                             concurrency: Optional[int] = None,
                             batch_timeout: Optional[float] = None) -> BatchTask:
    iocs = normalize_batch_iocs(iocs)
    for raw in iocs:
        if len(refang(str(raw).strip())) > 2048:
            raise ValueError(f"IOC value too long: {refang(str(raw).strip())[:64]}…")
    bid = batch_id or uuid.uuid4().hex[:12]
    bt = _batch_tasks.get(bid) or BatchTask(bid, iocs)
    bt.status = "running"
    _batch_tasks[bid] = bt
    get_batch_queue(bid)
    _remove_oldest_batch()
    await _emit_batch_event(bid, "batch_started", {"batch_id": bid, "total": bt.total})

    ioc_timeout = timeout if timeout is not None else IOC_TIMEOUT
    batch_deadline = time.monotonic() + max(0.1, float(batch_timeout if batch_timeout is not None else getattr(settings, "batch_deadline_seconds", 300)))
    limit = concurrency if concurrency is not None else BATCH_SEMAPHORE_LIMIT
    if limit < 1:
        raise ValueError("concurrency must be >= 1")
    sem = asyncio.Semaphore(limit)

    async def run_one(ioc: str):
        async with sem:
            bt.active_iocs.append(ioc)
            try:
                fp = False
                if fp_overrides:
                    fp = refang(ioc.strip()) in fp_overrides
                task = await asyncio.wait_for(
                    run_analysis(ioc.strip(), task_id=f"{bid}-{uuid.uuid4().hex[:12]}", fp_override=fp),
                    timeout=ioc_timeout,
                )
                # run_analysis records cancellation and returns an error task
                # so it can persist its state.  Convert that batch-local
                # cancellation into an auditable timeout lookup instead of
                # leaving the IOC with zero provider accounting.
                if task.status == "error" and task.final_assessment is None:
                    value = refang(ioc.strip())
                    ioc_type = classify_ioc(value)
                    timed_out = "timed out" in (task.error or "").lower() or "cancelled" in (task.error or "").lower()
                    state = "timeout" if timed_out else "invalid_request"
                    tag = "timeout" if timed_out else "invalid_request"
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
                    ioc_value=ioc.strip(),
                    status="error",
                    error=str(exc)[:200],
                )
                value = refang(ioc.strip())
                ioc_type = classify_ioc(value)
                task.final_assessment = aggregate_evidence(value, ioc_type, [])
                task.final_assessment.assessment_status = "error"
                task.final_assessment.review_reasons = ["Batch worker failed before provider assessment"]
                return task
            finally:
                if ioc in bt.active_iocs:
                    bt.active_iocs.remove(ioc)

    # Consume tasks as they finish instead of awaiting one large gather before
    # publishing anything.  The old implementation kept ``completed`` and
    # all provider metrics at zero for the entire batch, making polling look
    # stuck even while work was progressing.
    runners = {asyncio.create_task(run_one(ioc)): ioc for ioc in iocs}
    pending = set(runners)
    while pending:
        done, pending = await asyncio.wait(pending, timeout=max(0.0, batch_deadline - time.monotonic()), return_when=asyncio.FIRST_COMPLETED)
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
        if pending and time.monotonic() >= batch_deadline:
            for runner in pending:
                runner.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for runner in pending:
                value = runners[runner]
                normalized_value = refang(value.strip())
                ioc_type = classify_ioc(normalized_value)
                task = AnalysisTask(task_id=f"{bid}-{uuid.uuid4().hex[:12]}", ioc_value=value, normalized=normalized_value, ioc_type=ioc_type, status="error", error="Batch deadline exceeded")
                task.assessment_domain = aggregate_evidence(normalized_value, ioc_type, []).assessment_domain
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
    await _emit_batch_event(bid, "batch_done", {"batch_id": bid, "progress": 100.0})
    return bt


def get_batch(batch_id: str) -> Optional[BatchTask]:
    return _batch_tasks.get(batch_id)


# --- Batch SSE streaming ---

BATCH_QUEUE_MAXSIZE = 500


def get_batch_queue(batch_id: str) -> asyncio.Queue:
    if batch_id not in _batch_queues:
        _batch_queues[batch_id] = asyncio.Queue(maxsize=BATCH_QUEUE_MAXSIZE)
    return _batch_queues[batch_id]


def cleanup_batch_queue(batch_id: str):
    _batch_queues.pop(batch_id, None)


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
        _batch_tasks.pop(oldest_key, None)
        _batch_queues.pop(oldest_key, None)


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
        if domain_bucket:
            summary["unknown"] += 1
        elif verdict == "benign":
            summary["clean"] += 1
            assessment_distribution["benign"] += 1
        elif verdict == "clean":
            summary["clean"] += 1
            assessment_distribution["benign"] += 1
        elif verdict in {"malicious", "suspicious", "unknown"}:
            summary[verdict] += 1
            assessment_distribution[verdict] += 1
        else:
            summary["error"] += 1
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
                r_dict["_ioc"] = task.ioc_value
                all_results.append(r_dict)
                if state != "not_applicable":
                    execution_health["applicable_provider_lookups"] += 1
                if state == "success": execution_health["successful"] += 1
                elif state == "not_found": execution_health["not_found"] += 1
                elif state == "rate_limited": execution_health["rate_limited"] += 1
                elif state in {"timeout", "aborted_due_to_ioc_deadline", "batch_deadline_exceeded"}: execution_health["timeout"] += 1
                elif state != "success": execution_health["errors"] += 1
                if r_dict.get("cached"): execution_health["cached"] += 1

        if task.final_assessment and task.final_assessment.assessment_status == "partial":
            execution_health["partial"] += 1
        if task.final_assessment and task.final_assessment.assessment_status == "batch_deadline_exceeded":
            execution_health["batch_deadline_exceeded"] += 1

        if task.relationships:
            all_relations.extend(task.relationships)
        if task.final_assessment:
            assessments.append(task.final_assessment.model_dump(mode="json"))

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
