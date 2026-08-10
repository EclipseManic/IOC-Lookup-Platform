import asyncio
import csv
import io
import json
import time
import uuid
from typing import Optional

from app.backend.classifier import refang
from app.backend.config import settings
from app.backend.pipeline import AnalysisTask, run_analysis


BATCH_SEMAPHORE_LIMIT = settings.batch_semaphore_limit
IOC_TIMEOUT = settings.ioc_timeout


class BatchTask:
    def __init__(self, batch_id: str, iocs: list[str]):
        self.batch_id = batch_id
        self.iocs = iocs
        self.subtasks: list[AnalysisTask] = []
        self.status = "pending"
        self.progress = 0.0
        self.total = len(iocs)
        self.completed = 0
        self.error: Optional[str] = None
        self.created_at = time.time()

    def to_dict(self):
        return {
            "batch_id": self.batch_id,
            "status": self.status,
            "progress": self.progress,
            "total": self.total,
            "completed": self.completed,
            "subtasks": [
                {
                    "task_id": t.task_id,
                    "ioc_value": t.ioc_value,
                    "status": t.status,
                    "progress": t.progress,
                    "error": t.error,
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
) -> BatchTask:
    """Create a batch immediately and run it in the background."""
    limit = concurrency if concurrency is not None else BATCH_SEMAPHORE_LIMIT
    if limit < 1:
        raise ValueError("concurrency must be >= 1")
    for raw in iocs:
        if len(refang(str(raw).strip())) > 2048:
            raise ValueError(f"IOC value too long: {refang(str(raw).strip())[:64]}â€¦")

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
                             concurrency: Optional[int] = None) -> BatchTask:
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
    limit = concurrency if concurrency is not None else BATCH_SEMAPHORE_LIMIT
    if limit < 1:
        raise ValueError("concurrency must be >= 1")
    sem = asyncio.Semaphore(limit)

    async def run_one(ioc: str):
        async with sem:
            try:
                fp = False
                if fp_overrides:
                    fp = refang(ioc.strip()) in fp_overrides
                task = await asyncio.wait_for(
                    run_analysis(ioc.strip(), task_id=f"{bid}-{uuid.uuid4().hex[:12]}", fp_override=fp),
                    timeout=ioc_timeout,
                )
                return task
            except asyncio.TimeoutError:
                tid = f"{bid}-{uuid.uuid4().hex[:12]}"
                task = AnalysisTask(
                    task_id=tid,
                    ioc_value=ioc.strip(),
                    status="error",
                    error="IOC analysis timed out",
                )
                return task
            except Exception as exc:
                tid = f"{bid}-{uuid.uuid4().hex[:12]}"
                task = AnalysisTask(
                    task_id=tid,
                    ioc_value=ioc.strip(),
                    status="error",
                    error=str(exc)[:200],
                )
                return task

    results = await asyncio.gather(*[run_one(ioc) for ioc in iocs], return_exceptions=False)

    for i, task in enumerate(results, start=1):
        bt.subtasks.append(task)
        bt.completed += 1
        bt.progress = (bt.completed / bt.total) * 100.0
        await _emit_batch_event(bid, "progress", {
            "completed": bt.completed,
            "total": bt.total,
            "progress": bt.progress,
            "ioc_value": task.ioc_value,
            "status": task.status,
            "error": task.error,
        })

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

    header = [c.strip().lower() for c in rows[0] if c.strip()]
    header_words = set(w for c in header for w in c.replace("-", "_").split("_"))
    header_keywords = {"ioc", "indicator", "value", "ioc_value", "type", "verdict", "score", "confidence", "source", "note", "malware", "family", "tag"}
    is_header = bool(header) and bool(header_words & header_keywords)

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
    if isinstance(data, dict):
        for key in ("iocs", "indicators", "values", "data"):
            if key in data:
                acc: list[str] = []
                _extract_strings(data[key], acc)
                if acc:
                    return acc
        acc = []
        _extract_strings(list(data.values()), acc)
        return acc
    acc = []
    _extract_strings(data, acc)
    return acc


def consolidate_batch_results(batch: BatchTask) -> dict:
    all_results = []
    all_relations = []
    summary = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0, "error": 0}

    for task in batch.subtasks:
        if task.status == "error":
            verdict = "error"
        elif task.composite:
            verdict = task.composite.verdict
        else:
            verdict = "error"
        if verdict in summary:
            summary[verdict] += 1
        else:
            summary["unknown"] += 1

        if task.results:
            for r in task.results:
                r_dict = r if isinstance(r, dict) else r.model_dump()
                r_dict["_ioc"] = task.ioc_value
                all_results.append(r_dict)

        if task.relationships:
            all_relations.extend(task.relationships)

    return {
        "batch_id": batch.batch_id,
        "total": batch.total,
        "completed": batch.completed,
        "summary": summary,
        "results": all_results,
        "relationships": all_relations,
    }
