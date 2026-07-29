import asyncio
import csv
import io
import json
import uuid
from typing import Optional

from app.backend.pipeline import AnalysisTask, run_analysis


BATCH_SEMAPHORE_LIMIT = 10
IOC_TIMEOUT = 30


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
_semaphore = asyncio.Semaphore(BATCH_SEMAPHORE_LIMIT)


async def run_batch_analysis(iocs: list[str], batch_id: Optional[str] = None) -> BatchTask:
    bid = batch_id or uuid.uuid4().hex[:12]
    bt = BatchTask(bid, iocs)
    bt.status = "running"
    _batch_tasks[bid] = bt

    sem = _semaphore

    async def run_one(ioc: str):
        async with sem:
            try:
                task = await asyncio.wait_for(
                    run_analysis(ioc.strip(), task_id=f"{bid}-{uuid.uuid4().hex[:12]}"),
                    timeout=IOC_TIMEOUT,
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

    for task in results:
        bt.subtasks.append(task)
        bt.completed += 1
        bt.progress = (bt.completed / bt.total) * 100.0

    bt.status = "done"
    bt.progress = 100.0
    return bt


def get_batch(batch_id: str) -> Optional[BatchTask]:
    return _batch_tasks.get(batch_id)


def parse_csv(content: str) -> list[str]:
    reader = csv.reader(io.StringIO(content))
    iocs = []
    for row in reader:
        for cell in row:
            cell = cell.strip()
            if cell:
                iocs.append(cell)
    return iocs


def parse_json(content: str) -> list[str]:
    data = json.loads(content)
    if isinstance(data, list):
        return [str(item).strip() for item in data if str(item).strip()]
    if isinstance(data, dict):
        for key in ("iocs", "indicators", "values", "data"):
            if key in data and isinstance(data[key], list):
                return [str(item).strip() for item in data[key] if str(item).strip()]
        return [str(v).strip() for v in data.values() if str(v).strip()]
    return []


def consolidate_batch_results(batch: BatchTask) -> dict:
    all_results = []
    all_relations = []
    summary = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0, "error": 0}

    for task in batch.subtasks:
        if task.results:
            for r in task.results:
                r_dict = r if isinstance(r, dict) else r.model_dump()
                r_dict["_ioc"] = task.ioc_value
                all_results.append(r_dict)
                if r.verdict in summary:
                    summary[r.verdict] += 1

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
