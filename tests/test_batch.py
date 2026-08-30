import sys
sys.path.insert(0, ".")

from app.backend.batch import BatchTask, consolidate_batch_results, normalize_batch_iocs, parse_csv, parse_json, get_batch_queue
from app.backend.adapters.base import CompositeScore
from app.backend.pipeline import AnalysisTask


def test_parse_csv_simple():
    iocs = parse_csv("8.8.8.8\ngoogle.com\n1.1.1.1")
    assert len(iocs) == 3
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs


def test_parse_csv_with_commas():
    iocs = parse_csv("8.8.8.8,google.com,1.1.1.1")
    assert len(iocs) == 3


def test_parse_csv_empty():
    iocs = parse_csv("")
    assert iocs == []


def test_parse_csv_whitespace():
    iocs = parse_csv("  8.8.8.8  \n  google.com  ")
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_csv_skips_header_row():
    iocs = parse_csv("ioc,verdict,score\n8.8.8.8,clean,0.0\ngoogle.com,unknown,0.1")
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_csv_single_column_header():
    iocs = parse_csv("ioc\n8.8.8.8\ngoogle.com")
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_csv_data_row_looks_like_header_keyword():
    iocs = parse_csv("8.8.8.8\nvalue\ngoogle.com")
    assert iocs == ["8.8.8.8", "value", "google.com"]


def test_parse_json_array():
    iocs = parse_json('["8.8.8.8", "google.com", "1.1.1.1"]')
    assert len(iocs) == 3


def test_parse_json_object_with_iocs_key():
    iocs = parse_json('{"iocs": ["8.8.8.8", "google.com"]}')
    assert len(iocs) == 2


def test_parse_json_list_of_dicts():
    iocs = parse_json('[{"value": "8.8.8.8"}, {"value": "google.com"}]')
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_json_nested_dict_values():
    iocs = parse_json('{"data": {"iocs": ["8.8.8.8", {"value": "google.com"}]}}')
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs


def test_parse_json_numbers_and_bools():
    iocs = parse_json('["8.8.8.8", 123, true]')
    assert "8.8.8.8" in iocs
    assert "123" in iocs
    assert any(v.lower() == "true" for v in iocs)


def test_parse_json_empty_array():
    iocs = parse_json("[]")
    assert iocs == []


def test_parse_json_indicators_key():
    iocs = parse_json('{"indicators": ["8.8.8.8"]}')
    assert iocs == ["8.8.8.8"]


def test_parse_json_mixed_whitespace():
    iocs = parse_json('["  8.8.8.8  ", "google.com"]')
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs


def test_normalize_batch_iocs_handles_markdown_and_escaped_values():
    values = normalize_batch_iocs([
        "[https://example.com/login](https://example.com/login)",
        r"test\@example.com",
        r"attacker\@example.com CVE-2024-3094 T1059.001 AS15169",
    ])
    assert "https://example.com/login" in values
    assert "test@example.com" in values
    assert "attacker@example.com" in values
    assert "CVE-2024-3094" in values
    assert "T1059.001" in values
    assert "AS15169" in values
    assert all("[" not in value and "]" not in value for value in values)


def test_normalize_batch_iocs_deduplicates_values():
    assert normalize_batch_iocs(["example.com", "example.com"]) == ["example.com"]


def _task(ioc_value, verdict, status="done"):
    t = AnalysisTask(task_id="t", ioc_value=ioc_value, status=status)
    t.composite = CompositeScore(score=0.0, verdict=verdict, confidence="low")
    return t


def test_consolidate_counts_per_ioc_not_per_result():
    bt = BatchTask("b1", ["8.8.8.8", "google.com", "1.1.1.1"])
    t1 = _task("8.8.8.8", "malicious")
    t2 = _task("google.com", "unknown")
    t3 = _task("1.1.1.1", "clean")
    bt.subtasks = [t1, t2, t3]
    bt.completed = 3
    out = consolidate_batch_results(bt)
    assert out["summary"] == {"malicious": 1, "suspicious": 0, "clean": 1, "unknown": 1, "error": 0}


def test_consolidate_error_subtask_counts_as_error():
    bt = BatchTask("b2", ["8.8.8.8"])
    t = AnalysisTask(task_id="t", ioc_value="8.8.8.8", status="error", error="boom")
    bt.subtasks = [t]
    bt.completed = 1
    out = consolidate_batch_results(bt)
    assert out["summary"]["error"] == 1
    assert out["summary"]["malicious"] == 0


def test_batch_queue_emits_events_and_cleans_up():
    import asyncio
    from app.backend import batch as batch_mod

    batch_mod._batch_queues.clear()
    q = get_batch_queue("bq1")
    assert q.maxsize == 500

    async def emit():
        await batch_mod._emit_batch_event("bq1", "progress", {"completed": 1, "total": 2})
        await batch_mod._emit_batch_event("bq1", "batch_done", {"progress": 100.0})

    async def collect():
        return await asyncio.wait_for(q.get(), timeout=2.0)

    async def main():
        import asyncio as aio
        await emit()
        e1 = await collect()
        e2 = await collect()
        assert e1[0] == "progress"
        assert e2[0] == "batch_done"
        batch_mod.cleanup_batch_queue("bq1")
        assert "bq1" not in batch_mod._batch_queues

    asyncio.run(main())


def test_defaults_from_settings():
    from app.backend.config import settings
    from app.backend.batch import BATCH_SEMAPHORE_LIMIT, IOC_TIMEOUT
    assert BATCH_SEMAPHORE_LIMIT == settings.batch_semaphore_limit
    assert IOC_TIMEOUT == settings.ioc_timeout
    assert IOC_TIMEOUT == 60


def test_run_batch_analysis_rejects_invalid_concurrency():
    import asyncio
    from app.backend import batch as batch_mod

    async def main():
        try:
            await batch_mod.run_batch_analysis([], concurrency=0)
        except ValueError as e:
            return str(e)
        return None

    err = asyncio.run(main())
    assert err is not None
    assert "concurrency" in err
