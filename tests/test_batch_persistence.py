import pytest
import json
from httpx import AsyncClient, ASGITransport
from app.backend.main import app
from app.backend.batch import (
    _batch_tasks,
    get_all_batches_from_db,
    get_batch_from_db,
)
from app.backend.models import BatchRecord
from app.backend.database import async_session


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as c:
        yield c


@pytest.mark.asyncio
async def test_batch_sqlite_persistence_and_endpoints(client):
    batch_id = "test_persistence_batch_123"

    # 1. Directly insert a BatchRecord to test DB persistence layer
    summary_data = {
        "total": 3,
        "completed": 3,
        "malicious": 1,
        "suspicious": 1,
        "clean": 1,
        "unknown": 0,
    }
    result_data = {
        "batch_id": batch_id,
        "status": "completed",
        "total": 3,
        "completed": 3,
        "summary": summary_data,
        "results": [
            {
                "task_id": "sub_1",
                "input": "1.1.1.1",
                "normalized": "1.1.1.1",
                "ioc_type": "ipv4",
                "composite": {
                    "score": 0.0,
                    "verdict": "clean",
                    "confidence": "high",
                    "breakdown": {},
                },
                "sources": [],
                "enrichment": {},
                "relationships": [],
            },
            {
                "task_id": "sub_2",
                "input": "evil.com",
                "normalized": "evil.com",
                "ioc_type": "domain",
                "composite": {
                    "score": 85.0,
                    "verdict": "malicious",
                    "confidence": "high",
                    "breakdown": {},
                },
                "sources": [],
                "enrichment": {},
                "relationships": [],
            },
        ],
    }

    async with async_session() as session:
        record = BatchRecord(
            id=batch_id,
            status="completed",
            total=3,
            completed=3,
            summary_json=json.dumps(summary_data),
            result_json=json.dumps(result_data),
        )
        session.add(record)
        await session.commit()

    # 2. Test get_all_batches_from_db
    batches = await get_all_batches_from_db()
    matching = [b for b in batches if b["batch_id"] == batch_id]
    assert len(matching) == 1
    assert matching[0]["summary"]["malicious"] == 1
    assert matching[0]["summary"]["suspicious"] == 1

    # 3. Test get_batch_from_db
    db_res = await get_batch_from_db(batch_id)
    assert db_res is not None
    assert db_res["batch_id"] == batch_id
    assert len(db_res["results"]) == 2
    assert db_res["results"][0]["ioc"] == "1.1.1.1"
    assert db_res["results"][0]["source"] == "historical_aggregate"
    assert len(db_res["assessments"]) == 2
    assert db_res["assessments"][0]["final_verdict"] == "clean"
    assert db_res["assessments"][1]["final_verdict"] == "malicious"
    assert db_res["assessments"][1]["normalized_score"] == 85.0

    # 4. Test API GET /api/batches
    r = await client.get("/api/batches")
    assert r.status_code == 200
    api_batches = r.json()
    assert any(b["batch_id"] == batch_id for b in api_batches)

    # 5. Ensure batch is NOT in memory _batch_tasks, then test fallback endpoints
    _batch_tasks.pop(batch_id, None)

    # Test GET /api/batch/{id}/result fallback to DB
    r_result = await client.get(f"/api/batch/{batch_id}/result")
    assert r_result.status_code == 200
    assert r_result.json()["batch_id"] == batch_id

    # Test GET /api/batch/{id}/ioc/{ioc} fallback to DB
    r_ioc = await client.get(f"/api/batch/{batch_id}/ioc/evil.com")
    assert r_ioc.status_code == 200
    assert r_ioc.json()["input"] == "evil.com"
    assert r_ioc.json()["composite"]["verdict"] == "malicious"

    # Test IOC not found in batch
    r_ioc_404 = await client.get(f"/api/batch/{batch_id}/ioc/notfound.com")
    assert r_ioc_404.status_code == 404

    # 6. Test API DELETE /api/batch/{batch_id}
    r_del = await client.delete(f"/api/batch/{batch_id}")
    assert r_del.status_code == 200
    assert r_del.json()["status"] == "deleted"

    # Verify deleted from DB
    assert await get_batch_from_db(batch_id) is None

    # Test DELETE non-existent returns 404
    r_del_404 = await client.delete(f"/api/batch/{batch_id}")
    assert r_del_404.status_code == 404


@pytest.mark.asyncio
async def test_legacy_batch_scalar_rows_are_hydrated():
    from app.backend.batch import _normalize_batch_payload

    payload = _normalize_batch_payload(
        {"batch_id": "scalar", "status": "completed", "total": 2, "completed": 2, "results": ["1.2.3.4", "evil.example"]},
        batch_id="scalar",
        status="completed",
        total=2,
        completed=2,
    )
    assert [row["ioc"] for row in payload["results"]] == ["1.2.3.4", "evil.example"]
    assert len(payload["assessments"]) == 2


@pytest.mark.asyncio
async def test_legacy_batch_payload_gets_complete_api_contract():
    batch_id = "test_legacy_batch_contract_456"
    async with async_session() as session:
        session.add(BatchRecord(
            id=batch_id,
            status="completed",
            total=2,
            completed=1,
            summary_json=json.dumps({"malicious": 1}),
            result_json=json.dumps({
                "batch_id": batch_id,
                "status": "completed",
                "total": 2,
                "completed": 1,
                "summary": {"malicious": 1},
            }),
        ))
        await session.commit()

    result = await get_batch_from_db(batch_id)
    assert result is not None
    assert result["expected_lookups"] == 0
    assert result["results"] == []
    assert result["provider_health"] == []
    assert result["relationships"] == []
    assert result["subtasks"] == []
    assert result["summary"] == {
        "malicious": 1,
        "suspicious": 0,
        "clean": 0,
        "unknown": 0,
        "error": 0,
    }
    assert result["progress"] == 100.0

    batches = await get_all_batches_from_db()
    summary = next(item["summary"] for item in batches if item["batch_id"] == batch_id)
    assert summary["suspicious"] == 0

    async with async_session() as session:
        record = await session.get(BatchRecord, batch_id)
        if record is not None:
            await session.delete(record)
            await session.commit()
