import sys

sys.path.insert(0, ".")

import asyncio

import pytest
from sqlalchemy.exc import OperationalError

from app.backend.database import _is_sqlite_lock_error, init_db, retry_sqlite_commit


def test_is_sqlite_lock_error_operational():
    exc = OperationalError("SELECT", {}, Exception("database is locked"))
    assert _is_sqlite_lock_error(exc) is True


def test_is_sqlite_lock_error_message():
    exc = RuntimeError("database table is locked")
    assert _is_sqlite_lock_error(exc) is True


def test_is_sqlite_lock_error_unrelated():
    assert _is_sqlite_lock_error(RuntimeError("something else")) is False


class _FakeSession:
    def __init__(self, failures):
        self.failures = failures
        self.commits = 0
        self.rollbacks = 0

    async def commit(self):
        self.commits += 1
        if self.failures:
            self.failures -= 1
            raise OperationalError("commit", {}, Exception("database is locked"))
        return None

    async def rollback(self):
        self.rollbacks += 1


def test_retry_sqlite_commit_succeeds_first_try():
    async def main():
        s = _FakeSession(0)
        await retry_sqlite_commit(s)
        assert s.commits == 1
        assert s.rollbacks == 0

    asyncio.run(main())


def test_retry_sqlite_commit_retries_then_succeeds():
    async def main():
        s = _FakeSession(2)
        await retry_sqlite_commit(s)
        assert s.commits == 3
        assert s.rollbacks == 2

    asyncio.run(main())


def test_retry_sqlite_commit_gives_up_and_raises():
    async def main():
        s = _FakeSession(99)
        with pytest.raises(OperationalError):
            await retry_sqlite_commit(s, attempts=2)
        assert s.commits == 2

    asyncio.run(main())


def test_retry_sqlite_commit_non_lock_raises_immediately():
    class _FailSession(_FakeSession):
        async def commit(self):
            self.commits += 1
            raise OperationalError("commit", {}, Exception("table not found"))

    async def main():
        s = _FailSession(0)
        with pytest.raises(OperationalError):
            await retry_sqlite_commit(s)
        assert s.commits == 1
        assert s.rollbacks == 0

    asyncio.run(main())


def test_init_db():
    asyncio.run(init_db())


def test_cleanup_old_lookups():
    """Old lookups are deleted; recent and orphaned IOCs are handled."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from app.backend.database import async_session, cleanup_old_lookups
    from app.backend.models import IOC, LookupResult

    async def main():
        async with async_session() as session:
            old_ioc = IOC(value="old.example.com", ioc_type="domain")
            recent_ioc = IOC(value="recent.example.com", ioc_type="domain")
            session.add_all([old_ioc, recent_ioc])
            await session.flush()
            old_lookup = LookupResult(
                ioc_id=old_ioc.id,
                task_id="task_old",
                composite_score=0.9,
                composite_verdict="malicious",
            )
            recent_lookup = LookupResult(
                ioc_id=recent_ioc.id,
                task_id="task_recent",
                composite_score=0.1,
                composite_verdict="clean",
            )
            session.add_all([old_lookup, recent_lookup])
            await session.flush()
            old_lookup_id = old_lookup.id
            await session.commit()

        # Backdate the old rows beyond the retention window.
        async with async_session() as session:
            from sqlalchemy import update as sa_update
            cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=400)
            await session.execute(
                sa_update(LookupResult)
                .where(LookupResult.id == old_lookup_id)
                .values(created_at=cutoff)
            )
            await session.commit()

        deleted = await cleanup_old_lookups(days=30)

        async with async_session() as session:
            remaining_lookups = (await session.execute(select(LookupResult))).scalars().all()
            remaining_iocs = (await session.execute(select(IOC))).scalars().all()
            assert deleted >= 1
            assert all(item.id != old_lookup_id for item in remaining_lookups)
            assert any(ioc.value == "recent.example.com" for ioc in remaining_iocs)
            assert all(ioc.value != "old.example.com" for ioc in remaining_iocs)

    asyncio.run(main())


def test_cleanup_old_lookups_zero_days_noop():
    """Zero-day window deletes everything; function returns count, not raises."""
    from app.backend.database import cleanup_old_lookups

    assert asyncio.run(cleanup_old_lookups(days=0)) >= 0
