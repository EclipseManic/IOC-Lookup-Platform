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
