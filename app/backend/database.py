import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import event, select, delete
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.backend.config import settings
from app.backend.models import Base, IOC, LookupResult

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

_db_url = settings.database_url
if _db_url.startswith("sqlite"):
    prefix, _, rel_path = _db_url.partition("///")
    if rel_path and not Path(rel_path).is_absolute():
        abs_path = PROJECT_ROOT / rel_path
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        _db_url = f"{prefix}///{abs_path.as_posix()}"
    elif rel_path:
        path_part = rel_path
        if "/" in path_part:
            Path(path_part).parent.mkdir(parents=True, exist_ok=True)

_pool_kwargs = {"pool_pre_ping": True}
_connect_args = {}
if _db_url.startswith("sqlite"):
    # WU-0.2: keep writes from failing under concurrency — wait on the lock
    # instead of raising "database is locked" immediately.
    _connect_args = {"timeout": 30}
else:
    _pool_kwargs["pool_size"] = 5
    _pool_kwargs["max_overflow"] = 10

engine = create_async_engine(
    _db_url,
    echo=settings.debug,
    connect_args=_connect_args,
    **_pool_kwargs,
)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if not _db_url.startswith("sqlite"):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=True)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


_SQLITE_LOCKED_MESSAGES = (
    "database is locked",
    "database table is locked",
    "attempt to write a readonly database",
    "disk I/O error",
)


def _is_sqlite_lock_error(exc: BaseException) -> bool:
    if not _db_url.startswith("sqlite"):
        return False
    if isinstance(exc, OperationalError):
        for msg in _SQLITE_LOCKED_MESSAGES:
            if msg in str(exc.orig):
                return True
    return any(msg in str(exc).lower() for msg in _SQLITE_LOCKED_MESSAGES)


async def retry_sqlite_commit(session: AsyncSession, *, attempts: int = 3, delay: float = 0.05) -> None:
    """Commit with retry for SQLite lock contention.

    WU-0.2: a commit can still hit "database is locked" under concurrent
    writers even with WAL + busy_timeout. Roll back and retry the commit
    with a short backoff instead of surfacing a 500.
    """
    for attempt in range(1, attempts + 1):
        try:
            await session.commit()
            return
        except OperationalError as exc:
            if not _is_sqlite_lock_error(exc) or attempt == attempts:
                raise
            await session.rollback()
            await asyncio.sleep(delay * attempt)


async def cleanup_old_lookups(days: int | None = None) -> int:
    """Delete lookup results older than ``HISTORY_RETENTION_DAYS``.

    Retention is config-driven (``HISTORY_RETENTION_DAYS``, default 30).
    Lookup results that fall out of the retention window are removed, and
    IOC rows that no longer reference any lookup result are pruned as well.

    Returns the number of rows deleted (lookups + pruned IOCs).
    """
    retention_days = days if days is not None else settings.history_retention_days
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=retention_days)
    deleted = 0

    async with async_session() as session:
        result = await session.execute(
            delete(LookupResult).where(LookupResult.created_at < cutoff)
        )
        deleted += result.rowcount or 0
        # Prune IOCs that are no longer referenced by any lookup result.
        referenced = select(LookupResult.ioc_id).distinct()
        stale_iocs = (
            select(IOC.id)
            .where(IOC.id.not_in(referenced))
        )
        ioc_rows = (await session.execute(stale_iocs)).scalars().all()
        if ioc_rows:
            await session.execute(delete(IOC).where(IOC.id.in_(ioc_rows)))
            deleted += len(ioc_rows)
        await retry_sqlite_commit(session)
    return deleted
