import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import event, inspect, select, delete, text
from sqlalchemy.exc import OperationalError
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.backend.config import settings
from app.backend.models import Base, IOC, InvestigationIOC, IOCFeedback, LookupResult

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


def _adopt_unversioned_sqlite() -> bool:
    if not _db_url.startswith("sqlite+aiosqlite"):
        return False
    sync_engine = create_engine(_db_url.replace("+aiosqlite", ""))
    try:
        with sync_engine.connect() as connection:
            inspector = inspect(connection)
            tables = set(inspector.get_table_names())
            if not {"iocs", "lookup_results", "investigation_iocs", "investigations"} <= tables:
                return False
            if "alembic_version" in tables:
                versions = connection.execute(text("SELECT version_num FROM alembic_version")).fetchall()
                if versions:
                    return False
            problems: list[str] = []
            for table in Base.metadata.sorted_tables:
                if table.name not in tables:
                    continue
                columns = {column["name"] for column in inspector.get_columns(table.name)}
                for column in table.columns:
                    if column.nullable or column.server_default is not None:
                        continue
                    if column.name not in columns:
                        problems.append(f"{table.name} missing required column {column.name}")
            if problems:
                raise RuntimeError(
                    "Refusing to adopt unversioned SQLite database with an incompatible schema: "
                    + "; ".join(problems)
                )
        Base.metadata.create_all(sync_engine)
        with sync_engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS alembic_version "
                    "(version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
                )
            )
            connection.execute(text("DELETE FROM alembic_version"))
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": "a1f96ea838ee"},
            )
        return True
    finally:
        sync_engine.dispose()


async def init_db():
    if ":memory:" in settings.database_url:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return

    def upgrade() -> None:
        _adopt_unversioned_sqlite()
        environment = os.environ.copy()
        environment["DATABASE_URL"] = settings.database_url
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"Database migration failed: {detail}")

    await asyncio.to_thread(upgrade)


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
    "unable to open database file",
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


async def upsert_lookup_result(
    session: AsyncSession,
    *,
    ioc_id: int,
    task_id: str,
    composite_score: float,
    composite_verdict: str,
    composite_confidence: str,
    full_response: str,
    source_count: int,
    batch_id: str | None = None,
) -> None:
    values = {
        "ioc_id": ioc_id,
        "task_id": task_id,
        "composite_score": composite_score,
        "composite_verdict": composite_verdict,
        "composite_confidence": composite_confidence,
        "full_response": full_response,
        "source_count": source_count,
    }
    if batch_id is not None:
        values["batch_id"] = batch_id
    if session.get_bind().dialect.name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        update_values = {
            key: value for key, value in values.items() if key not in {"task_id", "batch_id"}
        }
        if batch_id is not None:
            update_values["batch_id"] = batch_id
        statement = sqlite_insert(LookupResult).values(**values)
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=["task_id"],
                set_=update_values,
            )
        )
    else:
        result = await session.execute(select(LookupResult).where(LookupResult.task_id == task_id))
        row = result.scalar_one_or_none()
        if row is None:
            session.add(LookupResult(**values))
        else:
            for key, value in values.items():
                if key != "task_id":
                    setattr(row, key, value)
    await retry_sqlite_commit(session)


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
            delete(LookupResult).where(
                LookupResult.created_at < cutoff,
                LookupResult.batch_id.is_(None),
            )
        )
        deleted += result.rowcount or 0

        lookup_references = select(LookupResult.ioc_id).distinct()
        investigation_references = select(InvestigationIOC.ioc_id).distinct()
        feedback_references = select(IOCFeedback.ioc_value).distinct()
        batch_references = select(LookupResult.ioc_id).where(LookupResult.batch_id.is_not(None)).distinct()
        stale_iocs = (
            select(IOC.id)
            .where(IOC.id.not_in(lookup_references))
            .where(IOC.id.not_in(investigation_references))
            .where(IOC.id.not_in(batch_references))
            .where(IOC.value.not_in(feedback_references))
        )
        ioc_rows = (await session.execute(stale_iocs)).scalars().all()
        if ioc_rows:
            await session.execute(delete(IOC).where(IOC.id.in_(ioc_rows)))
            deleted += len(ioc_rows)
        await retry_sqlite_commit(session)
    return deleted
