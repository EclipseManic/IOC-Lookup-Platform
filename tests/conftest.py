import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Keep the test suite away from the developer's real database. This must be
# configured before any application module imports Settings/database.py.
_TEST_DB_PATH = Path(tempfile.gettempdir()) / f"ioc_platform_pytest_{os.getpid()}.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB_PATH.as_posix()}"


def pytest_sessionstart(session):
    import asyncio

    from app.backend.database import init_db

    asyncio.run(init_db())


def pytest_sessionfinish(session, exitstatus):
    import asyncio

    from app.backend.database import engine

    asyncio.run(engine.dispose())
    for suffix in ("", "-shm", "-wal"):
        try:
            Path(f"{_TEST_DB_PATH}{suffix}").unlink(missing_ok=True)
        except PermissionError:
            # Windows may briefly retain a SQLite handle during interpreter
            # shutdown; the uniquely named file is safe in the temp folder.
            pass
