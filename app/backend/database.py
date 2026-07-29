import os
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.backend.config import settings
from app.backend.models import Base

# Ensure data directory exists
db_path = settings.database_url
if db_path.startswith("sqlite"):
    path_part = db_path.split("///")[-1]
    if path_part and "/" in path_part:
        dir_path = Path(path_part).parent
        dir_path.mkdir(parents=True, exist_ok=True)

engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
