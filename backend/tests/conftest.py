    """Pytest fixtures for CodeSentinel backend and database testing."""

import asyncio
from collections.abc import AsyncGenerator
from pathlib import Path
import tempfile
import pytest
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from fastapi.testclient import TestClient

from backend.app.db.base import Base
import backend.app.models  # Register all models
from backend.app.db.session import get_db
from backend.app.main import app

FIXTURE_PATH = str(Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project")


class AsyncTestContext:
    """Manages an isolated SQLite test database and synchronous execution of async coroutines."""

    def __init__(self, db_file: str):
        self.db_file = db_file
        self.url = f"sqlite+aiosqlite:///{db_file}"
        self.engine: AsyncEngine = create_async_engine(
            self.url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        self.session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    def init_tables(self) -> None:
        async def _init():
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        asyncio.run(_init())

    def cleanup(self) -> None:
        async def _clean():
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            await self.engine.dispose()
        asyncio.run(_clean())

    def run(self, coro):
        """Execute a coroutine synchronously within a clean event loop."""
        return asyncio.run(coro)

    async def get_session(self) -> AsyncSession:
        return self.session_factory()


@pytest.fixture
def test_ctx():
    """Provide an isolated database context for unit tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name

    ctx = AsyncTestContext(tmp_path)
    ctx.init_tables()
    yield ctx
    ctx.cleanup()
    try:
        Path(tmp_path).unlink(missing_ok=True)
    except Exception:
        pass


@pytest.fixture
def client_with_db(test_ctx: AsyncTestContext):
    """Provide a TestClient with get_db overridden to use the isolated test database."""
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with test_ctx.session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
