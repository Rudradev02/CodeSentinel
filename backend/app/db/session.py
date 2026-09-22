"""Database engine and async session management for CodeSentinel."""

from collections.abc import AsyncGenerator
from typing import Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.app.core.config import get_settings

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine(database_url: Optional[str] = None) -> AsyncEngine:
    """Obtain or initialize the global async SQLAlchemy engine.
    
    Supports both PostgreSQL (production) and SQLite/aiosqlite (local tests).
    """
    global _engine
    if _engine is not None and database_url is None:
        return _engine

    url = database_url or get_settings().DATABASE_URL
    echo = get_settings().DATABASE_ECHO

    engine_kwargs = {"echo": echo}
    if "sqlite" in url:
        # SQLite specific configuration
        engine_kwargs["connect_args"] = {"check_same_thread": False}

    engine = create_async_engine(url, **engine_kwargs)
    if database_url is None:
        _engine = engine
    return engine


def get_session_factory(engine: Optional[AsyncEngine] = None) -> async_sessionmaker[AsyncSession]:
    """Obtain or initialize the async session maker."""
    global _session_factory
    if _session_factory is not None and engine is None:
        return _session_factory

    target_engine = engine or get_engine()
    factory = async_sessionmaker(
        bind=target_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    if engine is None:
        _session_factory = factory
    return factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session within a transaction context."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
