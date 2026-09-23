"""Synchronous database engine and session management for Celery worker processes."""

from collections.abc import Generator
from contextlib import contextmanager
from typing import Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import get_settings

_sync_engine: Optional[Engine] = None
_sync_session_factory: Optional[sessionmaker[Session]] = None


def get_sync_engine(database_url: Optional[str] = None) -> Engine:
    """Obtain or initialize the global synchronous SQLAlchemy engine."""
    global _sync_engine
    if _sync_engine is not None and database_url is None:
        return _sync_engine

    url = database_url or get_settings().SYNC_DATABASE_URL
    echo = get_settings().DATABASE_ECHO

    engine_kwargs = {"echo": echo}
    if "sqlite" in url:
        engine_kwargs["connect_args"] = {"check_same_thread": False}

    engine = create_engine(url, **engine_kwargs)
    if database_url is None:
        _sync_engine = engine
    return engine


def get_sync_session_factory(engine: Optional[Engine] = None) -> sessionmaker[Session]:
    """Obtain or initialize the synchronous session maker."""
    global _sync_session_factory
    if _sync_session_factory is not None and engine is None:
        return _sync_session_factory

    target_engine = engine or get_sync_engine()
    factory = sessionmaker(
        bind=target_engine,
        class_=Session,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    if engine is None:
        _sync_session_factory = factory
    return factory


@contextmanager
def get_sync_db(database_url: Optional[str] = None) -> Generator[Session, None, None]:
    """Context manager yielding a synchronous database session with automatic commit/rollback."""
    engine = get_sync_engine(database_url) if database_url else None
    factory = get_sync_session_factory(engine)
    session = factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
