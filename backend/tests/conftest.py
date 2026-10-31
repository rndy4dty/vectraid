"""Pytest fixtures - Phase 11a.

Uses NullPool to avoid asyncpg connection pool being bound to a stale
event loop (classic "attached to a different loop" error).
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.models import Base

DEFAULT_TEST_URL = (
    "postgresql+asyncpg://vectraid:vectraid_dev_password"
    "@localhost:5432/vectraid_test"
)


@pytest.fixture(scope="session")
def test_database_url() -> str:
    return os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_URL)


@pytest_asyncio.fixture
async def engine(test_database_url: str) -> AsyncEngine:
    """Function-scoped async engine with NullPool (no connection reuse)."""
    eng = create_async_engine(
        test_database_url,
        echo=False,
        poolclass=NullPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest_asyncio.fixture
async def db_session(engine: AsyncEngine) -> AsyncSession:
    """Per-test session. Tables are recreated per test by `engine`."""
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
def api_client(engine: AsyncEngine) -> Generator[TestClient, None, None]:
    """TestClient with DB session override using the per-test engine."""
    from app.api.v1.dependencies import get_db_session
    from app.main import create_app

    app = create_app()

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    app.state.session_maker = session_maker

    async def _override() -> AsyncGenerator[AsyncSession, None]:
        async with session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = _override

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()
