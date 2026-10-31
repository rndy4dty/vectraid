"""Pytest fixtures for Phase 11a repository tests.

Uses a real PostgreSQL database (TEST_DATABASE_URL) for integration
tests. In CI, GitHub Actions provides the postgres service.

Local developers must run:
    docker compose up -d postgres
and set TEST_DATABASE_URL (defaults below).
"""
from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

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
    """Function-scoped async engine. Creates + drops all tables per test.

    Function scope avoids ScopeMismatch with function-scoped db_session
    under pytest-asyncio 0.24+ (session-scoped async fixtures cannot be
    accessed from function-scoped tests).
    """
    eng = create_async_engine(test_database_url, echo=False)
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
