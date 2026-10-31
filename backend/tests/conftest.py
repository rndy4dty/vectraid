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


@pytest_asyncio.fixture(scope="session")
async def engine(test_database_url: str) -> AsyncEngine:
    """Session-scoped async engine. Creates + drops all tables once."""
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
    """Per-test session with transaction rolled back afterwards.

    Each test gets a clean slate. We truncate all tables after the test
    to keep tests isolated.
    """
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session
        await session.rollback()

    # Truncate all tables for next test (FK-aware order)
    async with engine.begin() as conn:
        from sqlalchemy import text
        await conn.execute(text(
            "TRUNCATE case_evidence_links, case_decisions, case_notes, "
            "case_events, evidence, cases RESTART IDENTITY CASCADE"
        ))
