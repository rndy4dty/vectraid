"""VECTRAID FastAPI application entrypoint.

Exposes a create_app() factory so tests can build isolated instances.
Each app gets its own async engine + session maker. Database tables are
managed by Alembic (see migrations/), not by the app.

API key auth is applied to the /api/v1 router; /health and /openapi.json
remain unauthenticated.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from app.api.v1.router import router as v1_router
from app.core.auth import require_api_key
from app.core.config import get_settings
from app.core.logging import configure_logging

configure_logging()
settings = get_settings()


def _make_engine() -> AsyncEngine:
    return create_async_engine(
        settings.database_url,
        echo=False,
        pool_pre_ping=True,
    )


def create_app() -> FastAPI:
    """Build a fresh FastAPI application with isolated state."""
    engine = _make_engine()
    session_maker = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await engine.dispose()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "VECTRAID - Unified Threat Intelligence & Investigation Platform"
        ),
        lifespan=lifespan,
    )

    # Per-app state
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_maker = session_maker
    app.state.started_at = datetime.now(UTC)

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "app": settings.app_name,
            "version": settings.app_version,
        }

    app.include_router(
        v1_router,
        prefix=settings.api_v1_prefix,
        dependencies=[Depends(require_api_key)],
    )

    return app


app = create_app()
