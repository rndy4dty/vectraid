"""VECTRAID FastAPI application entrypoint.

Exposes a create_app() factory so tests can build isolated instances.
Each app gets its own CaseStore / EvidenceStore / CaseIDGenerator.
API key auth is applied to the /api/v1 router; /health and /openapi.json
remain unauthenticated.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import Depends, FastAPI

from app.api.v1.router import router as v1_router
from app.core.auth import require_api_key
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.modules.investigation.case_store import CaseIDGenerator, CaseStore
from app.modules.investigation.evidence import EvidenceStore

configure_logging()
settings = get_settings()


def create_app() -> FastAPI:
    """Build a fresh FastAPI application with isolated state."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "VECTRAID - Unified Threat Intelligence & Investigation Platform"
        ),
    )

    # Per-app state
    app.state.settings = settings
    app.state.case_store = CaseStore()
    app.state.evidence_store = EvidenceStore()
    app.state.case_id_generator = CaseIDGenerator(
        year=datetime.now(UTC).year
    )

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
