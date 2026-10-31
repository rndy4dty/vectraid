"""VECTRAID FastAPI application entrypoint.

Exposes a create_app() factory so tests can build isolated instances.
The default module-level `app` is preserved for uvicorn.

Design rules:
  - create_app() builds a fresh app with fresh dependency instances.
  - /health is unauthenticated and always available.
  - All business endpoints live under API_V1_PREFIX (/api/v1).
"""
from __future__ import annotations

from fastapi import FastAPI

from app.core.config import get_settings
from app.core.logging import configure_logging

configure_logging()
settings = get_settings()


def create_app() -> FastAPI:
    """Build a fresh FastAPI application.

    Each call returns a new app instance with independent routers and
    dependency state. This keeps tests isolated.
    """
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "VECTRAID - Unified Threat Intelligence & Investigation Platform"
        ),
    )

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "app": settings.app_name,
            "version": settings.app_version,
        }

    return app


# Module-level app for uvicorn / production
app = create_app()
