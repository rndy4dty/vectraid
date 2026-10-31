"""API key authentication - Phase 9f.

Minimal API-key auth via X-API-Key header. When no key is configured on
the server (VECTRAID_API_KEY empty), auth is disabled (dev mode).

Design rules:
  - Missing or wrong key -> 401 Unauthorized (not 403).
  - If server key is empty, all requests pass.
  - Health and OpenAPI remain unauthenticated.
  - Reads expected key from request.app.state.settings so tests and
    per-app configuration work.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, Request, status


async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency: reject request if API key is required and wrong."""
    settings = getattr(request.app.state, "settings", None)
    expected = (getattr(settings, "vectraid_api_key", "") or "") if settings else ""

    # Auth disabled in development when no key is configured.
    if not expected:
        return

    if not x_api_key or x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
