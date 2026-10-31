"""API v1 router - Phase 9b."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.cases import router as cases_router

router = APIRouter()
router.include_router(cases_router)
