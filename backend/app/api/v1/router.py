"""API v1 router - Phase 9c."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.cases import router as cases_router
from app.api.v1.evidence import router as evidence_router

router = APIRouter()
router.include_router(cases_router)
router.include_router(evidence_router)
