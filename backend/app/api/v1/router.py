"""API v1 router - Phase 9e."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.analysis import router as analysis_router
from app.api.v1.cases import router as cases_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.graph import router as graph_router
from app.api.v1.hunt import router as hunt_router
from app.api.v1.investigation import router as investigation_router

router = APIRouter()
router.include_router(cases_router)
router.include_router(evidence_router)
router.include_router(investigation_router)
router.include_router(analysis_router)
router.include_router(hunt_router)
router.include_router(graph_router)
