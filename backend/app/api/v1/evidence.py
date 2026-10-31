"""Evidence endpoints - Phase 11a-4."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.v1.dependencies import get_evidence_repository
from app.modules.investigation.evidence import (
    Evidence,
    EvidenceType,
)
from app.repositories.base import RepositoryError
from app.repositories.evidence_repository import EvidenceRepository
from app.schemas.evidence import EvidenceCreateRequest, EvidenceResponse

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("", status_code=201, response_model=EvidenceResponse)
async def create_evidence(
    payload: EvidenceCreateRequest,
    repo: EvidenceRepository = Depends(get_evidence_repository),
) -> Evidence:
    try:
        evidence = Evidence(
            evidence_id=payload.evidence_id,
            case_id=payload.case_id,
            source_module=payload.source_module,
            evidence_type=EvidenceType(payload.evidence_type),
            raw_reference=payload.raw_reference,
            finding=payload.finding,
            timestamp=payload.timestamp,
            confidence=payload.confidence,
            provenance=payload.provenance,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        await repo.add(evidence)
    except RepositoryError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return evidence


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: str,
    repo: EvidenceRepository = Depends(get_evidence_repository),
) -> Evidence:
    evidence = await repo.get(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return evidence


@router.get("", response_model=list[EvidenceResponse])
async def list_evidence(
    case_id: str | None = Query(default=None),
    repo: EvidenceRepository = Depends(get_evidence_repository),
) -> list[Evidence]:
    if case_id is not None:
        return await repo.list_by_case(case_id)
    return await repo.list_all()
