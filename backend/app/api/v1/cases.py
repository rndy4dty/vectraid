"""Case endpoints - Phase 11a-4.

All endpoints are async and use CaseRepository via dependency injection.
Business logic remains in app.modules.investigation.case*.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.api.v1.dependencies import (
    get_case_repository,
    get_evidence_repository,
)
from app.modules.investigation.case import (
    Case,
    CasePriority,
    CaseStatus,
    add_note,
    assign_analyst,
    new_case,
    transition_status,
)
from app.modules.investigation.case_decisions import (
    DecisionOutcome,
    add_decision,
)
from app.modules.investigation.case_evidence import (
    link_evidence,
    unlink_evidence,
)
from app.reports.generator import generate_case_pdf
from app.modules.investigation.case_investigation import (
    open_case_investigation,
)
from app.repositories.case_repository import CaseRepository
from app.repositories.evidence_repository import EvidenceRepository
from app.schemas.case import (
    CaseAssignRequest,
    CaseCreateRequest,
    CaseDecisionRequest,
    CaseNoteRequest,
    CaseResponse,
    CaseTransitionRequest,
)
from app.schemas.evidence import LinkEvidenceRequest
from app.schemas.report import CaseReportResponse

router = APIRouter(prefix="/cases", tags=["cases"])


# ---------- helpers ----------
async def _require_case(repo: CaseRepository, case_id: str) -> Case:
    case = await repo.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return case


async def _next_case_id(repo: CaseRepository) -> str:
    """Generate a new case id by probing count + 1."""
    all_cases = await repo.list_all()
    year = __import__("datetime").datetime.now(__import__("datetime").UTC).year
    counter = len(all_cases) + 1
    while True:
        candidate = f"CASE-{year}-{counter:04d}"
        if await repo.get(candidate) is None:
            return candidate
        counter += 1


# ---------- create ----------
@router.post("", status_code=201, response_model=CaseResponse)
async def create_case(
    payload: CaseCreateRequest,
    repo: CaseRepository = Depends(get_case_repository),
) -> Case:
    case_id = await _next_case_id(repo)
    case = new_case(
        case_id=case_id,
        title=payload.title,
        priority=CasePriority(payload.priority),
        created_by=payload.created_by,
    )
    await repo.add(case)
    return case


# ---------- list ----------
@router.get("", response_model=list[CaseResponse])
async def list_cases(
    status: str | None = Query(
        default=None,
        pattern="^(new|investigating|resolved|closed)$",
    ),
    repo: CaseRepository = Depends(get_case_repository),
) -> list[Case]:
    if status is not None:
        return await repo.list_by_status(CaseStatus(status))
    return await repo.list_all()


# ---------- get ----------
@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: str,
    repo: CaseRepository = Depends(get_case_repository),
) -> Case:
    return await _require_case(repo, case_id)


# ---------- transition ----------
@router.post("/{case_id}/transition", response_model=CaseResponse)
async def transition_case(
    case_id: str,
    payload: CaseTransitionRequest,
    repo: CaseRepository = Depends(get_case_repository),
) -> Case:
    case = await _require_case(repo, case_id)
    try:
        updated = transition_status(case, CaseStatus(payload.to), by=payload.by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await repo.update(updated)
    return updated


# ---------- assign ----------
@router.post("/{case_id}/assign", response_model=CaseResponse)
async def assign_case(
    case_id: str,
    payload: CaseAssignRequest,
    repo: CaseRepository = Depends(get_case_repository),
) -> Case:
    case = await _require_case(repo, case_id)
    try:
        updated = assign_analyst(case, assignee=payload.assignee, by=payload.by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await repo.update(updated)
    return updated


# ---------- notes ----------
@router.post("/{case_id}/notes", response_model=CaseResponse)
async def add_note_endpoint(
    case_id: str,
    payload: CaseNoteRequest,
    repo: CaseRepository = Depends(get_case_repository),
) -> Case:
    case = await _require_case(repo, case_id)
    try:
        updated = add_note(case, note=payload.note, by=payload.by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await repo.update(updated)
    return updated


# ---------- decisions ----------
@router.post("/{case_id}/decisions", response_model=CaseResponse)
async def add_decision_endpoint(
    case_id: str,
    payload: CaseDecisionRequest,
    repo: CaseRepository = Depends(get_case_repository),
) -> Case:
    case = await _require_case(repo, case_id)
    try:
        updated = add_decision(
            case,
            outcome=DecisionOutcome(payload.outcome),
            rationale=payload.rationale,
            by=payload.by,
            evidence_reference=payload.evidence_reference,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await repo.update(updated)
    return updated


# ---------- evidence linking ----------
@router.post("/{case_id}/evidence", response_model=CaseResponse)
async def link_evidence_endpoint(
    case_id: str,
    payload: LinkEvidenceRequest,
    repo: CaseRepository = Depends(get_case_repository),
    evidence_repo: EvidenceRepository = Depends(get_evidence_repository),
) -> Case:
    case = await _require_case(repo, case_id)
    ev = await evidence_repo.get(payload.evidence_id)
    if ev is None:
        raise HTTPException(
            status_code=404,
            detail=f"evidence not found: {payload.evidence_id}",
        )
    try:
        updated = link_evidence(case, payload.evidence_id, by=payload.by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await repo.update(updated)
    return updated


@router.delete("/{case_id}/evidence/{evidence_id}", response_model=CaseResponse)
async def unlink_evidence_endpoint(
    case_id: str,
    evidence_id: str,
    by: str = Query(..., min_length=1, max_length=200),
    repo: CaseRepository = Depends(get_case_repository),
) -> Case:
    case = await _require_case(repo, case_id)
    try:
        updated = unlink_evidence(case, evidence_id, by=by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await repo.update(updated)
    return updated


# ---------- full report ----------
@router.get("/{case_id}/report", response_model=CaseReportResponse)
async def case_report(
    case_id: str,
    repo: CaseRepository = Depends(get_case_repository),
    evidence_repo: EvidenceRepository = Depends(get_evidence_repository),
) -> object:
    case = await _require_case(repo, case_id)
    # Load evidence into an in-memory store adapter (Phase 7 engine expects
    # a store-like object; we build a minimal one from the repository).
    from app.modules.investigation.evidence import EvidenceStore

    store = EvidenceStore()
    for ev in await evidence_repo.list_by_case(case_id):
        store.add(ev)

    report = open_case_investigation(case, store, by="api")
    await repo.update(report.case)
    return report

# ---------- PDF report ----------
@router.get("/{case_id}/report.pdf")
async def case_report_pdf(
    case_id: str,
    repo: CaseRepository = Depends(get_case_repository),
    evidence_repo: EvidenceRepository = Depends(get_evidence_repository),
) -> Response:
    """Generate a PDF report for the given case."""
    case = await _require_case(repo, case_id)

    # Load evidence into a store adapter (Phase 7 engine expects a store-like).
    from app.modules.investigation.case_investigation import open_case_investigation
    from app.modules.investigation.evidence import EvidenceStore

    store = EvidenceStore()
    for ev in await evidence_repo.list_by_case(case_id):
        store.add(ev)

    report = open_case_investigation(case, store, by="api")
    await repo.update(report.case)

    pdf_bytes = generate_case_pdf(report.case, report.investigation)

    filename = f"VECTRAID-{report.case.case_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
