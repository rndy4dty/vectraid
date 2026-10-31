"""Case endpoints - Phase 9b.

Thin wrappers around Phase 8 operations. Business logic lives in
app.modules.investigation.case*, not here.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.v1.dependencies import (
    get_case_id_generator,
    get_case_store,
    get_evidence_store,
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
from app.modules.investigation.case_investigation import (
    open_case_investigation,
)
from app.modules.investigation.case_store import CaseIDGenerator, CaseStore
from app.modules.investigation.evidence import EvidenceStore
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
def _require_case(store: CaseStore, case_id: str) -> Case:
    case = store.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return case


def _save(store: CaseStore, case: Case) -> None:
    """Persist a new-or-modified case. add() if new, update() if existing."""
    if store.get(case.case_id) is None:
        store.add(case)
    else:
        store.update(case)


# ---------- create ----------
@router.post("", status_code=201, response_model=CaseResponse)
def create_case(
    payload: CaseCreateRequest,
    store: CaseStore = Depends(get_case_store),
    id_gen: CaseIDGenerator = Depends(get_case_id_generator),
) -> Case:
    case_id = id_gen.next()
    case = new_case(
        case_id=case_id,
        title=payload.title,
        priority=CasePriority(payload.priority),
        created_by=payload.created_by,
    )
    store.add(case)
    return case


# ---------- list ----------
@router.get("", response_model=list[CaseResponse])
def list_cases(
    status: str | None = Query(
        default=None,
        pattern="^(new|investigating|resolved|closed)$",
    ),
    store: CaseStore = Depends(get_case_store),
) -> list[Case]:
    if status is not None:
        return store.list_by_status(CaseStatus(status))
    return store.list_all()


# ---------- get ----------
@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: str,
    store: CaseStore = Depends(get_case_store),
) -> Case:
    return _require_case(store, case_id)


# ---------- transition ----------
@router.post("/{case_id}/transition", response_model=CaseResponse)
def transition_case(
    case_id: str,
    payload: CaseTransitionRequest,
    store: CaseStore = Depends(get_case_store),
) -> Case:
    case = _require_case(store, case_id)
    try:
        updated = transition_status(
            case, CaseStatus(payload.to), by=payload.by
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store.update(updated)
    return updated


# ---------- assign ----------
@router.post("/{case_id}/assign", response_model=CaseResponse)
def assign_case(
    case_id: str,
    payload: CaseAssignRequest,
    store: CaseStore = Depends(get_case_store),
) -> Case:
    case = _require_case(store, case_id)
    try:
        updated = assign_analyst(case, assignee=payload.assignee, by=payload.by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store.update(updated)
    return updated


# ---------- notes ----------
@router.post("/{case_id}/notes", response_model=CaseResponse)
def add_note_endpoint(
    case_id: str,
    payload: CaseNoteRequest,
    store: CaseStore = Depends(get_case_store),
) -> Case:
    case = _require_case(store, case_id)
    try:
        updated = add_note(case, note=payload.note, by=payload.by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store.update(updated)
    return updated


# ---------- decisions ----------
@router.post("/{case_id}/decisions", response_model=CaseResponse)
def add_decision_endpoint(
    case_id: str,
    payload: CaseDecisionRequest,
    store: CaseStore = Depends(get_case_store),
) -> Case:
    case = _require_case(store, case_id)
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
    store.update(updated)
    return updated

# ---------- evidence linking ----------
@router.post("/{case_id}/evidence", response_model=CaseResponse)
def link_evidence_endpoint(
    case_id: str,
    payload: LinkEvidenceRequest,
    store: CaseStore = Depends(get_case_store),
    evidence_store: EvidenceStore = Depends(get_evidence_store),
) -> Case:
    case = _require_case(store, case_id)
    try:
        updated = link_evidence(
            case, payload.evidence_id, by=payload.by, store=evidence_store
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    store.update(updated)
    return updated


@router.delete("/{case_id}/evidence/{evidence_id}", response_model=CaseResponse)
def unlink_evidence_endpoint(
    case_id: str,
    evidence_id: str,
    by: str = Query(..., min_length=1, max_length=200),
    store: CaseStore = Depends(get_case_store),
) -> Case:
    case = _require_case(store, case_id)
    try:
        updated = unlink_evidence(case, evidence_id, by=by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store.update(updated)
    return updated

# ---------- full report ----------
@router.get("/{case_id}/report", response_model=CaseReportResponse)
def case_report(
    case_id: str,
    store: CaseStore = Depends(get_case_store),
    evidence_store: EvidenceStore = Depends(get_evidence_store),
) -> object:
    case = _require_case(store, case_id)
    report = open_case_investigation(case, evidence_store, by="api")
    # Persist any case changes (linking, transition)
    if store.get(report.case.case_id) is not None:
        store.update(report.case)
    return report
