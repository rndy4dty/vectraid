"""Case + Investigation integration - Phase 8e.

Top-level orchestrator: given a Case and an EvidenceStore, run the full
Investigation pipeline over the case's evidence, link that evidence to
the case, and return a combined CaseReport.

Design rules:
  - Only evidence whose case_id matches the case is investigated.
  - Status transitions to INVESTIGATING only when evidence exists.
  - Operations are idempotent: re-running on an already-investigating
    case does not raise, does not re-link, does not duplicate history.
  - Fail-soft: if a component raises, the report still has whatever
    succeeded; the case itself remains valid.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.modules.investigation.case import Case, CaseStatus, transition_status
from app.modules.investigation.case_evidence import link_evidence
from app.modules.investigation.engine import (
    InvestigationReport,
    run_investigation,
)
from app.modules.investigation.evidence import EvidenceStore


@dataclass(frozen=True)
class CaseReport:
    case: Case
    investigation: InvestigationReport


def open_case_investigation(
    case: Case,
    store: EvidenceStore,
    *,
    by: str = "system",
) -> CaseReport:
    """Run investigation over the case's evidence and return a combined report."""
    # 1. Gather evidence for this case only.
    evidence_for_case = store.list_by_case(case.case_id)

    # 2. Run the investigation pipeline.
    investigation = run_investigation(evidence_for_case, case_id=case.case_id)

    # 3. Link each evidence to the case (idempotent).
    linked_case = case
    for ev in evidence_for_case:
        linked_case = link_evidence(
            linked_case,
            ev.evidence_id,
            by=by,
            store=store,
        )

    # 4. Transition to INVESTIGATING if we have evidence and not already there.
    if evidence_for_case and linked_case.status == CaseStatus.NEW:
        linked_case = transition_status(
            linked_case, CaseStatus.INVESTIGATING, by=by
        )

    return CaseReport(case=linked_case, investigation=investigation)
