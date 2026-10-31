"""Case evidence linking - Phase 8c.

Links evidence from the EvidenceStore to a Case. Case stores evidence IDs
(the Evidence itself lives in the store; the case references it).

Design rules:
  - All operations are immutable: return a new Case.
  - Linking is idempotent: re-linking does not duplicate.
  - Unlinking a missing ID is a no-op (idempotent).
  - If a store is provided, linking validates that the evidence exists.
  - list_evidence_ids returns a copy (mutations don't affect the case).
"""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from app.modules.investigation.case import Case, CaseEvent
from app.modules.investigation.evidence import EvidenceStore


def link_evidence(
    case: Case,
    evidence_id: str,
    *,
    by: str,
    store: EvidenceStore | None = None,
) -> Case:
    """Link an evidence to a case. Idempotent."""
    _require_actor(by)
    if not evidence_id or not evidence_id.strip():
        raise ValueError("evidence_id is required")

    target = evidence_id.strip()

    if store is not None and store.get(target) is None:
        raise ValueError(f"evidence not found: {target}")

    if target in case.evidence_ids:
        # Idempotent: no change, no event
        return case

    event = CaseEvent(
        timestamp=_now(),
        actor=by.strip(),
        action="evidence_linked",
        detail={"evidence_id": target},
    )

    return replace(
        case,
        evidence_ids=[*case.evidence_ids, target],
        history=[*case.history, event],
    )


def unlink_evidence(case: Case, evidence_id: str, *, by: str) -> Case:
    """Unlink evidence from a case. No-op if not linked."""
    _require_actor(by)
    if not evidence_id or not evidence_id.strip():
        raise ValueError("evidence_id is required")

    target = evidence_id.strip()

    if target not in case.evidence_ids:
        # Idempotent: no change
        return case

    event = CaseEvent(
        timestamp=_now(),
        actor=by.strip(),
        action="evidence_unlinked",
        detail={"evidence_id": target},
    )

    return replace(
        case,
        evidence_ids=[e for e in case.evidence_ids if e != target],
        history=[*case.history, event],
    )


def has_evidence(case: Case, evidence_id: str) -> bool:
    if not evidence_id:
        return False
    return evidence_id.strip() in case.evidence_ids


def list_evidence_ids(case: Case) -> list[str]:
    """Return a copy of the evidence IDs, preserving insertion order."""
    return list(case.evidence_ids)


# ---------- helpers ----------
def _require_actor(actor: str) -> None:
    if not actor or not actor.strip():
        raise ValueError("actor is required")


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
