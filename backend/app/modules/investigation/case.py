"""Case Management - Phase 8a.

Immutable Case objects with explicit workflow state machine and audit trail.

Design rules:
  - Case is frozen. Every operation produces a new Case with an appended
    CaseEvent. The original Case is never mutated.
  - Workflow transitions are explicit data. Invalid transitions raise.
  - Every operation requires an actor (email or identifier). Anonymous
    changes are not permitted - audit trail must be complete.
  - Case IDs follow "CASE-YYYY-NNNN". IDs are supplied by the caller;
    this module does not invent them.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum


class CaseStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Valid transitions: from -> set of allowed "to"
_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.NEW: {CaseStatus.INVESTIGATING},
    CaseStatus.INVESTIGATING: {CaseStatus.RESOLVED, CaseStatus.CLOSED},
    CaseStatus.RESOLVED: {CaseStatus.CLOSED, CaseStatus.INVESTIGATING},
    CaseStatus.CLOSED: set(),  # terminal
}


@dataclass(frozen=True)
class CaseEvent:
    timestamp: str
    actor: str
    action: str
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class CaseNote:
    timestamp: str
    author: str
    text: str


@dataclass(frozen=True)
class Case:
    case_id: str
    title: str
    status: CaseStatus
    priority: CasePriority
    created_by: str
    assignee: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    decisions: list = field(default_factory=list)
    notes: list[CaseNote] = field(default_factory=list)
    history: list[CaseEvent] = field(default_factory=list)


# ---------- creation ----------
def new_case(
    case_id: str,
    title: str,
    priority: CasePriority,
    created_by: str,
) -> Case:
    """Create a new case in NEW status."""
    if not title or not title.strip():
        raise ValueError("title is required")
    if not created_by or not created_by.strip():
        raise ValueError("created_by is required")
    if not case_id or not case_id.strip():
        raise ValueError("case_id is required")

    created_event = CaseEvent(
        timestamp=_now(),
        actor=created_by,
        action="created",
        detail={
            "title": title,
            "priority": priority.value,
        },
    )

    return Case(
        case_id=case_id.strip(),
        title=title.strip(),
        status=CaseStatus.NEW,
        priority=priority,
        created_by=created_by.strip(),
        history=[created_event],
    )


# ---------- workflow ----------
def can_transition(from_status: CaseStatus, to_status: CaseStatus) -> bool:
    return to_status in _TRANSITIONS.get(from_status, set())


def transition_status(case: Case, to_status: CaseStatus, *, by: str) -> Case:
    """Return a new Case with the status transitioned and an event appended."""
    _require_actor(by)
    if not can_transition(case.status, to_status):
        raise ValueError(
            f"invalid transition: {case.status.value} -> {to_status.value}"
        )

    event = CaseEvent(
        timestamp=_now(),
        actor=by,
        action="status_changed",
        detail={"from": case.status.value, "to": to_status.value},
    )

    return replace(
        case,
        status=to_status,
        history=[*case.history, event],
    )


# ---------- assignment ----------
def assign_analyst(case: Case, assignee: str, *, by: str) -> Case:
    if not assignee or not assignee.strip():
        raise ValueError("assignee is required")
    _require_actor(by)

    event = CaseEvent(
        timestamp=_now(),
        actor=by,
        action="assigned",
        detail={
            "assignee": assignee.strip(),
            "previous": case.assignee,
        },
    )

    return replace(
        case,
        assignee=assignee.strip(),
        history=[*case.history, event],
    )


# ---------- notes ----------
def add_note(case: Case, note: str, *, by: str) -> Case:
    if not note or not note.strip():
        raise ValueError("note text is required")
    _require_actor(by)

    stamp = _now()
    new_note = CaseNote(timestamp=stamp, author=by.strip(), text=note.strip())
    event = CaseEvent(
        timestamp=stamp,
        actor=by.strip(),
        action="note_added",
        detail={"preview": note.strip()[:80]},
    )

    return replace(
        case,
        notes=[*case.notes, new_note],
        history=[*case.history, event],
    )


# ---------- helpers ----------
def _require_actor(actor: str) -> None:
    if not actor or not actor.strip():
        raise ValueError("actor is required")


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
