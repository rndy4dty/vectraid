"""Analyst decisions - Phase 8d.

Formal analyst decisions attached to a case. Unlike notes, decisions
carry a structured outcome and a mandatory rationale.

Design rules:
  - AnalystDecision is frozen: after creation, it cannot be edited.
    Changing a decision means adding a new one.
  - rationale is mandatory: no decision without justification.
  - evidence_reference is optional but recorded for traceability.
  - All mutating operations return a new Case; the original is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum

from app.modules.investigation.case import Case, CaseEvent


class DecisionOutcome(StrEnum):
    FALSE_POSITIVE = "false_positive"
    ESCALATE = "escalate"
    DUPLICATE = "duplicate"
    RESOLVED = "resolved"
    CLOSE = "close"


@dataclass(frozen=True)
class AnalystDecision:
    timestamp: str
    analyst: str
    outcome: DecisionOutcome
    rationale: str
    evidence_reference: str | None = None

    def __post_init__(self) -> None:
        if not self.analyst or not self.analyst.strip():
            raise ValueError("analyst is required")
        if not self.rationale or not self.rationale.strip():
            raise ValueError("rationale is required")


def add_decision(
    case: Case,
    *,
    outcome: DecisionOutcome,
    rationale: str,
    by: str,
    evidence_reference: str | None = None,
) -> Case:
    """Append an analyst decision. Returns a new Case."""
    _require_actor(by)
    if not rationale or not rationale.strip():
        raise ValueError("rationale is required")

    stamp = _now()
    decision = AnalystDecision(
        timestamp=stamp,
        analyst=by.strip(),
        outcome=outcome,
        rationale=rationale.strip(),
        evidence_reference=evidence_reference,
    )

    event = CaseEvent(
        timestamp=stamp,
        actor=by.strip(),
        action="decision_added",
        detail={
            "outcome": outcome.value,
            "rationale": rationale.strip(),
            "evidence_reference": evidence_reference,
        },
    )

    return replace(
        case,
        decisions=[*case.decisions, decision],
        history=[*case.history, event],
    )


def list_decisions(case: Case) -> list[AnalystDecision]:
    """Return a copy of the decisions list."""
    return list(case.decisions)


def latest_decision(case: Case) -> AnalystDecision | None:
    if not case.decisions:
        return None
    return case.decisions[-1]


# ---------- helpers ----------
def _require_actor(actor: str) -> None:
    if not actor or not actor.strip():
        raise ValueError("actor is required")


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
