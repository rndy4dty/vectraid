"""Phase 8d - Analyst decisions tests (test-first)."""
import pytest

from app.modules.investigation.case import (
    Case,
    CasePriority,
    new_case,
)
from app.modules.investigation.case_decisions import (
    AnalystDecision,
    DecisionOutcome,
    add_decision,
    latest_decision,
    list_decisions,
)


def _make_case() -> Case:
    return new_case(
        case_id="CASE-2026-0001",
        title="Test",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )


# ---------- DecisionOutcome ----------
def test_decision_outcome_values():
    assert DecisionOutcome.FALSE_POSITIVE.value == "false_positive"
    assert DecisionOutcome.ESCALATE.value == "escalate"
    assert DecisionOutcome.DUPLICATE.value == "duplicate"
    assert DecisionOutcome.RESOLVED.value == "resolved"
    assert DecisionOutcome.CLOSE.value == "close"


# ---------- AnalystDecision ----------
def test_analyst_decision_fields():
    d = AnalystDecision(
        timestamp="2026-11-01T09:00:00Z",
        analyst="analyst@example.com",
        outcome=DecisionOutcome.FALSE_POSITIVE,
        rationale="Legitimate marketing email from known sender",
        evidence_reference=None,
    )
    assert d.analyst == "analyst@example.com"
    assert d.outcome == DecisionOutcome.FALSE_POSITIVE
    assert d.rationale


def test_analyst_decision_requires_rationale():
    with pytest.raises(ValueError):
        AnalystDecision(
            timestamp="2026-11-01T09:00:00Z",
            analyst="analyst@example.com",
            outcome=DecisionOutcome.FALSE_POSITIVE,
            rationale="",
            evidence_reference=None,
        )


def test_analyst_decision_requires_analyst():
    with pytest.raises(ValueError):
        AnalystDecision(
            timestamp="2026-11-01T09:00:00Z",
            analyst="",
            outcome=DecisionOutcome.FALSE_POSITIVE,
            rationale="x",
            evidence_reference=None,
        )


# ---------- add_decision ----------
def test_add_decision_appends():
    case = _make_case()
    case2 = add_decision(
        case,
        outcome=DecisionOutcome.FALSE_POSITIVE,
        rationale="Legit marketing",
        by="analyst@example.com",
    )
    assert len(case2.decisions) == 1
    assert case2.decisions[0].outcome == DecisionOutcome.FALSE_POSITIVE
    # original unchanged
    assert len(case.decisions) == 0


def test_add_decision_appends_history():
    case = _make_case()
    case2 = add_decision(
        case,
        outcome=DecisionOutcome.ESCALATE,
        rationale="Needs forensic analysis",
        by="analyst@example.com",
    )
    assert case2.history[-1].action == "decision_added"
    assert case2.history[-1].detail["outcome"] == "escalate"
    assert case2.history[-1].detail["rationale"] == "Needs forensic analysis"


def test_add_decision_with_evidence_reference():
    case = _make_case()
    case2 = add_decision(
        case,
        outcome=DecisionOutcome.RESOLVED,
        rationale="Confirmed malware",
        by="analyst@example.com",
        evidence_reference="ev-001",
    )
    assert case2.decisions[0].evidence_reference == "ev-001"


def test_add_decision_requires_rationale():
    case = _make_case()
    with pytest.raises(ValueError):
        add_decision(
            case,
            outcome=DecisionOutcome.RESOLVED,
            rationale="",
            by="analyst@example.com",
        )


def test_add_decision_requires_actor():
    case = _make_case()
    with pytest.raises(ValueError):
        add_decision(
            case,
            outcome=DecisionOutcome.RESOLVED,
            rationale="x",
            by="",
        )


# ---------- list_decisions ----------
def test_list_decisions_empty():
    case = _make_case()
    assert list_decisions(case) == []


def test_list_decisions_returns_copy():
    case = _make_case()
    case = add_decision(
        case, outcome=DecisionOutcome.ESCALATE,
        rationale="x", by="a@x.com",
    )
    decisions = list_decisions(case)
    decisions.append(
        AnalystDecision(
            timestamp="x", analyst="a@x.com",
            outcome=DecisionOutcome.CLOSE,
            rationale="x", evidence_reference=None,
        )
    )
    assert len(list_decisions(case)) == 1


# ---------- latest_decision ----------
def test_latest_decision_empty():
    case = _make_case()
    assert latest_decision(case) is None


def test_latest_decision_returns_most_recent():
    case = _make_case()
    case = add_decision(
        case, outcome=DecisionOutcome.ESCALATE,
        rationale="first", by="a@x.com",
    )
    case = add_decision(
        case, outcome=DecisionOutcome.RESOLVED,
        rationale="second", by="a@x.com",
    )
    latest = latest_decision(case)
    assert latest.outcome == DecisionOutcome.RESOLVED
    assert latest.rationale == "second"


# ---------- decisions are immutable ----------
def test_decision_is_frozen():
    d = AnalystDecision(
        timestamp="2026-11-01T09:00:00Z",
        analyst="a@x.com",
        outcome=DecisionOutcome.CLOSE,
        rationale="x",
        evidence_reference=None,
    )
    with pytest.raises(Exception):  # FrozenInstanceError
        d.rationale = "changed"  # type: ignore[misc]
