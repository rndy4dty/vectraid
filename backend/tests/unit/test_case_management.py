"""Phase 8a - Case Management tests (test-first)."""
import pytest

from app.modules.investigation.case import (
    Case,
    CaseEvent,
    CasePriority,
    CaseStatus,
    add_note,
    assign_analyst,
    can_transition,
    new_case,
    transition_status,
)


# ---------- enums ----------
def test_case_status_values():
    assert CaseStatus.NEW.value == "new"
    assert CaseStatus.INVESTIGATING.value == "investigating"
    assert CaseStatus.RESOLVED.value == "resolved"
    assert CaseStatus.CLOSED.value == "closed"


def test_case_priority_values():
    assert CasePriority.LOW.value == "low"
    assert CasePriority.MEDIUM.value == "medium"
    assert CasePriority.HIGH.value == "high"
    assert CasePriority.CRITICAL.value == "critical"


# ---------- Case creation ----------
def test_new_case_creates_with_new_status():
    c = new_case(
        case_id="CASE-2026-0001",
        title="Suspicious email",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )
    assert c.case_id == "CASE-2026-0001"
    assert c.title == "Suspicious email"
    assert c.status == CaseStatus.NEW
    assert c.priority == CasePriority.HIGH
    assert c.assignee is None
    assert c.notes == []
    assert len(c.history) == 1
    assert c.history[0].action == "created"


def test_new_case_requires_title():
    with pytest.raises(ValueError):
        new_case(
            case_id="CASE-2026-0001",
            title="",
            priority=CasePriority.HIGH,
            created_by="analyst@example.com",
        )


def test_new_case_requires_created_by():
    with pytest.raises(ValueError):
        new_case(
            case_id="CASE-2026-0001",
            title="Test",
            priority=CasePriority.MEDIUM,
            created_by="",
        )


# ---------- state machine ----------
def test_can_transition_new_to_investigating():
    assert can_transition(CaseStatus.NEW, CaseStatus.INVESTIGATING) is True


def test_can_transition_new_to_closed_is_invalid():
    assert can_transition(CaseStatus.NEW, CaseStatus.CLOSED) is False


def test_can_transition_investigating_to_resolved():
    assert can_transition(CaseStatus.INVESTIGATING, CaseStatus.RESOLVED) is True


def test_can_transition_resolved_to_closed():
    assert can_transition(CaseStatus.RESOLVED, CaseStatus.CLOSED) is True


def test_can_transition_resolved_back_to_investigating():
    """Re-opening a resolved case is allowed."""
    assert can_transition(CaseStatus.RESOLVED, CaseStatus.INVESTIGATING) is True


def test_can_transition_closed_is_terminal():
    """Closed is terminal - no transitions out."""
    assert can_transition(CaseStatus.CLOSED, CaseStatus.INVESTIGATING) is False
    assert can_transition(CaseStatus.CLOSED, CaseStatus.RESOLVED) is False


# ---------- transition_status ----------
def _make_case() -> Case:
    return new_case(
        case_id="CASE-2026-0001",
        title="Test",
        priority=CasePriority.MEDIUM,
        created_by="analyst@example.com",
    )


def test_transition_status_produces_new_case():
    c = _make_case()
    c2 = transition_status(c, CaseStatus.INVESTIGATING, by="analyst@example.com")
    assert c2 is not c
    assert c2.status == CaseStatus.INVESTIGATING
    # original unchanged
    assert c.status == CaseStatus.NEW


def test_transition_appends_history():
    c = _make_case()
    c2 = transition_status(c, CaseStatus.INVESTIGATING, by="analyst@example.com")
    assert len(c2.history) == 2
    assert c2.history[-1].action == "status_changed"
    assert c2.history[-1].detail["to"] == "investigating"
    assert c2.history[-1].detail["from"] == "new"


def test_transition_invalid_raises():
    c = _make_case()
    with pytest.raises(ValueError):
        transition_status(c, CaseStatus.CLOSED, by="analyst@example.com")


def test_transition_requires_actor():
    c = _make_case()
    with pytest.raises(ValueError):
        transition_status(c, CaseStatus.INVESTIGATING, by="")


# ---------- assign_analyst ----------
def test_assign_analyst():
    c = _make_case()
    c2 = assign_analyst(c, assignee="analyst@example.com", by="lead@example.com")
    assert c2.assignee == "analyst@example.com"
    assert c.assignee is None  # original unchanged
    assert len(c2.history) == 2
    assert c2.history[-1].action == "assigned"


def test_assign_analyst_requires_assignee():
    c = _make_case()
    with pytest.raises(ValueError):
        assign_analyst(c, assignee="", by="lead@example.com")


# ---------- add_note ----------
def test_add_note():
    c = _make_case()
    c2 = add_note(c, note="Suspicious sender domain", by="analyst@example.com")
    assert len(c2.notes) == 1
    assert c2.notes[0].text == "Suspicious sender domain"
    assert c2.notes[0].author == "analyst@example.com"
    # original unchanged
    assert len(c.notes) == 0


def test_add_note_requires_text():
    c = _make_case()
    with pytest.raises(ValueError):
        add_note(c, note="", by="analyst@example.com")


def test_add_note_requires_author():
    c = _make_case()
    with pytest.raises(ValueError):
        add_note(c, note="test", by="")


# ---------- CaseEvent ----------
def test_case_event_fields():
    e = CaseEvent(
        timestamp="2026-11-01T09:00:00Z",
        actor="analyst@example.com",
        action="status_changed",
        detail={"from": "new", "to": "investigating"},
    )
    assert e.actor == "analyst@example.com"
    assert e.action == "status_changed"
    assert e.detail["to"] == "investigating"
