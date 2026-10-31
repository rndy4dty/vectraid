"""CaseRepository integration tests - Phase 11a.

Runs against a real PostgreSQL test database (vectraid_test).
"""
from __future__ import annotations

import pytest

from app.modules.investigation.case import (
    Case,
    CasePriority,
    CaseStatus,
    new_case,
    transition_status,
)
from app.modules.investigation.case_decisions import (
    DecisionOutcome,
    add_decision,
)
from app.repositories.base import RepositoryError
from app.repositories.case_repository import CaseRepository


def _case(case_id: str = "CASE-001") -> Case:
    return new_case(
        case_id=case_id,
        title="Test case",
        priority=CasePriority.MEDIUM,
        created_by="analyst@example.com",
    )


@pytest.mark.asyncio
async def test_add_and_get_case(db_session):
    repo = CaseRepository(db_session)
    case = _case()
    await repo.add(case)
    fetched = await repo.get("CASE-001")
    assert fetched is not None
    assert fetched.case_id == "CASE-001"
    assert fetched.status == CaseStatus.NEW
    assert fetched.created_by == "analyst@example.com"
    assert len(fetched.history) == 1  # created event
    assert fetched.history[0].action == "created"


@pytest.mark.asyncio
async def test_add_duplicate_raises(db_session):
    repo = CaseRepository(db_session)
    await repo.add(_case())
    with pytest.raises(RepositoryError):
        await repo.add(_case())


@pytest.mark.asyncio
async def test_get_missing_returns_none(db_session):
    repo = CaseRepository(db_session)
    assert await repo.get("CASE-999") is None


@pytest.mark.asyncio
async def test_transition_persists_status_and_history(db_session):
    repo = CaseRepository(db_session)
    case = _case()
    await repo.add(case)

    # Simulate a transition
    updated = transition_status(case, CaseStatus.INVESTIGATING, by="analyst@example.com")
    await repo.update(updated)

    fetched = await repo.get("CASE-001")
    assert fetched.status == CaseStatus.INVESTIGATING
    # Two events: created + status_changed
    actions = [e.action for e in fetched.history]
    assert "created" in actions
    assert "status_changed" in actions


@pytest.mark.asyncio
async def test_update_idempotent(db_session):
    """Calling update twice with same Case must not duplicate history."""
    repo = CaseRepository(db_session)
    case = _case()
    await repo.add(case)
    await repo.update(case)  # no-op
    await repo.update(case)
    fetched = await repo.get("CASE-001")
    assert len(fetched.history) == 1  # still just "created"


@pytest.mark.asyncio
async def test_list_all(db_session):
    repo = CaseRepository(db_session)
    await repo.add(_case("CASE-A"))
    await repo.add(_case("CASE-B"))
    assert len(await repo.list_all()) == 2


@pytest.mark.asyncio
async def test_list_by_status(db_session):
    repo = CaseRepository(db_session)
    a = _case("CASE-A")
    await repo.add(a)
    b = _case("CASE-B")
    await repo.add(b)
    b_inv = transition_status(b, CaseStatus.INVESTIGATING, by="a@x.com")
    await repo.update(b_inv)

    new_cases = await repo.list_by_status(CaseStatus.NEW)
    assert {c.case_id for c in new_cases} == {"CASE-A"}
    inv_cases = await repo.list_by_status(CaseStatus.INVESTIGATING)
    assert {c.case_id for c in inv_cases} == {"CASE-B"}


@pytest.mark.asyncio
async def test_find_by_title(db_session):
    repo = CaseRepository(db_session)
    await repo.add(_case("CASE-A"))
    b = new_case(
        case_id="CASE-B",
        title="Suspicious phishing incident",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )
    await repo.add(b)
    results = await repo.find("phishing")
    assert len(results) == 1
    assert results[0].case_id == "CASE-B"


@pytest.mark.asyncio
async def test_decision_persists(db_session):
    repo = CaseRepository(db_session)
    case = _case()
    await repo.add(case)
    with_dec = add_decision(
        case,
        outcome=DecisionOutcome.ESCALATE,
        rationale="Needs IR",
        by="analyst@example.com",
    )
    await repo.update(with_dec)
    fetched = await repo.get("CASE-001")
    assert len(fetched.decisions) == 1
    assert fetched.decisions[0].outcome == DecisionOutcome.ESCALATE
    assert fetched.decisions[0].rationale == "Needs IR"


@pytest.mark.asyncio
async def test_remove_case(db_session):
    repo = CaseRepository(db_session)
    await repo.add(_case())
    await repo.remove("CASE-001")
    assert await repo.get("CASE-001") is None
