"""Phase 8b - Case Store tests (test-first)."""
import pytest

from app.modules.investigation.case import (
    Case,
    CasePriority,
    CaseStatus,
    new_case,
)
from app.modules.investigation.case_store import CaseIDGenerator, CaseStore


def _make_case(case_id: str = "CASE-2026-0001") -> Case:
    return new_case(
        case_id=case_id,
        title="Test case",
        priority=CasePriority.MEDIUM,
        created_by="analyst@example.com",
    )


# ---------- CaseIDGenerator ----------
def test_id_generator_first():
    gen = CaseIDGenerator(year=2026)
    assert gen.next() == "CASE-2026-0001"


def test_id_generator_increments():
    gen = CaseIDGenerator(year=2026)
    assert gen.next() == "CASE-2026-0001"
    assert gen.next() == "CASE-2026-0002"
    assert gen.next() == "CASE-2026-0003"


def test_id_generator_per_year():
    gen_2026 = CaseIDGenerator(year=2026)
    gen_2027 = CaseIDGenerator(year=2027)
    gen_2026.next()
    gen_2026.next()
    gen_2027.next()
    assert gen_2026.next() == "CASE-2026-0003"
    assert gen_2027.next() == "CASE-2027-0002"


def test_id_generator_pads_to_4_digits():
    gen = CaseIDGenerator(year=2026)
    for _ in range(9):
        gen.next()
    assert gen.next() == "CASE-2026-0010"


# ---------- store add/get ----------
def test_store_add_and_get():
    store = CaseStore()
    c = _make_case()
    store.add(c)
    assert store.get("CASE-2026-0001") is c
    assert store.count() == 1


def test_store_add_duplicate_raises():
    store = CaseStore()
    store.add(_make_case())
    with pytest.raises(ValueError):
        store.add(_make_case())


def test_store_get_missing_returns_none():
    store = CaseStore()
    assert store.get("CASE-2026-9999") is None


# ---------- store update ----------
def test_store_update_replaces_case():
    store = CaseStore()
    c = _make_case()
    store.add(c)
    # Simulate a transition via update
    from app.modules.investigation.case import transition_status

    c2 = transition_status(c, CaseStatus.INVESTIGATING, by="analyst@example.com")
    store.update(c2)
    assert store.get("CASE-2026-0001").status == CaseStatus.INVESTIGATING


def test_store_update_missing_raises():
    store = CaseStore()
    with pytest.raises(ValueError):
        store.update(_make_case())


# ---------- store list ----------
def test_store_list_all():
    store = CaseStore()
    store.add(_make_case("CASE-2026-0001"))
    store.add(_make_case("CASE-2026-0002"))
    store.add(_make_case("CASE-2026-0003"))
    assert len(store.list_all()) == 3


def test_store_list_by_status():
    store = CaseStore()
    c1 = _make_case("CASE-2026-0001")
    c2 = _make_case("CASE-2026-0002")
    from app.modules.investigation.case import transition_status

    c2 = transition_status(c2, CaseStatus.INVESTIGATING, by="analyst@example.com")
    store.add(c1)
    store.add(c2)

    new_cases = store.list_by_status(CaseStatus.NEW)
    assert len(new_cases) == 1
    assert new_cases[0].case_id == "CASE-2026-0001"

    investigating = store.list_by_status(CaseStatus.INVESTIGATING)
    assert len(investigating) == 1


def test_store_list_by_assignee():
    store = CaseStore()
    c1 = _make_case("CASE-2026-0001")
    from app.modules.investigation.case import assign_analyst

    c1 = assign_analyst(c1, assignee="alice@example.com", by="lead@example.com")
    store.add(c1)
    store.add(_make_case("CASE-2026-0002"))

    alice_cases = store.list_by_assignee("alice@example.com")
    assert len(alice_cases) == 1
    assert alice_cases[0].case_id == "CASE-2026-0001"


def test_store_list_by_priority():
    store = CaseStore()
    c1 = new_case(
        case_id="CASE-2026-0001", title="High",
        priority=CasePriority.HIGH, created_by="a@x.com",
    )
    c2 = new_case(
        case_id="CASE-2026-0002", title="Low",
        priority=CasePriority.LOW, created_by="a@x.com",
    )
    store.add(c1)
    store.add(c2)
    assert len(store.list_by_priority(CasePriority.HIGH)) == 1


# ---------- store remove ----------
def test_store_remove():
    store = CaseStore()
    store.add(_make_case())
    store.remove("CASE-2026-0001")
    assert store.count() == 0


def test_store_remove_missing_is_silent():
    store = CaseStore()
    store.remove("CASE-2026-9999")
    assert store.count() == 0


# ---------- store find (search) ----------
def test_store_find_by_title_substring():
    store = CaseStore()
    c1 = new_case(
        case_id="CASE-2026-0001", title="Suspicious phishing email",
        priority=CasePriority.HIGH, created_by="a@x.com",
    )
    c2 = new_case(
        case_id="CASE-2026-0002", title="Malware on endpoint",
        priority=CasePriority.MEDIUM, created_by="a@x.com",
    )
    store.add(c1)
    store.add(c2)
    results = store.find("phishing")
    assert len(results) == 1
    assert results[0].case_id == "CASE-2026-0001"


def test_store_find_case_insensitive():
    store = CaseStore()
    c1 = new_case(
        case_id="CASE-2026-0001", title="Suspicious Phishing Email",
        priority=CasePriority.HIGH, created_by="a@x.com",
    )
    store.add(c1)
    assert len(store.find("PHISHING")) == 1
    assert len(store.find("phishing")) == 1
