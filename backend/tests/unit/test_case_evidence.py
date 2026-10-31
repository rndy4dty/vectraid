"""Phase 8c - Case evidence linking tests (test-first)."""
import pytest

from app.modules.investigation.case import (
    CasePriority,
    new_case,
)
from app.modules.investigation.case_evidence import (
    has_evidence,
    link_evidence,
    list_evidence_ids,
    unlink_evidence,
)
from app.modules.investigation.evidence import (
    Evidence,
    EvidenceStore,
    EvidenceType,
)


def _make_case():
    return new_case(
        case_id="CASE-2026-0001",
        title="Test case",
        priority=CasePriority.HIGH,
        created_by="analyst@example.com",
    )


def _make_evidence(eid: str = "ev-001") -> Evidence:
    return Evidence(
        evidence_id=eid,
        case_id="CASE-2026-0001",
        source_module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        raw_reference=f"raw:{eid}",
        finding="test",
        timestamp="2026-11-01T09:00:00Z",
        confidence=80,
        provenance={},
    )


# ---------- link ----------
def test_link_evidence_adds_id():
    case = _make_case()
    case2 = link_evidence(case, "ev-001", by="analyst@example.com")
    assert "ev-001" in list_evidence_ids(case2)
    # original unchanged
    assert "ev-001" not in list_evidence_ids(case)


def test_link_evidence_appends_history():
    case = _make_case()
    case2 = link_evidence(case, "ev-001", by="analyst@example.com")
    assert len(case2.history) == 2
    assert case2.history[-1].action == "evidence_linked"
    assert case2.history[-1].detail["evidence_id"] == "ev-001"


def test_link_evidence_requires_actor():
    case = _make_case()
    with pytest.raises(ValueError):
        link_evidence(case, "ev-001", by="")


def test_link_evidence_requires_id():
    case = _make_case()
    with pytest.raises(ValueError):
        link_evidence(case, "", by="analyst@example.com")


def test_link_evidence_idempotent():
    """Linking the same evidence twice does not duplicate."""
    case = _make_case()
    case2 = link_evidence(case, "ev-001", by="analyst@example.com")
    case3 = link_evidence(case2, "ev-001", by="analyst@example.com")
    ids = list_evidence_ids(case3)
    assert ids.count("ev-001") == 1


def test_link_with_store_validates():
    """If a store is provided, unknown evidence IDs are rejected."""
    store = EvidenceStore()
    store.add(_make_evidence("ev-001"))
    case = _make_case()

    # valid link
    case2 = link_evidence(case, "ev-001", by="a@x.com", store=store)
    assert "ev-001" in list_evidence_ids(case2)

    # invalid link
    with pytest.raises(ValueError):
        link_evidence(case, "ev-999", by="a@x.com", store=store)


# ---------- unlink ----------
def test_unlink_evidence():
    case = _make_case()
    case = link_evidence(case, "ev-001", by="analyst@example.com")
    case = unlink_evidence(case, "ev-001", by="analyst@example.com")
    assert "ev-001" not in list_evidence_ids(case)


def test_unlink_appends_history():
    case = _make_case()
    case = link_evidence(case, "ev-001", by="analyst@example.com")
    case = unlink_evidence(case, "ev-001", by="analyst@example.com")
    assert case.history[-1].action == "evidence_unlinked"
    assert case.history[-1].detail["evidence_id"] == "ev-001"


def test_unlink_missing_is_noop():
    case = _make_case()
    case2 = unlink_evidence(case, "ev-999", by="analyst@example.com")
    assert len(case2.history) == len(case.history)


def test_unlink_requires_actor():
    case = _make_case()
    with pytest.raises(ValueError):
        unlink_evidence(case, "ev-001", by="")


# ---------- has_evidence ----------
def test_has_evidence():
    case = _make_case()
    case = link_evidence(case, "ev-001", by="analyst@example.com")
    assert has_evidence(case, "ev-001") is True
    assert has_evidence(case, "ev-999") is False


# ---------- list_evidence_ids ----------
def test_list_evidence_ids_returns_copy():
    """Mutating the returned list must not affect the case."""
    case = _make_case()
    case = link_evidence(case, "ev-001", by="analyst@example.com")
    ids = list_evidence_ids(case)
    ids.append("ev-999")
    assert "ev-999" not in list_evidence_ids(case)


def test_list_evidence_ids_preserves_insertion_order():
    case = _make_case()
    case = link_evidence(case, "ev-003", by="a@x.com")
    case = link_evidence(case, "ev-001", by="a@x.com")
    case = link_evidence(case, "ev-002", by="a@x.com")
    assert list_evidence_ids(case) == ["ev-003", "ev-001", "ev-002"]
