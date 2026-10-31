"""Phase 7a - Evidence Management tests (test-first)."""
import pytest

from app.modules.investigation.evidence import (
    Evidence,
    EvidenceStore,
    EvidenceType,
)


# ---------- dataclass shape ----------
def test_evidence_fields():
    e = Evidence(
        evidence_id="ev-001",
        case_id="case-001",
        source_module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        raw_reference="evidence:phishtrace:phish-001",
        finding="SPF failed, DKIM failed, DMARC failed",
        timestamp="2026-11-01T09:00:00Z",
        confidence=90,
        provenance={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
    )
    assert e.evidence_id == "ev-001"
    assert e.source_module == "phishtrace"
    assert e.confidence == 90


def test_evidence_confidence_validation():
    with pytest.raises(ValueError):
        Evidence(
            evidence_id="x", case_id="c", source_module="m",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="r", finding="f", timestamp="t",
            confidence=150,
            provenance={},
        )
    with pytest.raises(ValueError):
        Evidence(
            evidence_id="x", case_id="c", source_module="m",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="r", finding="f", timestamp="t",
            confidence=-1,
            provenance={},
        )


def test_evidence_requires_raw_reference():
    with pytest.raises(ValueError):
        Evidence(
            evidence_id="x", case_id="c", source_module="m",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="", finding="f", timestamp="t",
            confidence=50, provenance={},
        )


def test_evidence_requires_timestamp():
    with pytest.raises(ValueError):
        Evidence(
            evidence_id="x", case_id="c", source_module="m",
            evidence_type=EvidenceType.EMAIL_ANALYSIS,
            raw_reference="r", finding="f", timestamp="",
            confidence=50, provenance={},
        )


# ---------- EvidenceType ----------
def test_evidence_types():
    assert EvidenceType.EMAIL_ANALYSIS.value == "email_analysis"
    assert EvidenceType.FILE_ANALYSIS.value == "file_analysis"
    assert EvidenceType.HUNT_FINDING.value == "hunt_finding"
    assert EvidenceType.IOC_MATCH.value == "ioc_match"
    assert EvidenceType.THREAT_INTEL.value == "threat_intel"


# ---------- store ----------
def _make_ev(evidence_id: str = "ev-001", case_id: str = "case-001") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        case_id=case_id,
        source_module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        raw_reference="r",
        finding="f",
        timestamp="2026-11-01T09:00:00Z",
        confidence=80,
        provenance={},
    )


def test_store_add_and_get():
    store = EvidenceStore()
    ev = _make_ev()
    store.add(ev)
    assert store.get("ev-001") is ev
    assert store.count() == 1


def test_store_add_duplicate_raises():
    store = EvidenceStore()
    store.add(_make_ev())
    with pytest.raises(ValueError):
        store.add(_make_ev())


def test_store_get_missing_returns_none():
    store = EvidenceStore()
    assert store.get("nope") is None


def test_store_list_by_case():
    store = EvidenceStore()
    store.add(_make_ev("ev-001", "case-A"))
    store.add(_make_ev("ev-002", "case-A"))
    store.add(_make_ev("ev-003", "case-B"))
    case_a = store.list_by_case("case-A")
    assert len(case_a) == 2
    assert {e.evidence_id for e in case_a} == {"ev-001", "ev-002"}


def test_store_list_by_module():
    store = EvidenceStore()
    ev1 = Evidence(
        evidence_id="ev-001", case_id="case-A", source_module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        raw_reference="r", finding="f", timestamp="t",
        confidence=80, provenance={},
    )
    ev2 = Evidence(
        evidence_id="ev-002", case_id="case-A", source_module="maltrace",
        evidence_type=EvidenceType.FILE_ANALYSIS,
        raw_reference="r", finding="f", timestamp="t",
        confidence=80, provenance={},
    )
    store.add(ev1)
    store.add(ev2)
    assert len(store.list_by_module("phishtrace")) == 1
    assert len(store.list_by_module("maltrace")) == 1


def test_store_remove():
    store = EvidenceStore()
    store.add(_make_ev())
    store.remove("ev-001")
    assert store.count() == 0
    assert store.get("ev-001") is None


def test_store_remove_missing_is_silent():
    store = EvidenceStore()
    store.remove("nope")
    assert store.count() == 0
