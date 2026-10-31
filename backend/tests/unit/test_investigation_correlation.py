"""Phase 7b - Correlation Engine tests (test-first)."""
from app.modules.investigation.correlation import (
    CorrelationResult,
    correlate_evidence,
)
from app.modules.investigation.evidence import Evidence, EvidenceType


def _ev(
    eid: str,
    module: str = "phishtrace",
    ioc_type: str = "domain",
    ioc_value: str = "evil.test",
    timestamp: str = "2026-11-01T09:00:00Z",
    host: str | None = None,
    confidence: int = 80,
) -> Evidence:
    provenance = {"ioc_type": ioc_type, "ioc_value": ioc_value}
    if host:
        provenance["hostname"] = host
    return Evidence(
        evidence_id=eid,
        case_id="case-001",
        source_module=module,
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        raw_reference=f"raw:{eid}",
        finding=f"found {ioc_type} {ioc_value}",
        timestamp=timestamp,
        confidence=confidence,
        provenance=provenance,
    )


# ---------- dataclass shape ----------
def test_correlation_result_fields():
    r = CorrelationResult(
        correlation_id="cor-001",
        evidence_a="ev-001",
        evidence_b="ev-002",
        correlation_type="exact_ioc",
        strength=90,
        detail="both mention evil.test",
        shared_indicators=["evil.test"],
    )
    assert r.correlation_id == "cor-001"
    assert r.strength == 90
    assert r.shared_indicators == ["evil.test"]


# ---------- exact IOC matching ----------
def test_exact_ioc_match_across_modules():
    ev1 = _ev("ev-001", module="phishtrace", ioc_type="domain", ioc_value="evil.test")
    ev2 = _ev("ev-002", module="huntscope", ioc_type="domain", ioc_value="evil.test")
    results = correlate_evidence([ev1, ev2])
    exact = [r for r in results if r.correlation_type == "exact_ioc"]
    assert len(exact) == 1
    assert set(exact[0].shared_indicators) == {"evil.test"}
    assert exact[0].evidence_a in ("ev-001", "ev-002")
    assert exact[0].evidence_b in ("ev-001", "ev-002")


def test_exact_ioc_no_match():
    ev1 = _ev("ev-001", ioc_value="evil.test")
    ev2 = _ev("ev-002", module="huntscope", ioc_value="other.test")
    results = correlate_evidence([ev1, ev2])
    exact = [r for r in results if r.correlation_type == "exact_ioc"]
    assert exact == []


def test_exact_ioc_same_module_not_correlated():
    """Same-module IOCs of the same value: not a cross-module correlation."""
    ev1 = _ev("ev-001", module="phishtrace", ioc_value="evil.test")
    ev2 = _ev("ev-002", module="phishtrace", ioc_value="evil.test")
    results = correlate_evidence([ev1, ev2])
    exact = [r for r in results if r.correlation_type == "exact_ioc"]
    assert exact == []


# ---------- multiple IOCs per evidence ----------
def test_multiple_shared_iocs():
    ev1 = _ev("ev-001", ioc_value="evil.test")
    # Manually give ev2 two IOCs by using provenance list
    ev2 = Evidence(
        evidence_id="ev-002", case_id="case-001", source_module="huntscope",
        evidence_type=EvidenceType.HUNT_FINDING,
        raw_reference="raw:ev-002", finding="found evil.test and 203.0.113.10",
        timestamp="2026-11-01T09:00:00Z", confidence=80,
        provenance={
            "ioc_type": "domain", "ioc_value": "evil.test",
            "ioc_list": ["evil.test", "203.0.113.10"],
        },
    )
    results = correlate_evidence([ev1, ev2])
    exact = [r for r in results if r.correlation_type == "exact_ioc"]
    assert len(exact) == 1
    assert "evil.test" in exact[0].shared_indicators


# ---------- temporal correlation ----------
def test_temporal_correlation_same_host():
    ev1 = _ev(
        "ev-001", module="huntscope", ioc_type="ipv4", ioc_value="203.0.113.10",
        timestamp="2026-11-01T09:00:00Z", host="WKS-01",
    )
    ev2 = _ev(
        "ev-002", module="huntscope", ioc_type="ipv4", ioc_value="198.51.100.5",
        timestamp="2026-11-01T09:05:00Z", host="WKS-01",
    )
    results = correlate_evidence([ev1, ev2])
    temporal = [r for r in results if r.correlation_type == "temporal"]
    assert len(temporal) == 1


def test_temporal_no_correlation_different_hosts():
    ev1 = _ev("ev-001", timestamp="2026-11-01T09:00:00Z", host="WKS-01")
    ev2 = _ev("ev-002", timestamp="2026-11-01T09:05:00Z", host="WKS-02")
    results = correlate_evidence([ev1, ev2])
    temporal = [r for r in results if r.correlation_type == "temporal"]
    assert temporal == []


def test_temporal_no_correlation_far_apart_in_time():
    ev1 = _ev("ev-001", timestamp="2026-11-01T09:00:00Z", host="WKS-01")
    ev2 = _ev("ev-002", timestamp="2026-11-02T09:00:00Z", host="WKS-01")
    results = correlate_evidence([ev1, ev2])
    temporal = [r for r in results if r.correlation_type == "temporal"]
    assert temporal == []


# ---------- no false positives ----------
def test_no_correlation_for_unrelated_evidence():
    ev1 = _ev("ev-001", ioc_value="a.test", timestamp="2026-11-01T09:00:00Z")
    ev2 = _ev("ev-002", ioc_value="b.test", timestamp="2026-11-02T09:00:00Z")
    results = correlate_evidence([ev1, ev2])
    assert results == []


def test_empty_input():
    assert correlate_evidence([]) == []


def test_single_evidence():
    ev = _ev("ev-001")
    assert correlate_evidence([ev]) == []
