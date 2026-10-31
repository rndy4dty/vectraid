"""Phase 6b - ThreatGraph node/edge factories tests (test-first)."""
import pytest

from app.modules.threatgraph.graph import EdgeType, NodeType
from app.modules.threatgraph.types import (
    make_case_node,
    make_edge,
    make_evidence_node,
    make_host_node,
    make_ioc_node,
    make_user_node,
)


# ---------- IOC node ----------
def test_ioc_node_id_is_deterministic():
    n1 = make_ioc_node("Example.TEST", "domain")
    n2 = make_ioc_node("example.test", "domain")
    assert n1.id == n2.id
    assert n1.id == "ioc:domain:example.test"


def test_ioc_node_different_types_different_ids():
    a = make_ioc_node("example.test", "domain")
    b = make_ioc_node("example.test", "url")
    assert a.id != b.id


def test_ioc_node_has_type_and_label():
    n = make_ioc_node("203.0.113.10", "ipv4")
    assert n.node_type == NodeType.IOC
    assert n.label == "203.0.113.10"
    assert n.properties["ioc_type"] == "ipv4"


def test_ioc_node_normalizes_hash_case():
    h1 = make_ioc_node("ABCDEF" + "0" * 58, "sha256")
    h2 = make_ioc_node(("ABCDEF" + "0" * 58).lower(), "sha256")
    assert h1.id == h2.id


def test_ioc_node_url_keeps_path_case():
    """URL path case is significant; only scheme/host lowercased."""
    a = make_ioc_node("https://example.test/Path", "url")
    b = make_ioc_node("https://example.test/path", "url")
    assert a.id != b.id


# ---------- evidence node ----------
def test_evidence_node_id():
    n = make_evidence_node("ev-123", "phishtrace", "SPF failed")
    assert n.id == "evidence:phishtrace:ev-123"
    assert n.node_type == NodeType.EVIDENCE
    assert n.label == "SPF failed"
    assert n.properties["module"] == "phishtrace"


# ---------- host node ----------
def test_host_node_lowercases():
    n = make_host_node("WORKSTATION-01")
    assert n.id == "host:workstation-01"
    assert n.node_type == NodeType.HOST


# ---------- user node ----------
def test_user_node_lowercases():
    n = make_user_node("CORP\\Alice")
    assert n.id == "user:corp\\alice"
    assert n.node_type == NodeType.USER


# ---------- case node ----------
def test_case_node():
    n = make_case_node("CASE-2026-0001")
    assert n.id == "case:case-2026-0001"
    assert n.node_type == NodeType.CASE


# ---------- edge ----------
def test_edge_requires_source_module():
    src = make_ioc_node("example.test", "domain")
    dst = make_ioc_node("203.0.113.10", "ipv4")
    with pytest.raises(ValueError):
        make_edge(
            src, dst, EdgeType.RESOLVES_TO,
            module="",  # empty
            timestamp="2026-11-01T09:00:00Z",
        )


def test_edge_requires_timestamp():
    src = make_ioc_node("example.test", "domain")
    dst = make_ioc_node("203.0.113.10", "ipv4")
    with pytest.raises(ValueError):
        make_edge(
            src, dst, EdgeType.RESOLVES_TO,
            module="threatgraph",
            timestamp="",
        )


def test_edge_confidence_clamped():
    src = make_ioc_node("example.test", "domain")
    dst = make_ioc_node("203.0.113.10", "ipv4")
    e = make_edge(
        src, dst, EdgeType.RESOLVES_TO,
        module="threatgraph",
        confidence=150,
        timestamp="2026-11-01T09:00:00Z",
    )
    assert e.confidence == 100
    e2 = make_edge(
        src, dst, EdgeType.RESOLVES_TO,
        module="threatgraph",
        confidence=-5,
        timestamp="2026-11-01T09:00:00Z",
    )
    assert e2.confidence == 0


def test_edge_fields():
    src = make_ioc_node("example.test", "domain")
    dst = make_ioc_node("203.0.113.10", "ipv4")
    e = make_edge(
        src, dst, EdgeType.RESOLVES_TO,
        module="threatgraph",
        confidence=80,
        timestamp="2026-11-01T09:00:00Z",
        properties={"resolver": "dns"},
    )
    assert e.src_id == "ioc:domain:example.test"
    assert e.dst_id == "ioc:ipv4:203.0.113.10"
    assert e.edge_type == EdgeType.RESOLVES_TO
    assert e.source_module == "threatgraph"
    assert e.confidence == 80
    assert e.timestamp == "2026-11-01T09:00:00Z"
    assert e.properties["resolver"] == "dns"


# ---------- real-world scenario ----------
def test_scenario_phishing_pivot():
    """PhishTrace extracts evil.test and 203.0.113.10 from an email."""
    email_ev = make_evidence_node("phish-001", "phishtrace", "Suspicious email")
    domain = make_ioc_node("evil.test", "domain")
    ip = make_ioc_node("203.0.113.10", "ipv4")

    edge1 = make_edge(
        email_ev, domain, EdgeType.CONTAINS,
        module="phishtrace", timestamp="2026-11-01T09:00:00Z",
    )
    edge2 = make_edge(
        domain, ip, EdgeType.RESOLVES_TO,
        module="threatgraph", timestamp="2026-11-01T09:01:00Z",
    )

    assert edge1.src_id == email_ev.id
    assert edge1.dst_id == domain.id
    assert edge2.edge_type == EdgeType.RESOLVES_TO


# ---------- cross-module IOC coincidence ----------
def test_same_ioc_from_different_modules_shares_node_id():
    """An IOC found by PhishTrace and HuntScope must yield the same node id."""
    from_phish = make_ioc_node("evil.test", "domain")
    from_hunt = make_ioc_node("evil.test", "domain")
    assert from_phish.id == from_hunt.id
