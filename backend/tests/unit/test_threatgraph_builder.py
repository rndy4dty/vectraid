"""Phase 6c - ThreatGraph relationship builder tests (test-first)."""

from app.modules.huntscope.parser import NormalizedEvent
from app.modules.huntscope.report import HuntReport, HuntSummary
from app.modules.maltrace.classifier import ClassificationResult
from app.modules.maltrace.metadata import FileMetadata
from app.modules.phishtrace.extractor import EmailIOC, EmailIOCResult
from app.modules.phishtrace.parser import (
    EmailAuthentication,
    EmailHeaders,
    EmailMismatchFlags,
    EmailParseResult,
)
from app.modules.threatgraph.builder import (
    build_from_email,
    build_from_file,
    build_from_hunt,
)
from app.modules.threatgraph.graph import EdgeType, InMemoryGraph, NodeType


# ---------- helpers to build inputs ----------
def _empty_graph() -> InMemoryGraph:
    return InMemoryGraph()


def _email_parsed(
    from_domain: str = "spoofed-sender.test",
    reply_to_domain: str | None = "evil-collector.test",
) -> EmailParseResult:
    headers = EmailHeaders(
        from_=f"IT Support <notification@{from_domain}>",
        from_domain=from_domain,
        reply_to=f"<a@{reply_to_domain}>" if reply_to_domain else None,
        reply_to_domain=reply_to_domain,
        return_path=f"<bounce@{from_domain}>",
        return_path_domain=from_domain,
        to="victim@example.com",
        subject="Verify",
        date=None,
        authentication=EmailAuthentication(spf="fail", dkim="fail", dmarc="fail"),
    )
    return EmailParseResult(
        headers=headers,
        body_plain="See hxxps://account-update[.]bad[.]test/login",
        body_html=None,
        attachments=[],
        mismatch_flags=EmailMismatchFlags(True, False, True),
        raw_auth_header="spf=fail",
    )


def _email_iocs() -> EmailIOCResult:
    return EmailIOCResult(iocs=[
        EmailIOC("https://account-update.bad.test/login", "url", "body_plain"),
        EmailIOC("bad.test", "domain", "body_plain"),
    ])


def _file_metadata() -> FileMetadata:
    return FileMetadata(
        path="/tmp/sample.exe",
        size=1024,
        md5="a" * 32,
        sha1="b" * 40,
        sha256="c" * 64,
        pe_info=None,
        strings_sample=["powershell -enc AAAA", "http://evil.test/path"],
        strings_truncated=False,
        error=None,
    )


def _verdict(classification: str = "malicious") -> ClassificationResult:
    return ClassificationResult(
        classification=classification,
        confidence=80,
        reasons=["test"],
        evidence={"test": True},
    )


def _hunt_report() -> HuntReport:
    ev = NormalizedEvent(
        timestamp="2026-11-01T09:00:00Z",
        hostname="WKS-01",
        event_id=3,
        channel="Sysmon",
        event_type="network",
        dst_ip="203.0.113.10",
        dst_port=443,
        raw={},
    )
    from app.modules.huntscope.ioc_matcher import IOCMatch
    return HuntReport(
        rule_findings=[],
        ioc_matches=[
            IOCMatch("203.0.113.10", "ipv4", "dst_ip", ev),
        ],
        summary=HuntSummary(
            event_count=1, rule_finding_count=0, ioc_match_count=1,
            unique_hosts=1, unique_users=0,
        ),
        errors=[],
    )


# ---------- build_from_email ----------
def test_email_builder_adds_evidence_node():
    g = _empty_graph()
    build_from_email(
        _email_parsed(), _email_iocs(), g,
        evidence_id="phish-001", timestamp="2026-11-01T09:00:00Z",
    )
    assert g.node_count() >= 1
    ev_id = "evidence:phishtrace:phish-001"
    assert g.get_node(ev_id) is not None
    assert g.get_node(ev_id).node_type == NodeType.EVIDENCE


def test_email_builder_adds_ioc_nodes():
    g = _empty_graph()
    build_from_email(
        _email_parsed(), _email_iocs(), g,
        evidence_id="phish-001", timestamp="2026-11-01T09:00:00Z",
    )
    domain_node = g.get_node("ioc:domain:bad.test")
    url_node = g.get_node("ioc:url:https://account-update.bad.test/login")
    assert domain_node is not None
    assert url_node is not None


def test_email_builder_adds_header_domains():
    g = _empty_graph()
    build_from_email(
        _email_parsed(), _email_iocs(), g,
        evidence_id="phish-001", timestamp="2026-11-01T09:00:00Z",
    )
    # from_domain and reply_to_domain should be added as IOC nodes
    assert g.get_node("ioc:domain:spoofed-sender.test") is not None
    assert g.get_node("ioc:domain:evil-collector.test") is not None


def test_email_builder_adds_contains_edges():
    g = _empty_graph()
    build_from_email(
        _email_parsed(), _email_iocs(), g,
        evidence_id="phish-001", timestamp="2026-11-01T09:00:00Z",
    )
    edges = g.get_edges("evidence:phishtrace:phish-001")
    assert len(edges) >= 1
    for e in edges:
        assert e.edge_type == EdgeType.CONTAINS
        assert e.source_module == "phishtrace"


def test_email_builder_idempotent():
    g = _empty_graph()
    build_from_email(
        _email_parsed(), _email_iocs(), g,
        evidence_id="phish-001", timestamp="2026-11-01T09:00:00Z",
    )
    nodes_before = g.node_count()
    edges_before = g.edge_count()

    build_from_email(
        _email_parsed(), _email_iocs(), g,
        evidence_id="phish-001", timestamp="2026-11-01T09:00:00Z",
    )
    # Same evidence_id -> same nodes, but edges may double
    # (add_edge is not idempotent, by design: two observations = two edges)
    # Nodes must remain stable.
    assert g.node_count() == nodes_before
    # Edges may or may not double; document current behavior.
    assert g.edge_count() >= edges_before


# ---------- build_from_file ----------
def test_file_builder_adds_evidence_and_hash_node():
    g = _empty_graph()
    build_from_file(
        _file_metadata(), _verdict(), g,
        evidence_id="mal-001", timestamp="2026-11-01T09:00:00Z",
    )
    ev = g.get_node("evidence:maltrace:mal-001")
    assert ev is not None
    hash_node = g.get_node(f"ioc:sha256:{'c' * 64}")
    assert hash_node is not None


def test_file_builder_adds_url_from_strings():
    g = _empty_graph()
    build_from_file(
        _file_metadata(), _verdict(), g,
        evidence_id="mal-001", timestamp="2026-11-01T09:00:00Z",
    )
    url = g.get_node("ioc:url:http://evil.test/path")
    assert url is not None


def test_file_builder_contains_edges():
    g = _empty_graph()
    build_from_file(
        _file_metadata(), _verdict(), g,
        evidence_id="mal-001", timestamp="2026-11-01T09:00:00Z",
    )
    edges = g.get_edges("evidence:maltrace:mal-001")
    assert len(edges) >= 2  # sha256 + url
    for e in edges:
        assert e.source_module == "maltrace"


# ---------- build_from_hunt ----------
def test_hunt_builder_adds_iocs():
    g = _empty_graph()
    build_from_hunt(
        _hunt_report(), g,
        evidence_id="hunt-001", timestamp="2026-11-01T09:00:00Z",
    )
    ip = g.get_node("ioc:ipv4:203.0.113.10")
    assert ip is not None
    edges = g.get_edges("evidence:huntscope:hunt-001")
    assert any(e.edge_type == EdgeType.CONTAINS for e in edges)


# ---------- cross-module convergence ----------
def test_same_ioc_across_modules_shares_node():
    """IOC found by email and by hunt must collapse to one node."""
    g = _empty_graph()

    # Email path finds bad.test
    build_from_email(
        _email_parsed(), _email_iocs(), g,
        evidence_id="phish-001", timestamp="2026-11-01T09:00:00Z",
    )
    # Hunt path finds 203.0.113.10
    build_from_hunt(
        _hunt_report(), g,
        evidence_id="hunt-001", timestamp="2026-11-01T09:00:00Z",
    )

    # Now add a *second* email that mentions the hunt IP
    class _FakeIOCs(EmailIOCResult):
        pass
    extra = EmailIOCResult(iocs=[EmailIOC("203.0.113.10", "ipv4", "body_plain")])
    build_from_email(
        _email_parsed(),
        extra,
        g,
        evidence_id="phish-002",
        timestamp="2026-11-01T09:01:00Z",
    )
    ip = g.get_node("ioc:ipv4:203.0.113.10")
    assert ip is not None
    # It should now have incoming edges from both evidence nodes
    incoming = g.get_incoming_edges("ioc:ipv4:203.0.113.10")
    incoming_srcs = {e.src_id for e in incoming}
    assert "evidence:phishtrace:phish-002" in incoming_srcs
    assert "evidence:huntscope:hunt-001" in incoming_srcs


# ---------- empty input ----------
def test_empty_email_iocs_no_crash():
    g = _empty_graph()
    build_from_email(
        _email_parsed(), EmailIOCResult(iocs=[]), g,
        evidence_id="phish-empty", timestamp="2026-11-01T09:00:00Z",
    )
    # Should still create evidence node and header domains
    assert g.get_node("evidence:phishtrace:phish-empty") is not None
