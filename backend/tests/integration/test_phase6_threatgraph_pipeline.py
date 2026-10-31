"""Phase 6 integration - end-to-end ThreatGraph pipeline.

Simulates: analyst processes an email (PhishTrace), a file (MalTrace),
and logs (HuntScope), then pivots between IOCs in the resulting graph.

No network. All fixtures are synthetic.
"""
from app.modules.huntscope.ioc_matcher import IOCMatch
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
from app.modules.threatgraph.graph import InMemoryGraph, NodeType
from app.modules.threatgraph.pivot import (
    find_evidence_for_ioc,
    find_path_between_iocs,
    find_related_iocs,
    find_shared_evidence,
    summarize_neighborhood,
)

# ---------- synthetic inputs ----------
SHARED_DOMAIN = "evil.test"
SHARED_IP = "203.0.113.10"
OTHER_IP = "198.51.100.5"


def _email_inputs():
    headers = EmailHeaders(
        from_=f"IT <n@{SHARED_DOMAIN}>",
        from_domain=SHARED_DOMAIN,
        reply_to="<a@collector.test>",
        reply_to_domain="collector.test",
        return_path=f"<b@{SHARED_DOMAIN}>",
        return_path_domain=SHARED_DOMAIN,
        to="victim@example.com",
        subject="Verify",
        date=None,
        authentication=EmailAuthentication(spf="fail", dkim="fail", dmarc="fail"),
    )
    parsed = EmailParseResult(
        headers=headers,
        body_plain="See hxxps://evil[.]test/login",
        body_html=None,
        attachments=[],
        mismatch_flags=EmailMismatchFlags(True, False, True),
        raw_auth_header="spf=fail",
    )
    iocs = EmailIOCResult(iocs=[
        EmailIOC(f"https://{SHARED_DOMAIN}/login", "url", "body_plain"),
        EmailIOC(SHARED_IP, "ipv4", "body_plain"),
    ])
    return parsed, iocs


def _file_inputs():
    meta = FileMetadata(
        path="/tmp/sample.exe",
        size=1024,
        md5="a" * 32,
        sha1="b" * 40,
        sha256="c" * 64,
        pe_info=None,
        strings_sample=[
            f"connect to {SHARED_IP}",
            f"http://{SHARED_DOMAIN}/c2",
            f"also contacts {SHARED_DOMAIN}",
        ],
        strings_truncated=False,
        error=None,
    )
    verdict = ClassificationResult(
        classification="malicious",
        confidence=80,
        reasons=["test"],
        evidence={},
    )
    return meta, verdict


def _hunt_inputs():
    ev = NormalizedEvent(
        timestamp="2026-11-01T09:00:00Z",
        hostname="WKS-01",
        event_id=3,
        channel="Sysmon",
        event_type="network",
        dst_ip=SHARED_IP,
        dst_port=443,
        raw={},
    )
    ev2 = NormalizedEvent(
        timestamp="2026-11-01T09:05:00Z",
        hostname="WKS-01",
        event_id=3,
        channel="Sysmon",
        event_type="network",
        dst_ip=OTHER_IP,
        dst_port=4444,
        raw={},
    )
    report = HuntReport(
        rule_findings=[],
        ioc_matches=[
            IOCMatch(SHARED_IP, "ipv4", "dst_ip", ev),
            IOCMatch(OTHER_IP, "ipv4", "dst_ip", ev2),
        ],
        summary=HuntSummary(
            event_count=2,
            rule_finding_count=0,
            ioc_match_count=2,
            unique_hosts=1,
            unique_users=0,
        ),
        errors=[],
    )
    return report


def _build_full_graph() -> InMemoryGraph:
    g = InMemoryGraph()

    parsed, email_iocs = _email_inputs()
    build_from_email(
        parsed, email_iocs, g,
        evidence_id="phish-001", timestamp="2026-11-01T08:00:00Z",
    )

    meta, verdict = _file_inputs()
    build_from_file(
        meta, verdict, g,
        evidence_id="mal-001", timestamp="2026-11-01T08:30:00Z",
    )

    report = _hunt_inputs()
    build_from_hunt(
        report, g,
        evidence_id="hunt-001", timestamp="2026-11-01T09:10:00Z",
    )

    return g


# ---------- graph content ----------
def test_graph_has_three_evidence_nodes():
    g = _build_full_graph()
    evidence_nodes = [
        n for n in
        [g.get_node("evidence:phishtrace:phish-001"),
         g.get_node("evidence:maltrace:mal-001"),
         g.get_node("evidence:huntscope:hunt-001")]
        if n is not None
    ]
    assert len(evidence_nodes) == 3
    for n in evidence_nodes:
        assert n.node_type == NodeType.EVIDENCE


def test_graph_has_shared_ioc():
    g = _build_full_graph()
    # SHARED_IP appears in all three modules
    node = g.get_node(f"ioc:ipv4:{SHARED_IP}")
    assert node is not None
    # It should have incoming edges from all three evidence nodes
    incoming = g.get_incoming_edges(f"ioc:ipv4:{SHARED_IP}")
    srcs = {e.src_id for e in incoming}
    assert "evidence:phishtrace:phish-001" in srcs
    assert "evidence:maltrace:mal-001" in srcs
    assert "evidence:huntscope:hunt-001" in srcs


def test_graph_has_shared_domain():
    g = _build_full_graph()
    node = g.get_node(f"ioc:domain:{SHARED_DOMAIN}")
    assert node is not None
    incoming = g.get_incoming_edges(f"ioc:domain:{SHARED_DOMAIN}")
    # Should be referenced by both email and file
    srcs = {e.src_id for e in incoming}
    assert "evidence:phishtrace:phish-001" in srcs
    assert "evidence:maltrace:mal-001" in srcs


# ---------- pivot queries ----------
def test_pivot_evidence_for_shared_ip():
    g = _build_full_graph()
    evidence = find_evidence_for_ioc(g, f"ioc:ipv4:{SHARED_IP}")
    ids = {n.id for n in evidence}
    assert ids == {
        "evidence:phishtrace:phish-001",
        "evidence:maltrace:mal-001",
        "evidence:huntscope:hunt-001",
    }


def test_pivot_related_iocs_from_shared_ip():
    g = _build_full_graph()
    related = find_related_iocs(g, f"ioc:ipv4:{SHARED_IP}", max_depth=2)
    related_ids = {n.id for n in related}
    # From SHARED_IP we should reach: SHARED_DOMAIN, OTHER_IP, the hash
    assert f"ioc:domain:{SHARED_DOMAIN}" in related_ids
    assert f"ioc:ipv4:{OTHER_IP}" in related_ids


def test_pivot_shared_evidence_between_ip_and_domain():
    g = _build_full_graph()
    shared = find_shared_evidence(
        g,
        f"ioc:ipv4:{SHARED_IP}",
        f"ioc:domain:{SHARED_DOMAIN}",
    )
    ids = {n.id for n in shared}
    # Both appear in email and file evidence
    assert "evidence:phishtrace:phish-001" in ids
    assert "evidence:maltrace:mal-001" in ids


def test_pivot_path_between_ip_and_other_ip():
    g = _build_full_graph()
    path = find_path_between_iocs(
        g,
        f"ioc:ipv4:{SHARED_IP}",
        f"ioc:ipv4:{OTHER_IP}",
        max_depth=6,
    )
    assert path is not None
    assert path[0] == f"ioc:ipv4:{SHARED_IP}"
    assert path[-1] == f"ioc:ipv4:{OTHER_IP}"


def test_neighborhood_summary():
    g = _build_full_graph()
    summary = summarize_neighborhood(g, f"ioc:ipv4:{SHARED_IP}", max_depth=2)
    assert summary.ioc_count >= 2
    assert summary.evidence_count >= 3
    assert summary.edge_type_counts.get("contains", 0) >= 3


# ---------- cross-module convergence ----------
def test_cross_module_convergence_is_single_node():
    """SHARED_IP node must exist exactly once, even though 3 modules added it."""
    g = _build_full_graph()
    # node_count should be the number of unique nodes, not total edge count
    # SHARED_IP was added 3 times (once per module) but must be one node
    assert g.get_node(f"ioc:ipv4:{SHARED_IP}") is not None
    # Verify only one such node exists by checking node_count doesn't
    # double-count
    nodes, edges = g.subgraph(f"ioc:ipv4:{SHARED_IP}", max_depth=1)
    # The IOC itself appears once
    ioc_nodes = [n for n in nodes if n.id == f"ioc:ipv4:{SHARED_IP}"]
    assert len(ioc_nodes) == 1
