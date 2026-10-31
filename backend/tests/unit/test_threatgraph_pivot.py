"""Phase 6d - ThreatGraph pivot queries tests (test-first)."""
from app.modules.threatgraph.graph import (
    EdgeType,
    InMemoryGraph,
    NodeType,
)
from app.modules.threatgraph.pivot import (
    NeighborhoodSummary,
    find_evidence_for_ioc,
    find_path_between_iocs,
    find_related_iocs,
    find_shared_evidence,
    summarize_neighborhood,
)
from app.modules.threatgraph.types import (
    make_edge,
    make_evidence_node,
    make_ioc_node,
)


def _build_fixture_graph() -> InMemoryGraph:
    """Build:
      ev1 CONTAINS domain1, ip1
      ev2 CONTAINS ip1, ip2
    """
    g = InMemoryGraph()
    ev1 = make_evidence_node("e1", "phishtrace", "email 1")
    ev2 = make_evidence_node("e2", "huntscope", "hunt 1")
    d1 = make_ioc_node("evil.test", "domain")
    ip1 = make_ioc_node("203.0.113.10", "ipv4")
    ip2 = make_ioc_node("198.51.100.5", "ipv4")
    for n in (ev1, ev2, d1, ip1, ip2):
        g.add_node(n)
    g.add_edge(make_edge(ev1, d1, EdgeType.CONTAINS,
                        module="phishtrace", timestamp="t1"))
    g.add_edge(make_edge(ev1, ip1, EdgeType.CONTAINS,
                        module="phishtrace", timestamp="t1"))
    g.add_edge(make_edge(ev2, ip1, EdgeType.CONTAINS,
                        module="huntscope", timestamp="t2"))
    g.add_edge(make_edge(ev2, ip2, EdgeType.CONTAINS,
                        module="huntscope", timestamp="t2"))
    return g


# ---------- find_evidence_for_ioc ----------
def test_find_evidence_for_ioc():
    g = _build_fixture_graph()
    evidence = find_evidence_for_ioc(g, "ioc:ipv4:203.0.113.10")
    ids = {n.id for n in evidence}
    assert ids == {"evidence:phishtrace:e1", "evidence:huntscope:e2"}


def test_find_evidence_for_isolated_ioc():
    g = _build_fixture_graph()
    assert find_evidence_for_ioc(g, "ioc:ipv4:8.8.8.8") == []


# ---------- find_related_iocs ----------
def test_find_related_iocs_depth1():
    """From ip1, at depth 2 through evidence, we reach d1 and ip2."""
    g = _build_fixture_graph()
    related = find_related_iocs(g, "ioc:ipv4:203.0.113.10", max_depth=2)
    ids = {n.id for n in related}
    # ip1 itself must not be in the result
    assert "ioc:ipv4:203.0.113.10" not in ids
    # d1 is 2 hops away (ip1 -> ev1 -> d1)
    assert "ioc:domain:evil.test" in ids
    # ip2 is 2 hops away (ip1 -> ev2 -> ip2)
    assert "ioc:ipv4:198.51.100.5" in ids


def test_find_related_iocs_only_returns_ioc_nodes():
    g = _build_fixture_graph()
    related = find_related_iocs(g, "ioc:ipv4:203.0.113.10", max_depth=2)
    for n in related:
        assert n.node_type == NodeType.IOC


# ---------- find_shared_evidence ----------
def test_find_shared_evidence_between_two_iocs():
    g = _build_fixture_graph()
    shared = find_shared_evidence(
        g, "ioc:domain:evil.test", "ioc:ipv4:203.0.113.10"
    )
    ids = {n.id for n in shared}
    # Only ev1 contains both
    assert ids == {"evidence:phishtrace:e1"}


def test_find_shared_evidence_none():
    g = _build_fixture_graph()
    shared = find_shared_evidence(
        g, "ioc:domain:evil.test", "ioc:ipv4:198.51.100.5"
    )
    assert shared == []


# ---------- find_path_between_iocs ----------
def test_find_path_between_iocs():
    g = _build_fixture_graph()
    path = find_path_between_iocs(
        g, "ioc:domain:evil.test", "ioc:ipv4:198.51.100.5", max_depth=6
    )
    assert path is not None
    # Path must start and end with the two IOC ids
    assert path[0] == "ioc:domain:evil.test"
    assert path[-1] == "ioc:ipv4:198.51.100.5"


def test_find_path_between_iocs_none():
    g = _build_fixture_graph()
    # add an isolated IOC
    iso = make_ioc_node("9.9.9.9", "ipv4")
    g.add_node(iso)
    path = find_path_between_iocs(
        g, "ioc:domain:evil.test", "ioc:ipv4:9.9.9.9", max_depth=6
    )
    assert path is None


# ---------- summarize_neighborhood ----------
def test_summarize_neighborhood():
    g = _build_fixture_graph()
    summary = summarize_neighborhood(g, "ioc:ipv4:203.0.113.10", max_depth=2)
    assert isinstance(summary, NeighborhoodSummary)
    assert summary.ioc_count >= 2
    assert summary.evidence_count >= 2
    assert summary.edge_type_counts.get("contains", 0) >= 4


def test_summarize_neighborhood_isolated():
    g = _build_fixture_graph()
    iso = make_ioc_node("9.9.9.9", "ipv4")
    g.add_node(iso)
    summary = summarize_neighborhood(g, "ioc:ipv4:9.9.9.9", max_depth=2)
    assert summary.ioc_count == 0
    assert summary.evidence_count == 0
    assert summary.edge_type_counts == {}
