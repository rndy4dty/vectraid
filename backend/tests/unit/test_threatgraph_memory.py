"""Phase 6a - ThreatGraph in-memory implementation tests (test-first)."""
import pytest

from app.modules.threatgraph.graph import (
    BaseGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    InMemoryGraph,
    NodeType,
)


def _ioc_node(node_id: str, value: str, kind: str = "ipv4") -> GraphNode:
    return GraphNode(
        id=node_id,
        node_type=NodeType.IOC,
        label=value,
        properties={"ioc_type": kind},
    )


def _evidence_node(node_id: str, label: str) -> GraphNode:
    return GraphNode(
        id=node_id,
        node_type=NodeType.EVIDENCE,
        label=label,
        properties={"module": "test"},
    )


def _edge(
    src: str, dst: str, etype: EdgeType = EdgeType.REFERENCES
) -> GraphEdge:
    return GraphEdge(
        src_id=src,
        dst_id=dst,
        edge_type=etype,
        source_module="test",
        confidence=80,
        timestamp="2026-11-01T09:00:00Z",
    )


# ---------- enum and dataclass shapes ----------
def test_node_types():
    assert NodeType.IOC.value == "ioc"
    assert NodeType.EVIDENCE.value == "evidence"
    assert NodeType.CASE.value == "case"
    assert NodeType.HOST.value == "host"
    assert NodeType.USER.value == "user"


def test_edge_types():
    assert EdgeType.CONTAINS.value == "contains"
    assert EdgeType.RESOLVES_TO.value == "resolves_to"
    assert EdgeType.REFERENCES.value == "references"
    assert EdgeType.OBSERVED_IN.value == "observed_in"
    assert EdgeType.SAME_AS.value == "same_as"
    assert EdgeType.COMMUNICATES_WITH.value == "communicates_with"


def test_node_dataclass():
    n = _ioc_node("n1", "203.0.113.10")
    assert n.id == "n1"
    assert n.node_type == NodeType.IOC
    assert n.label == "203.0.113.10"
    assert n.properties["ioc_type"] == "ipv4"


def test_edge_dataclass():
    e = _edge("n1", "n2")
    assert e.src_id == "n1"
    assert e.dst_id == "n2"
    assert e.edge_type == EdgeType.REFERENCES
    assert e.confidence == 80
    assert e.source_module == "test"


# ---------- abstract base ----------
def test_base_graph_is_abstract():
    with pytest.raises(TypeError):
        BaseGraph()


# ---------- add node ----------
def test_add_node_returns_id():
    g = InMemoryGraph()
    n = _ioc_node("n1", "example.test", "domain")
    returned = g.add_node(n)
    assert returned == "n1"


def test_add_node_twice_upserts():
    g = InMemoryGraph()
    n1 = _ioc_node("n1", "old.test", "domain")
    n2 = _ioc_node("n1", "new.test", "domain")
    g.add_node(n1)
    g.add_node(n2)
    fetched = g.get_node("n1")
    assert fetched.label == "new.test"


def test_get_node_returns_none_for_missing():
    g = InMemoryGraph()
    assert g.get_node("nope") is None


# ---------- add edge ----------
def test_add_edge_requires_both_nodes():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    # n2 missing -> should raise
    with pytest.raises(ValueError):
        g.add_edge(_edge("n1", "n2"))


def test_add_edge_stores():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_evidence_node("n2", "ev1"))
    g.add_edge(_edge("n1", "n2"))
    edges = g.get_edges("n1")
    assert len(edges) == 1
    assert edges[0].dst_id == "n2"


def test_get_edges_filtered_by_dst():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_evidence_node("n2", "ev1"))
    g.add_node(_evidence_node("n3", "ev2"))
    g.add_edge(_edge("n1", "n2"))
    g.add_edge(_edge("n1", "n3"))
    only_n2 = g.get_edges("n1", to_id="n2")
    assert len(only_n2) == 1
    assert only_n2[0].dst_id == "n2"


# ---------- neighbors ----------
def test_neighbors():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_ioc_node("n2", "203.0.113.10", "ipv4"))
    g.add_edge(_edge("n1", "n2", EdgeType.RESOLVES_TO))
    neighbors = g.neighbors("n1")
    assert len(neighbors) == 1
    assert neighbors[0].id == "n2"


def test_neighbors_filtered_by_edge_type():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_ioc_node("n2", "203.0.113.10", "ipv4"))
    g.add_node(_evidence_node("n3", "ev1"))
    g.add_edge(_edge("n1", "n2", EdgeType.RESOLVES_TO))
    g.add_edge(_edge("n1", "n3", EdgeType.REFERENCES))
    only_resolves = g.neighbors("n1", edge_type=EdgeType.RESOLVES_TO)
    assert len(only_resolves) == 1
    assert only_resolves[0].id == "n2"


# ---------- find_path ----------
def test_find_path_simple():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_ioc_node("n2", "203.0.113.10", "ipv4"))
    g.add_node(_evidence_node("n3", "ev1"))
    g.add_edge(_edge("n1", "n2", EdgeType.RESOLVES_TO))
    g.add_edge(_edge("n2", "n3", EdgeType.REFERENCES))
    path = g.find_path("n1", "n3")
    assert path == ["n1", "n2", "n3"]


def test_find_path_no_route():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_ioc_node("n2", "b.test", "domain"))
    # No edge
    assert g.find_path("n1", "n2") is None


def test_find_path_same_node():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    assert g.find_path("n1", "n1") == ["n1"]


def test_find_path_respects_max_depth():
    g = InMemoryGraph()
    for i in range(1, 6):
        g.add_node(_ioc_node(f"n{i}", f"v{i}.test", "domain"))
    for i in range(1, 5):
        g.add_edge(_edge(f"n{i}", f"n{i+1}", EdgeType.RESOLVES_TO))
    # n1 -> n2 -> n3 -> n4 -> n5 = depth 4
    # max_depth=2 should fail
    assert g.find_path("n1", "n5", max_depth=2) is None
    # max_depth=5 should succeed
    assert g.find_path("n1", "n5", max_depth=5) == ["n1", "n2", "n3", "n4", "n5"]


# ---------- subgraph ----------
def test_subgraph():
    g = InMemoryGraph()
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_ioc_node("n2", "203.0.113.10", "ipv4"))
    g.add_node(_evidence_node("n3", "ev1"))
    g.add_edge(_edge("n1", "n2", EdgeType.RESOLVES_TO))
    g.add_edge(_edge("n2", "n3", EdgeType.REFERENCES))
    nodes, edges = g.subgraph("n1", max_depth=2)
    node_ids = {n.id for n in nodes}
    assert node_ids == {"n1", "n2", "n3"}
    assert len(edges) == 2


# ---------- counts ----------
def test_counts():
    g = InMemoryGraph()
    assert g.node_count() == 0
    assert g.edge_count() == 0
    g.add_node(_ioc_node("n1", "a.test", "domain"))
    g.add_node(_evidence_node("n2", "ev1"))
    assert g.node_count() == 2
    g.add_edge(_edge("n1", "n2"))
    assert g.edge_count() == 1
