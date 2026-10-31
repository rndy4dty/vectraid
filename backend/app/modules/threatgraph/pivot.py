"""ThreatGraph pivot queries - Phase 6d.

Read-only queries over the graph that help an analyst pivot from one IOC
to related IOCs through shared evidence.

Design rules:
  - All queries are read-only.
  - No edges are inferred: we only traverse edges that exist.
  - Results are deterministic (BFS order, dedup by node id).
  - Return GraphNode / GraphEdge objects; callers serialize as needed.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from app.modules.threatgraph.graph import (
    BaseGraph,
    EdgeType,
    GraphNode,
    NodeType,
)


@dataclass(frozen=True)
class NeighborhoodSummary:
    ioc_count: int
    evidence_count: int
    edge_type_counts: dict[str, int] = field(default_factory=dict)
    max_depth_reached: int = 0


# ---------- evidence for an IOC ----------
def find_evidence_for_ioc(
    graph: BaseGraph, ioc_id: str
) -> list[GraphNode]:
    """Return evidence nodes that CONTAIN this IOC (incoming edges)."""
    out: list[GraphNode] = []
    seen: set[str] = set()
    for edge in graph.get_incoming_edges(ioc_id):
        if edge.edge_type != EdgeType.CONTAINS:
            continue
        if edge.src_id in seen:
            continue
        node = graph.get_node(edge.src_id)
        if node is None or node.node_type != NodeType.EVIDENCE:
            continue
        seen.add(edge.src_id)
        out.append(node)
    return out


# ---------- related IOCs ----------
def find_related_iocs(
    graph: BaseGraph, ioc_id: str, max_depth: int = 2
) -> list[GraphNode]:
    """Return IOC nodes reachable from ioc_id within max_depth edges.

    Traverses both directions (IOC -> evidence -> IOC), but only returns
    IOC-type nodes; the starting IOC is excluded.
    """
    if graph.get_node(ioc_id) is None:
        return []

    related: list[GraphNode] = []
    seen_nodes: set[str] = {ioc_id}

    queue: deque[tuple[str, int]] = deque([(ioc_id, 0)])

    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue

        # Outgoing edges
        for edge in graph.get_edges(current):
            nxt = edge.dst_id
            if nxt in seen_nodes:
                continue
            seen_nodes.add(nxt)
            node = graph.get_node(nxt)
            if node is None:
                continue
            if node.node_type == NodeType.IOC and node.id != ioc_id:
                related.append(node)
            queue.append((nxt, depth + 1))

        # Incoming edges
        for edge in graph.get_incoming_edges(current):
            nxt = edge.src_id
            if nxt in seen_nodes:
                continue
            seen_nodes.add(nxt)
            node = graph.get_node(nxt)
            if node is None:
                continue
            if node.node_type == NodeType.IOC and node.id != ioc_id:
                related.append(node)
            queue.append((nxt, depth + 1))

    return related


# ---------- shared evidence ----------
def find_shared_evidence(
    graph: BaseGraph, ioc_a: str, ioc_b: str
) -> list[GraphNode]:
    """Return evidence that CONTAINS both IOCs."""
    if ioc_a == ioc_b:
        return []
    evidence_a = {n.id for n in find_evidence_for_ioc(graph, ioc_a)}
    evidence_b = {n.id for n in find_evidence_for_ioc(graph, ioc_b)}
    shared_ids = evidence_a & evidence_b
    out: list[GraphNode] = []
    for eid in shared_ids:
        node = graph.get_node(eid)
        if node is not None:
            out.append(node)
    return out


# ---------- path between two IOCs ----------
def find_path_between_iocs(
    graph: BaseGraph,
    ioc_a: str,
    ioc_b: str,
    max_depth: int = 4,
) -> list[str] | None:
    """Shortest path (edge count) between two IOC ids, or None if unreachable."""
    if graph.get_node(ioc_a) is None or graph.get_node(ioc_b) is None:
        return None
    return graph.find_path(ioc_a, ioc_b, max_depth=max_depth)


# ---------- neighborhood summary ----------
def summarize_neighborhood(
    graph: BaseGraph, ioc_id: str, max_depth: int = 2
) -> NeighborhoodSummary:
    """Summarize the subgraph around an IOC."""
    if graph.get_node(ioc_id) is None:
        return NeighborhoodSummary(
            ioc_count=0, evidence_count=0, edge_type_counts={}, max_depth_reached=0
        )

    nodes, edges = graph.subgraph(ioc_id, max_depth=max_depth)

    ioc_count = sum(
        1 for n in nodes
        if n.node_type == NodeType.IOC and n.id != ioc_id
    )
    evidence_count = sum(
        1 for n in nodes if n.node_type == NodeType.EVIDENCE
    )

    edge_counts: dict[str, int] = {}
    for e in edges:
        key = e.edge_type.value
        edge_counts[key] = edge_counts.get(key, 0) + 1

    return NeighborhoodSummary(
        ioc_count=ioc_count,
        evidence_count=evidence_count,
        edge_type_counts=edge_counts,
        max_depth_reached=max_depth,
    )
