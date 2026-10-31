"""Graph endpoints - Phase 10f.

Builds a graph from evidence in the store and exposes pivot queries.
Uses the in-memory graph from Phase 6.

Design:
  - Nodes are IOCs and evidence, derived from provenance.
  - Edges are CONTAINS relationships (evidence -> IOC).
  - Pivot returns the subgraph around an IOC (depth 2 by default).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.v1.dependencies import get_evidence_store
from app.modules.investigation.evidence import EvidenceStore
from app.modules.threatgraph.graph import EdgeType, InMemoryGraph, NodeType
from app.modules.threatgraph.types import (
    make_edge,
    make_evidence_node,
    make_ioc_node,
)

router = APIRouter(prefix="/graph", tags=["graph"])


def _build_graph_from_store(store: EvidenceStore) -> InMemoryGraph:
    """Rebuild the in-memory graph from the current evidence store."""
    g = InMemoryGraph()
    for ev in store.list_all():
        ev_node = make_evidence_node(
            evidence_id=ev.evidence_id,
            module=ev.source_module,
            description=ev.finding[:100],
            extra={"case_id": ev.case_id, "confidence": ev.confidence},
        )
        g.add_node(ev_node)

        prov = ev.provenance or {}
        iocs: list[tuple[str, str]] = []
        single = prov.get("ioc_value")
        if isinstance(single, str) and single:
            ioc_type = prov.get("ioc_type", "unknown")
            iocs.append((single, ioc_type if isinstance(ioc_type, str) else "unknown"))
        multi = prov.get("ioc_list")
        if isinstance(multi, list):
            for item in multi:
                if isinstance(item, str) and item:
                    iocs.append((item, "unknown"))

        for value, ioc_type in iocs:
            try:
                ioc_node = make_ioc_node(value, ioc_type)
            except ValueError:
                continue
            g.add_node(ioc_node)
            try:
                edge = make_edge(
                    ev_node,
                    ioc_node,
                    EdgeType.CONTAINS,
                    module=ev.source_module,
                    timestamp=ev.timestamp,
                    confidence=ev.confidence,
                )
                g.add_edge(edge)
            except ValueError:
                continue
    return g


def _serialize_subgraph(nodes, edges):
    return {
        "nodes": [
            {
                "id": n.id,
                "type": n.node_type.value,
                "label": n.label,
                "properties": n.properties,
            }
            for n in nodes
        ],
        "edges": [
            {
                "source": e.src_id,
                "target": e.dst_id,
                "type": e.edge_type.value,
                "module": e.source_module,
                "confidence": e.confidence,
                "timestamp": e.timestamp,
            }
            for e in edges
        ],
    }


@router.get("/pivot/{ioc_id}")
def pivot_graph(
    ioc_id: str,
    max_depth: int = Query(default=2, ge=1, le=5),
    store: EvidenceStore = Depends(get_evidence_store),
):
    """Return the subgraph centered on an IOC node."""
    g = _build_graph_from_store(store)
    if g.get_node(ioc_id) is None:
        raise HTTPException(status_code=404, detail="ioc not found in graph")
    nodes, edges = g.subgraph(ioc_id, max_depth=max_depth)
    return _serialize_subgraph(nodes, edges)


@router.get("/overview")
def graph_overview(
    store: EvidenceStore = Depends(get_evidence_store),
):
    """Return a summary of the graph."""
    g = _build_graph_from_store(store)
    ioc_nodes = 0
    evidence_nodes = 0
    for node_id in [n.id for n in g._nodes.values()]:  # noqa: SLF001
        n = g.get_node(node_id)
        if n is None:
            continue
        if n.node_type == NodeType.IOC:
            ioc_nodes += 1
        elif n.node_type == NodeType.EVIDENCE:
            evidence_nodes += 1
    return {
        "node_count": g.node_count(),
        "edge_count": g.edge_count(),
        "ioc_count": ioc_nodes,
        "evidence_count": evidence_nodes,
    }
