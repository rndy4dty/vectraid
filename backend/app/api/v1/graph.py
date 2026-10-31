"""Graph endpoints - Phase 10f.

Builds a graph from evidence in the store and exposes pivot queries.
Uses the in-memory graph from Phase 6.
"""
from __future__ import annotations

import re

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

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_URL = re.compile(r"^https?://", re.IGNORECASE)


def _infer_ioc_type(value: str) -> str:
    v = value.strip()
    if _URL.match(v):
        return "url"
    if _HEX64.match(v):
        return "sha256"
    if _HEX40.match(v):
        return "sha1"
    if _HEX32.match(v):
        return "md5"
    if _IPV4.match(v) and all(0 <= int(p) <= 255 for p in v.split(".")):
        return "ipv4"
    if _DOMAIN.match(v):
        return "domain"
    if "@" in v:
        return "email"
    return "unknown"


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

        # Collect (value, type) pairs. Prefer explicit ioc_type; fall back
        # to format inference.
        candidates: list[tuple[str, str]] = []

        single = prov.get("ioc_value")
        if isinstance(single, str) and single:
            explicit = prov.get("ioc_type")
            t = explicit if isinstance(explicit, str) and explicit else _infer_ioc_type(single)
            candidates.append((single, t))

        multi = prov.get("ioc_list")
        if isinstance(multi, list):
            for item in multi:
                if isinstance(item, str) and item:
                    # Infer type; ioc_list has no per-item type info.
                    candidates.append((item, _infer_ioc_type(item)))

        seen_ids: set[str] = set()
        for value, ioc_type in candidates:
            try:
                ioc_node = make_ioc_node(value, ioc_type)
            except ValueError:
                continue
            if ioc_node.id in seen_ids:
                continue
            seen_ids.add(ioc_node.id)
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
    g = _build_graph_from_store(store)
    if g.get_node(ioc_id) is None:
        raise HTTPException(status_code=404, detail="ioc not found in graph")
    nodes, edges = g.subgraph(ioc_id, max_depth=max_depth)
    return _serialize_subgraph(nodes, edges)


@router.get("/overview")
def graph_overview(
    store: EvidenceStore = Depends(get_evidence_store),
):
    g = _build_graph_from_store(store)
    ioc_count = 0
    evidence_count = 0
    for node in g.all_nodes():
        if node.node_type == NodeType.IOC:
            ioc_count += 1
        elif node.node_type == NodeType.EVIDENCE:
            evidence_count += 1
    return {
        "node_count": g.node_count(),
        "edge_count": g.edge_count(),
        "ioc_count": ioc_count,
        "evidence_count": evidence_count,
    }
