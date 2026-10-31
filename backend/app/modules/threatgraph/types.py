"""ThreatGraph node/edge factories - Phase 6b.

Builds GraphNode and GraphEdge instances with deterministic IDs and
required provenance. This is the only sanctioned way to create nodes
and edges for ThreatGraph - it enforces ID determinism so that the same
IOC discovered by different modules collapses to one node.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from app.modules.threatgraph.graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)


# ---------- IOC node ----------
def make_ioc_node(
    value: str,
    ioc_type: str,
    *,
    source: str | None = None,
) -> GraphNode:
    """Build an IOC node with a deterministic ID.

    Normalization rules (must match Phase 1b):
      - domain, hash: lowercase
      - ipv4: as-is (already canonical)
      - url: lowercase scheme/host, preserve path/query case
    """
    normalized = _normalize_ioc_value(value, ioc_type)
    node_id = f"ioc:{ioc_type}:{normalized}"
    props: dict = {"ioc_type": ioc_type}
    if source:
        props["source"] = source
    return GraphNode(
        id=node_id,
        node_type=NodeType.IOC,
        label=normalized,
        properties=props,
    )


# ---------- evidence node ----------
def make_evidence_node(
    evidence_id: str,
    module: str,
    description: str,
    *,
    extra: dict | None = None,
) -> GraphNode:
    if not evidence_id or not module:
        raise ValueError("evidence_id and module are required")
    props: dict = {"module": module}
    if extra:
        props.update(extra)
    return GraphNode(
        id=f"evidence:{module}:{evidence_id}",
        node_type=NodeType.EVIDENCE,
        label=description or evidence_id,
        properties=props,
    )


# ---------- host node ----------
def make_host_node(hostname: str) -> GraphNode:
    h = hostname.strip().lower()
    if not h:
        raise ValueError("hostname is required")
    return GraphNode(
        id=f"host:{h}",
        node_type=NodeType.HOST,
        label=h,
        properties={"hostname": h},
    )


# ---------- user node ----------
def make_user_node(username: str) -> GraphNode:
    u = username.strip().lower()
    if not u:
        raise ValueError("username is required")
    return GraphNode(
        id=f"user:{u}",
        node_type=NodeType.USER,
        label=u,
        properties={"username": u},
    )


# ---------- case node ----------
def make_case_node(case_id: str) -> GraphNode:
    c = case_id.strip().lower()
    if not c:
        raise ValueError("case_id is required")
    return GraphNode(
        id=f"case:{c}",
        node_type=NodeType.CASE,
        label=c,
        properties={"case_id": c},
    )


# ---------- edge ----------
def make_edge(
    src: GraphNode,
    dst: GraphNode,
    edge_type: EdgeType,
    *,
    module: str,
    timestamp: str,
    confidence: int = 50,
    properties: dict | None = None,
) -> GraphEdge:
    if not module:
        raise ValueError("edge requires a source module")
    if not timestamp:
        raise ValueError("edge requires a timestamp")

    clamped = max(0, min(100, int(confidence)))

    return GraphEdge(
        src_id=src.id,
        dst_id=dst.id,
        edge_type=edge_type,
        source_module=module,
        confidence=clamped,
        timestamp=timestamp,
        properties=dict(properties or {}),
    )


# ---------- internal ----------
def _normalize_ioc_value(value: str, ioc_type: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("IOC value is required")

    kind = ioc_type.lower()

    if kind == "domain":
        out = v.lower()
        if out.endswith("."):
            out = out[:-1]
        return out

    if kind in ("md5", "sha1", "sha256"):
        return v.lower()

    if kind == "ipv4":
        return v

    if kind == "url":
        try:
            parts = urlsplit(v)
        except ValueError:
            return v
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        netloc = host
        if parts.port is not None:
            netloc = f"{host}:{parts.port}"
        return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))

    # Unknown type: pass through as-is (no normalization guarantee)
    return v
