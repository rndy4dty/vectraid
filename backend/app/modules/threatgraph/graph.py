"""ThreatGraph in-memory graph - Phase 6a.

Defines the graph interface (BaseGraph) and an in-memory implementation
(InMemoryGraph) backed by plain dicts.

Design rules:
  - Evidence-backed: every edge carries source_module, confidence, timestamp.
  - No inferred edges: only relations supported by evidence are added.
  - Deterministic: BFS finds shortest path; iteration order is stable.
  - No Neo4j dependency in this module. Adapter for Neo4j comes later.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum


class NodeType(StrEnum):
    IOC = "ioc"
    EVIDENCE = "evidence"
    CASE = "case"
    HOST = "host"
    USER = "user"


class EdgeType(StrEnum):
    CONTAINS = "contains"
    RESOLVES_TO = "resolves_to"
    REFERENCES = "references"
    OBSERVED_IN = "observed_in"
    SAME_AS = "same_as"
    COMMUNICATES_WITH = "communicates_with"


@dataclass(frozen=True)
class GraphNode:
    id: str
    node_type: NodeType
    label: str
    properties: dict = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    src_id: str
    dst_id: str
    edge_type: EdgeType
    source_module: str
    confidence: int
    timestamp: str
    properties: dict = field(default_factory=dict)


class BaseGraph(ABC):
    """Abstract graph interface. Implementations must be deterministic."""

    @abstractmethod
    def add_node(self, node: GraphNode) -> str: ...

    @abstractmethod
    def add_edge(self, edge: GraphEdge) -> None: ...

    @abstractmethod
    def get_node(self, node_id: str) -> GraphNode | None: ...

    @abstractmethod
    def get_edges(
        self, from_id: str, to_id: str | None = None
    ) -> list[GraphEdge]: ...

    @abstractmethod
    def neighbors(
        self, node_id: str, edge_type: EdgeType | None = None
    ) -> list[GraphNode]: ...

    @abstractmethod
    def find_path(
        self, src_id: str, dst_id: str, max_depth: int = 5
    ) -> list[str] | None: ...

    @abstractmethod
    def subgraph(
        self, root_id: str, max_depth: int = 2
    ) -> tuple[list[GraphNode], list[GraphEdge]]: ...

    @abstractmethod
    def node_count(self) -> int: ...

    @abstractmethod
    def edge_count(self) -> int: ...


class InMemoryGraph(BaseGraph):
    """Pure-Python graph backed by dicts.

    - nodes: id -> GraphNode
    - adjacency: src_id -> list[GraphEdge] (outgoing only)
    - reverse: dst_id -> list[GraphEdge] (incoming only)
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._adj: dict[str, list[GraphEdge]] = {}
        self._rev: dict[str, list[GraphEdge]] = {}
        self._edge_count = 0

    # ---------- nodes ----------
    def add_node(self, node: GraphNode) -> str:
        self._nodes[node.id] = node
        self._adj.setdefault(node.id, [])
        self._rev.setdefault(node.id, [])
        return node.id

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def node_count(self) -> int:
        return len(self._nodes)

    # ---------- edges ----------
    def add_edge(self, edge: GraphEdge) -> None:
        if edge.src_id not in self._nodes:
            raise ValueError(f"src node not found: {edge.src_id}")
        if edge.dst_id not in self._nodes:
            raise ValueError(f"dst node not found: {edge.dst_id}")
        self._adj[edge.src_id].append(edge)
        self._rev[edge.dst_id].append(edge)
        self._edge_count += 1

    def get_edges(
        self, from_id: str, to_id: str | None = None
    ) -> list[GraphEdge]:
        edges = self._adj.get(from_id, [])
        if to_id is None:
            return list(edges)
        return [e for e in edges if e.dst_id == to_id]

    def edge_count(self) -> int:
        return self._edge_count

    # ---------- traversal ----------
    def neighbors(
        self, node_id: str, edge_type: EdgeType | None = None
    ) -> list[GraphNode]:
        out: list[GraphNode] = []
        seen: set[str] = set()
        for edge in self._adj.get(node_id, []):
            if edge_type is not None and edge.edge_type != edge_type:
                continue
            if edge.dst_id in seen:
                continue
            node = self._nodes.get(edge.dst_id)
            if node is None:
                continue
            seen.add(edge.dst_id)
            out.append(node)
        return out

    def find_path(
        self, src_id: str, dst_id: str, max_depth: int = 5
    ) -> list[str] | None:
        if src_id not in self._nodes or dst_id not in self._nodes:
            return None
        if src_id == dst_id:
            return [src_id]

        queue: deque[tuple[str, list[str]]] = deque([(src_id, [src_id])])
        visited: set[str] = {src_id}

        while queue:
            current, path = queue.popleft()
            if len(path) - 1 >= max_depth:
                continue
            for edge in self._adj.get(current, []):
                nxt = edge.dst_id
                if nxt in visited:
                    continue
                new_path = path + [nxt]
                if nxt == dst_id:
                    return new_path
                visited.add(nxt)
                queue.append((nxt, new_path))
        return None

    def subgraph(
        self, root_id: str, max_depth: int = 2
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        if root_id not in self._nodes:
            return [], []

        visited_nodes: dict[str, GraphNode] = {root_id: self._nodes[root_id]}
        collected_edges: list[GraphEdge] = []
        queue: deque[tuple[str, int]] = deque([(root_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self._adj.get(current, []):
                collected_edges.append(edge)
                if edge.dst_id not in visited_nodes:
                    node = self._nodes.get(edge.dst_id)
                    if node is not None:
                        visited_nodes[edge.dst_id] = node
                        queue.append((edge.dst_id, depth + 1))

        return list(visited_nodes.values()), collected_edges
