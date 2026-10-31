"""ThreatGraph relationship builder - Phase 6c.

Reads outputs of PhishTrace, MalTrace, and HuntScope, and adds nodes and
edges to a graph. Only evidence-backed relations are added: each edge
originates from an evidence node.

Design rules:
  - Every relationship must be justified by evidence (the evidence node
    is the source of the edge).
  - Node IDs are deterministic (via make_ioc_node); the graph upserts
    nodes, so cross-module IOC convergence "just works".
  - Edges are not deduplicated: two observations are two facts.
  - Fail-soft per IOC: bad values are skipped, not fatal.
"""
from __future__ import annotations

import re

from app.engine.extraction.ioc_extractor import extract_iocs
from app.modules.huntscope.report import HuntReport
from app.modules.maltrace.classifier import ClassificationResult
from app.modules.maltrace.metadata import FileMetadata
from app.modules.phishtrace.extractor import EmailIOCResult
from app.modules.phishtrace.parser import EmailParseResult
from app.modules.threatgraph.graph import (
    BaseGraph,
    EdgeType,
)
from app.modules.threatgraph.types import (
    make_edge,
    make_evidence_node,
    make_ioc_node,
)

# A conservative list of string fragments that likely represent IOCs.
_URL_LIKE = re.compile(r"^https?://", re.IGNORECASE)


# ---------- PhishTrace -> graph ----------
def build_from_email(
    parsed: EmailParseResult,
    iocs: EmailIOCResult,
    graph: BaseGraph,
    *,
    evidence_id: str,
    timestamp: str,
) -> None:
    """Add nodes/edges from an email analysis into the graph."""
    evidence = make_evidence_node(
        evidence_id=evidence_id,
        module="phishtrace",
        description=parsed.headers.subject or "email",
        extra={
            "from_domain": parsed.headers.from_domain,
            "subject": parsed.headers.subject,
        },
    )
    graph.add_node(evidence)

    seen: set[str] = set()

    def _add_ioc(ioc_value: str, ioc_type: str) -> None:
        if not ioc_value:
            return
        try:
            node = make_ioc_node(ioc_value, ioc_type)
        except ValueError:
            return
        if node.id in seen:
            return
        seen.add(node.id)
        graph.add_node(node)
        edge = make_edge(
            evidence,
            node,
            EdgeType.CONTAINS,
            module="phishtrace",
            timestamp=timestamp,
            confidence=80,
            properties={"ioc_type": ioc_type},
        )
        graph.add_edge(edge)

    # Header domains (from/reply_to/return_path)
    for domain in (
        parsed.headers.from_domain,
        parsed.headers.reply_to_domain,
        parsed.headers.return_path_domain,
    ):
        if domain:
            _add_ioc(domain, "domain")

    # Body/header IOCs already extracted in EmailIOCResult
    for ioc in iocs.iocs:
        _add_ioc(ioc.value, ioc.ioc_type)


# ---------- MalTrace -> graph ----------
def build_from_file(
    metadata: FileMetadata,
    verdict: ClassificationResult,
    graph: BaseGraph,
    *,
    evidence_id: str,
    timestamp: str,
) -> None:
    """Add nodes/edges from a file analysis into the graph."""
    evidence = make_evidence_node(
        evidence_id=evidence_id,
        module="maltrace",
        description=f"file {metadata.path}",
        extra={
            "sha256": metadata.sha256,
            "verdict": verdict.classification,
            "confidence": verdict.confidence,
        },
    )
    graph.add_node(evidence)

    seen: set[str] = set()

    def _add_ioc(ioc_value: str, ioc_type: str) -> None:
        if not ioc_value:
            return
        try:
            node = make_ioc_node(ioc_value, ioc_type)
        except ValueError:
            return
        if node.id in seen:
            return
        seen.add(node.id)
        graph.add_node(node)
        edge = make_edge(
            evidence,
            node,
            EdgeType.CONTAINS,
            module="maltrace",
            timestamp=timestamp,
            confidence=min(100, max(50, verdict.confidence)),
            properties={"ioc_type": ioc_type},
        )
        graph.add_edge(edge)

    # SHA256 is always present for a file
    _add_ioc(metadata.sha256, "sha256")

    # Extract IOCs from strings_sample
    if metadata.strings_sample:
        joined = "\n".join(metadata.strings_sample)
        try:
            result = extract_iocs(joined, source="maltrace:strings")
        except Exception:  # noqa: BLE001 - fail-soft
            result = None
        if result is not None:
            for ioc in result.iocs:
                _add_ioc(ioc.value, ioc.ioc_type)


# ---------- HuntScope -> graph ----------
def build_from_hunt(
    report: HuntReport,
    graph: BaseGraph,
    *,
    evidence_id: str,
    timestamp: str,
) -> None:
    """Add nodes/edges from a hunt report into the graph."""
    evidence = make_evidence_node(
        evidence_id=evidence_id,
        module="huntscope",
        description="hunt report",
        extra={
            "event_count": report.summary.event_count,
            "rule_finding_count": report.summary.rule_finding_count,
            "ioc_match_count": report.summary.ioc_match_count,
        },
    )
    graph.add_node(evidence)

    seen: set[str] = set()

    def _add_ioc(ioc_value: str, ioc_type: str) -> None:
        if not ioc_value:
            return
        try:
            node = make_ioc_node(ioc_value, ioc_type)
        except ValueError:
            return
        if node.id in seen:
            return
        seen.add(node.id)
        graph.add_node(node)
        edge = make_edge(
            evidence,
            node,
            EdgeType.CONTAINS,
            module="huntscope",
            timestamp=timestamp,
            confidence=70,
            properties={"ioc_type": ioc_type},
        )
        graph.add_edge(edge)

    for match in report.ioc_matches:
        _add_ioc(match.ioc, match.ioc_type)
