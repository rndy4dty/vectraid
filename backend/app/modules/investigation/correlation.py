"""Investigation correlation engine - Phase 7b.

Finds evidence pairs that are meaningfully related. Each correlation is
explicit and explainable:

  - exact_ioc   : two evidence from different modules mention the same IOC
  - temporal    : two evidence from the same host within a time window

No correlation is inferred. Every result carries a human-readable detail
string and the shared indicator(s) that justify it.

Phase 7b intentionally does NOT do:
  - domain-IP inference (needs ThreatGraph resolution data)
  - infrastructure similarity (needs curated domain lists)
Those arrive later if and when their inputs exist.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from app.modules.investigation.evidence import Evidence

# How close in time (seconds) two events from the same host must be
# to count as temporally correlated.
_TEMPORAL_WINDOW_SECONDS = 3600  # 1 hour

# Strength contribution per correlation kind (calibrated in Phase 7f).
_STRENGTH_EXACT_IOC = 90
_STRENGTH_TEMPORAL = 40


@dataclass(frozen=True)
class CorrelationResult:
    correlation_id: str
    evidence_a: str
    evidence_b: str
    correlation_type: str
    strength: int
    detail: str
    shared_indicators: list[str] = field(default_factory=list)


def correlate_evidence(
    evidence_list: list[Evidence],
) -> list[CorrelationResult]:
    """Find correlations between every pair of evidence. Read-only."""
    if len(evidence_list) < 2:
        return []

    results: list[CorrelationResult] = []
    seen_pairs: set[tuple[str, str, str]] = set()

    for i, a in enumerate(evidence_list):
        for b in evidence_list[i + 1:]:
            for result in _correlate_pair(a, b):
                key = (
                    result.correlation_id,
                    result.evidence_a,
                    result.evidence_b,
                )
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                results.append(result)

    return results


# ---------- per-pair correlation ----------
def _correlate_pair(a: Evidence, b: Evidence) -> list[CorrelationResult]:
    out: list[CorrelationResult] = []

    exact = _exact_ioc_correlation(a, b)
    if exact is not None:
        out.append(exact)

    temporal = _temporal_correlation(a, b)
    if temporal is not None:
        out.append(temporal)

    return out


# ---------- exact IOC ----------
def _exact_ioc_correlation(
    a: Evidence, b: Evidence
) -> CorrelationResult | None:
    # Cross-module only.
    if a.source_module == b.source_module:
        return None

    iocs_a = _iocs_in(a)
    iocs_b = _iocs_in(b)
    shared = sorted(iocs_a & iocs_b)
    if not shared:
        return None

    corr_id = _make_id("exact_ioc", a.evidence_id, b.evidence_id)
    detail = (
        f"Both evidence mention the same IOC(s): {', '.join(shared)} "
        f"(modules: {a.source_module}, {b.source_module})"
    )
    return CorrelationResult(
        correlation_id=corr_id,
        evidence_a=a.evidence_id,
        evidence_b=b.evidence_id,
        correlation_type="exact_ioc",
        strength=_STRENGTH_EXACT_IOC,
        detail=detail,
        shared_indicators=shared,
    )


def _iocs_in(ev: Evidence) -> set[str]:
    """Extract IOC values from an evidence's provenance.

    Expected shape (set by producers):
      - ioc_value: str          (single indicator)
      - ioc_list: list[str]     (multiple indicators)
    """
    out: set[str] = set()
    prov = ev.provenance or {}

    single = prov.get("ioc_value")
    if isinstance(single, str) and single:
        out.add(single.lower())

    multi = prov.get("ioc_list")
    if isinstance(multi, list):
        for item in multi:
            if isinstance(item, str) and item:
                out.add(item.lower())

    return out


# ---------- temporal ----------
def _temporal_correlation(
    a: Evidence, b: Evidence
) -> CorrelationResult | None:
    host_a = (a.provenance or {}).get("hostname")
    host_b = (b.provenance or {}).get("hostname")
    if not host_a or not host_b:
        return None
    if host_a != host_b:
        return None

    ts_a = _parse_ts(a.timestamp)
    ts_b = _parse_ts(b.timestamp)
    if ts_a is None or ts_b is None:
        return None

    delta = abs((ts_a - ts_b).total_seconds())
    if delta > _TEMPORAL_WINDOW_SECONDS:
        return None

    corr_id = _make_id("temporal", a.evidence_id, b.evidence_id)
    detail = (
        f"Both evidence from host {host_a} within "
        f"{int(delta)}s of each other"
    )
    return CorrelationResult(
        correlation_id=corr_id,
        evidence_a=a.evidence_id,
        evidence_b=b.evidence_id,
        correlation_type="temporal",
        strength=_STRENGTH_TEMPORAL,
        detail=detail,
        shared_indicators=[],
    )


# ---------- helpers ----------
def _make_id(kind: str, eid_a: str, eid_b: str) -> str:
    raw = f"{kind}:{eid_a}:{eid_b}".encode()
    digest = hashlib.sha1(raw).hexdigest()[:12]
    return f"cor-{kind}-{digest}"


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    # Tolerate trailing Z by converting to +00:00
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None
