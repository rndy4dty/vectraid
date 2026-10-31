"""HuntScope IOC matcher - Phase 5d.

Searches for known IOCs across normalized event fields. Per (event, ioc)
we record at most one match, with the first field that hit.

Design rules:
  - IOC type inferred from format unless explicitly overridden.
  - Field priority: src_ip -> dst_ip -> command_line -> process -> file_path.
  - Empty/invalid IOC values are skipped and counted in errors.
  - No dedup across events: the same IOC can match multiple events.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.modules.huntscope.parser import NormalizedEvent

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# Field search order when a single event has many fields.
_FIELD_PRIORITY = ("src_ip", "dst_ip", "command_line", "process", "file_path")


@dataclass(frozen=True)
class IOCMatch:
    ioc: str
    ioc_type: str
    field: str
    event: NormalizedEvent


@dataclass(frozen=True)
class IOCMatchResult:
    matches: list[IOCMatch] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    event_count: int = 0
    ioc_count: int = 0


def match_iocs(
    events: list[NormalizedEvent],
    iocs: list[str],
    ioc_types: dict[str, str] | None = None,
) -> IOCMatchResult:
    """Search for each IOC across all events. One match per (event, ioc)."""
    if not iocs:
        return IOCMatchResult(matches=[], errors=[], event_count=len(events), ioc_count=0)

    overrides = ioc_types or {}
    normalized_iocs: list[tuple[str, str]] = []
    errors: list[str] = []

    for raw in iocs:
        if not isinstance(raw, str) or not raw.strip():
            errors.append(f"skipped empty ioc: {raw!r}")
            continue
        value = raw.strip()
        kind = overrides.get(value) or _infer_type(value)
        normalized_iocs.append((value, kind))

    matches: list[IOCMatch] = []

    for event in events:
        for ioc_value, ioc_kind in normalized_iocs:
            hit_field = _find_field(event, ioc_value, ioc_kind)
            if hit_field is None:
                continue
            matches.append(
                IOCMatch(
                    ioc=ioc_value,
                    ioc_type=ioc_kind,
                    field=hit_field,
                    event=event,
                )
            )

    return IOCMatchResult(
        matches=matches,
        errors=errors,
        event_count=len(events),
        ioc_count=len(iocs),
    )


# ---------- internal ----------
def _infer_type(value: str) -> str:
    if _HEX64.match(value):
        return "sha256"
    if _HEX40.match(value):
        return "sha1"
    if _HEX32.match(value):
        return "md5"
    if _IPV4.match(value) and all(0 <= int(p) <= 255 for p in value.split(".")):
        return "ipv4"
    if _DOMAIN.match(value):
        return "domain"
    return "unknown"


def _find_field(event: NormalizedEvent, ioc_value: str, ioc_kind: str) -> str | None:
    """Return the first field that contains this IOC, honoring priority."""
    needle = ioc_value.lower()
    for field_name in _FIELD_PRIORITY:
        hay = getattr(event, field_name, None)
        if not hay:
            continue
        hay_l = hay.lower()
        if ioc_kind in ("ipv4", "domain", "unknown"):
            # Exact token match for IP/domain to avoid substring false positives.
            if _token_match(hay_l, needle):
                return field_name
        else:
            # Hash: substring is fine (hashes appear inside longer strings).
            if needle in hay_l:
                return field_name
    return None


def _token_match(haystack: str, needle: str) -> bool:
    """Token-based match: needle must appear as a whole token in haystack.

    Boundaries: whitespace, punctuation, slash, comma, semicolon, quotes,
    parentheses, brackets.
    """
    if not needle:
        return False
    pattern = r"(?<![A-Za-z0-9._-])" + re.escape(needle) + r"(?![A-Za-z0-9._-])"
    return re.search(pattern, haystack) is not None
