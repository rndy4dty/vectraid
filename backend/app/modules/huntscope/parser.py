"""HuntScope JSON event parser - Phase 5a.

Parses JSON array or NDJSON into NormalizedEvent objects with a uniform
schema, regardless of source format (Sysmon vs Windows Security).

Design rules:
  - No interpretation, no detection. Only field mapping.
  - Fail-soft: unparseable events are counted in `skipped`, not fatal.
  - Unparseable input (not JSON at all) -> errors list, empty events.
  - Unknown event shapes -> skipped, not error (they may not be relevant).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class NormalizedEvent:
    timestamp: str | None
    hostname: str | None
    event_id: int | None
    channel: str | None
    event_type: str  # process | network | auth | file | registry | unknown
    process: str | None = None
    command_line: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    file_path: str | None = None
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ParseResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def parse_events(blob: str) -> ParseResult:
    """Parse a JSON array or NDJSON blob into normalized events."""
    if not blob or not blob.strip():
        return ParseResult()

    raw_events = _load_json(blob)
    if raw_events is None:
        # NDJSON fallback (one object per line)
        raw_events = _load_ndjson(blob)

    if raw_events is None:
        return ParseResult(errors=["input is not valid JSON or NDJSON"])

    events: list[NormalizedEvent] = []
    skipped = 0
    errors: list[str] = []

    for i, raw in enumerate(raw_events):
        if not isinstance(raw, dict):
            skipped += 1
            continue
        try:
            ev = _normalize(raw)
        except Exception as exc:  # noqa: BLE001 - fail-soft per event
            skipped += 1
            errors.append(f"event {i}: {type(exc).__name__}")
            continue
        if ev is None:
            skipped += 1
            continue
        events.append(ev)

    return ParseResult(events=events, skipped=skipped, errors=errors)


# ---------- input readers ----------
def _load_json(blob: str) -> list | None:
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return None


def _load_ndjson(blob: str) -> list | None:
    out: list = []
    for line in blob.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return out or None


# ---------- normalization ----------
def _normalize(raw: dict) -> NormalizedEvent | None:
    event_id = _coerce_int(raw.get("EventID"))
    channel = _coerce_str(raw.get("Channel"))

    event_type = _classify(event_id, channel)
    if event_type is None:
        return None  # unknown event shape -> caller skips

    if event_type == "process":
        return _normalize_process(raw, event_id, channel)
    if event_type == "network":
        return _normalize_network(raw, event_id, channel)
    if event_type == "auth":
        return _normalize_auth(raw, event_id, channel)
    return None


def _classify(event_id: int | None, channel: str | None) -> str | None:
    if event_id is None:
        return None

    # Sysmon
    if event_id == 1:
        return "process"
    if event_id == 3:
        return "network"
    if event_id in (11,):
        return "file"
    if event_id in (12, 13, 14):
        return "registry"

    # Windows Security
    if event_id in (4624, 4625, 4634, 4672):
        return "auth"

    return None


def _normalize_process(raw: dict, event_id: int | None, channel: str | None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_coerce_str(raw.get("UtcTime") or raw.get("TimeCreated")),
        hostname=_coerce_str(raw.get("Computer") or raw.get("Hostname")),
        event_id=event_id,
        channel=channel,
        event_type="process",
        process=_coerce_str(raw.get("Image")),
        command_line=_coerce_str(raw.get("CommandLine")),
        user=_coerce_str(raw.get("User")),
        raw=raw,
    )


def _normalize_network(raw: dict, event_id: int | None, channel: str | None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_coerce_str(raw.get("UtcTime") or raw.get("TimeCreated")),
        hostname=_coerce_str(raw.get("Computer") or raw.get("Hostname")),
        event_id=event_id,
        channel=channel,
        event_type="network",
        process=_coerce_str(raw.get("Image")),
        user=_coerce_str(raw.get("User")),
        src_ip=_coerce_str(raw.get("SourceIp") or raw.get("SourceIpAddr")),
        dst_ip=_coerce_str(raw.get("DestinationIp") or raw.get("DestIp")),
        dst_port=_coerce_int(raw.get("DestinationPort")),
        raw=raw,
    )


def _normalize_auth(raw: dict, event_id: int | None, channel: str | None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_coerce_str(raw.get("TimeCreated") or raw.get("UtcTime")),
        hostname=_coerce_str(raw.get("Computer") or raw.get("Hostname")),
        event_id=event_id,
        channel=channel,
        event_type="auth",
        user=_coerce_str(raw.get("TargetUserName")),
        src_ip=_coerce_str(raw.get("IpAddress")),
        raw=raw,
    )


# ---------- coercion ----------
def _coerce_str(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v or None
    return str(v)


def _coerce_int(v) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
