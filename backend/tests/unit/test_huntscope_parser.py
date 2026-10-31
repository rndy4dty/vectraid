"""Phase 5a - HuntScope JSON event parser tests (test-first)."""
from pathlib import Path

from app.modules.huntscope.parser import (
    NormalizedEvent,
    ParseResult,
    parse_events,
)

_FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "logs"
)


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text()


# ---------- dataclass shape ----------
def test_normalized_event_fields():
    e = NormalizedEvent(
        timestamp="2026-11-01T09:00:00Z",
        hostname="WKS-01",
        event_id=1,
        channel="Sysmon",
        event_type="process",
        process="C:\\Windows\\notepad.exe",
        command_line="notepad.exe",
        user="alice",
        src_ip=None,
        dst_ip=None,
        dst_port=None,
        file_path=None,
        raw={"x": 1},
    )
    assert e.event_id == 1
    assert e.event_type == "process"
    assert e.raw == {"x": 1}


def test_parse_result_shape():
    r = ParseResult(events=[], skipped=0, errors=[])
    assert r.events == []
    assert r.skipped == 0


# ---------- parse Sysmon process events ----------
def test_parse_sysmon_process_events():
    result = parse_events(_load("sysmon_process.json"))
    assert isinstance(result, ParseResult)
    assert len(result.events) == 3
    assert result.skipped == 0

    first = result.events[0]
    assert first.hostname == "WORKSTATION-01"
    assert first.event_id == 1
    assert first.event_type == "process"
    assert "notepad.exe" in (first.process or "")
    assert "notes.txt" in (first.command_line or "")


def test_parse_sysmon_process_detects_powershell_event():
    result = parse_events(_load("sysmon_process.json"))
    ps_events = [
        e for e in result.events
        if e.process and "powershell.exe" in e.process.lower()
    ]
    assert len(ps_events) == 1
    assert "-enc" in (ps_events[0].command_line or "")


# ---------- parse Windows Security events ----------
def test_parse_windows_auth_events():
    result = parse_events(_load("windows_auth.json"))
    assert len(result.events) == 4
    assert result.skipped == 0

    types = {e.event_type for e in result.events}
    assert "auth" in types

    failed = [e for e in result.events if e.event_id == 4625]
    assert len(failed) == 3


def test_parse_windows_auth_populates_src_ip():
    result = parse_events(_load("windows_auth.json"))
    failed = [e for e in result.events if e.event_id == 4625]
    assert all(e.src_ip == "203.0.113.5" for e in failed)


# ---------- parse network events ----------
def test_parse_sysmon_network_events():
    result = parse_events(_load("sysmon_network.json"))
    assert len(result.events) == 2
    net_events = [e for e in result.events if e.event_type == "network"]
    assert len(net_events) == 2

    first = net_events[0]
    assert first.dst_ip == "203.0.113.10"
    assert first.dst_port == 443
    assert first.src_ip == "10.0.0.42"


# ---------- fail-soft ----------
def test_parse_empty_returns_empty():
    result = parse_events("")
    assert result.events == []
    assert result.skipped == 0


def test_parse_invalid_json_returns_error():
    result = parse_events("this is not json")
    assert result.events == []
    assert len(result.errors) >= 1


def test_parse_skips_unknown_events():
    """Events that don't match any known format are skipped, not fatal."""
    blob = (
        '[{"Something": "unrelated"}, '
        '{"EventID": 1, "UtcTime": "2026-11-01T09:00:00Z", '
        '"Computer": "x", "Image": "y"}]'
    )
    result = parse_events(blob)
    assert len(result.events) == 1
    assert result.skipped >= 1


def test_parse_ndjson_supported():
    """Newline-delimited JSON (one event per line) also supported."""
    blob = (
        '{"EventID": 1, "UtcTime": "2026-11-01T09:00:00Z", "Computer": "x", "Image": "a.exe"}\n'
        '{"EventID": 1, "UtcTime": "2026-11-01T09:01:00Z", "Computer": "x", "Image": "b.exe"}\n'
    )
    result = parse_events(blob)
    assert len(result.events) == 2
