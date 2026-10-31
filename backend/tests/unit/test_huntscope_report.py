"""Phase 5e - HuntScope report aggregation tests (test-first)."""
from app.modules.huntscope.parser import NormalizedEvent
from app.modules.huntscope.report import HuntReport, HuntSummary, build_report


def _process_event(
    process: str = "", cmd: str = "", host: str = "WKS-01", user: str = "u1"
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2026-11-01T09:00:00Z",
        hostname=host,
        event_id=1,
        channel="Sysmon",
        event_type="process",
        process=process,
        command_line=cmd,
        user=user,
        raw={"EventID": 1},
    )


def _network_event(
    dst_ip: str = "", host: str = "WKS-01", ts: str = "2026-11-01T09:05:00Z"
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=ts,
        hostname=host,
        event_id=3,
        channel="Sysmon",
        event_type="network",
        dst_ip=dst_ip,
        raw={"EventID": 3},
    )


def _auth_event(
    event_id: int = 4625,
    host: str = "WKS-01",
    user: str = "admin",
    ts: str = "2026-11-01T09:10:00Z",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=ts,
        hostname=host,
        event_id=event_id,
        channel="Security",
        event_type="auth",
        user=user,
        raw={"EventID": event_id},
    )


# ---------- dataclass shape ----------
def test_summary_shape():
    s = HuntSummary(
        event_count=5,
        rule_finding_count=3,
        ioc_match_count=2,
        unique_hosts=2,
        unique_users=3,
        severity_breakdown={"high": 1, "medium": 2},
        time_range=("2026-11-01T09:00:00Z", "2026-11-01T10:00:00Z"),
    )
    assert s.event_count == 5
    assert s.severity_breakdown["high"] == 1


def test_report_shape():
    r = HuntReport(
        rule_findings=[],
        ioc_matches=[],
        summary=HuntSummary(
            event_count=0,
            rule_finding_count=0,
            ioc_match_count=0,
            unique_hosts=0,
            unique_users=0,
            severity_breakdown={},
            time_range=(None, None),
        ),
        errors=[],
    )
    assert r.rule_findings == []


# ---------- empty events ----------
def test_empty_events_produce_empty_report():
    r = build_report([])
    assert r.rule_findings == []
    assert r.ioc_matches == []
    assert r.summary.event_count == 0
    assert r.summary.unique_hosts == 0


# ---------- rule findings only ----------
def test_report_with_rule_findings_only():
    events = [
        _process_event("powershell.exe", "powershell.exe -enc XXXX"),
        _process_event("notepad.exe", "notepad.exe"),
    ]
    r = build_report(events)
    assert r.summary.event_count == 2
    assert r.summary.rule_finding_count >= 1
    assert any(
        f.rule_id == "process_powershell_encoded" for f in r.rule_findings
    )


# ---------- ioc matches only ----------
def test_report_with_ioc_matches_only():
    events = [
        _network_event(dst_ip="203.0.113.10"),
        _network_event(dst_ip="8.8.8.8"),
    ]
    r = build_report(events, iocs=["203.0.113.10"])
    assert r.summary.event_count == 2
    assert r.summary.ioc_match_count == 1
    assert r.ioc_matches[0].ioc == "203.0.113.10"


# ---------- combined ----------
def test_report_combines_rules_and_iocs():
    events = [
        _process_event("powershell.exe", "powershell.exe -enc XXXX"),
        _network_event(dst_ip="203.0.113.10"),
        _auth_event(4625),
    ]
    r = build_report(events, iocs=["203.0.113.10"])
    assert r.summary.rule_finding_count >= 2
    assert r.summary.ioc_match_count == 1


# ---------- unique hosts / users ----------
def test_unique_hosts_and_users():
    events = [
        _process_event("x.exe", host="WKS-01", user="alice"),
        _process_event("y.exe", host="WKS-01", user="bob"),
        _process_event("z.exe", host="WKS-02", user="alice"),
        _auth_event(4625, host="WKS-02", user="admin"),
    ]
    r = build_report(events)
    assert r.summary.unique_hosts == 2
    assert r.summary.unique_users == 3


# ---------- severity breakdown ----------
def test_severity_breakdown():
    events = [
        _process_event("powershell.exe", "powershell.exe -enc XXXX"),
        _process_event(
            "rundll32.exe", "rundll32.exe C:\\Users\\Public\\x.dll,Main"
        ),
    ]
    r = build_report(events)
    assert r.summary.severity_breakdown.get("high", 0) >= 2


# ---------- time range ----------
def test_time_range():
    events = [
        _network_event(dst_ip="8.8.8.8", ts="2026-11-01T08:00:00Z"),
        _network_event(dst_ip="1.1.1.1", ts="2026-11-01T10:30:00Z"),
        _network_event(dst_ip="9.9.9.9", ts="2026-11-01T09:15:00Z"),
    ]
    r = build_report(events)
    assert r.summary.time_range == (
        "2026-11-01T08:00:00Z",
        "2026-11-01T10:30:00Z",
    )


# ---------- errors propagated ----------
def test_errors_from_ioc_matching_propagated():
    events = [_network_event(dst_ip="203.0.113.10")]
    r = build_report(events, iocs=["", "203.0.113.10"])
    assert len(r.errors) >= 1
