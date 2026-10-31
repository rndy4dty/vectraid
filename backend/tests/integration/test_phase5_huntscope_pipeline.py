"""Phase 5 integration - end-to-end HuntScope pipeline.

Simulates: analyst receives logs (Sysmon process, Sysmon network, Windows
auth), parses them, and builds a HuntReport with rule findings and IOC
matches.

No network. All fixtures are synthetic.
"""
from pathlib import Path

from app.modules.huntscope.parser import parse_events
from app.modules.huntscope.report import build_report

_FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "logs"
)


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text()


def _all_events():
    """Parse the three fixture files and combine into one event list."""
    combined = []
    for name in (
        "sysmon_process.json",
        "sysmon_network.json",
        "windows_auth.json",
    ):
        result = parse_events(_load(name))
        assert result.skipped == 0, f"{name}: skipped={result.skipped}"
        combined.extend(result.events)
    return combined


# ---------- parsing ----------
def test_all_fixtures_parse_without_error():
    events = _all_events()
    # 3 process + 2 network + 4 auth = 9 events
    assert len(events) == 9


# ---------- rule findings ----------
def test_report_detects_powershell_encoded():
    events = _all_events()
    report = build_report(events)
    ids = {f.rule_id for f in report.rule_findings}
    assert "process_powershell_encoded" in ids


def test_report_detects_rundll32_from_public():
    events = _all_events()
    report = build_report(events)
    ids = {f.rule_id for f in report.rule_findings}
    assert "process_rundll32_user_writable" in ids


def test_report_detects_failed_logon():
    events = _all_events()
    report = build_report(events)
    ids = {f.rule_id for f in report.rule_findings}
    assert "auth_failed_logon" in ids


# ---------- IOC matching ----------
def test_report_matches_ioc_in_network_event():
    events = _all_events()
    report = build_report(events, iocs=["203.0.113.10"])
    assert report.summary.ioc_match_count >= 1
    matched = [m for m in report.ioc_matches if m.ioc == "203.0.113.10"]
    assert len(matched) >= 1
    # Should have matched dst_ip of the network event
    assert matched[0].field == "dst_ip"


def test_report_matches_ioc_in_auth_src_ip():
    events = _all_events()
    report = build_report(events, iocs=["203.0.113.5"])
    assert report.summary.ioc_match_count >= 1
    matched = [m for m in report.ioc_matches if m.ioc == "203.0.113.5"]
    assert matched[0].field == "src_ip"


# ---------- summary ----------
def test_summary_is_populated():
    events = _all_events()
    report = build_report(events, iocs=["203.0.113.10"])
    assert report.summary.event_count == 9
    assert report.summary.rule_finding_count >= 3
    assert report.summary.ioc_match_count >= 1
    # At least two hostnames appear: WORKSTATION-01 and SERVER-DC-01
    assert report.summary.unique_hosts >= 2
    # At least two users appear
    assert report.summary.unique_users >= 2


def test_summary_time_range():
    events = _all_events()
    report = build_report(events)
    earliest, latest = report.summary.time_range
    assert earliest is not None
    assert latest is not None
    assert earliest < latest


def test_severity_breakdown_contains_high():
    events = _all_events()
    report = build_report(events)
    # powershell_encoded and rundll32 are both high severity
    assert report.summary.severity_breakdown.get("high", 0) >= 2


# ---------- combination ----------
def test_combined_report_is_consistent():
    """rule_finding_count and ioc_match_count must match list lengths."""
    events = _all_events()
    report = build_report(events, iocs=["203.0.113.10"])
    assert report.summary.rule_finding_count == len(report.rule_findings)
    assert report.summary.ioc_match_count == len(report.ioc_matches)
    # Every finding references an event
    for f in report.rule_findings:
        assert f.event is not None
    for m in report.ioc_matches:
        assert m.event is not None


# ---------- empty input ----------
def test_empty_events_no_crash():
    report = build_report([])
    assert report.summary.event_count == 0
    assert report.summary.time_range == (None, None)
    assert report.rule_findings == []
    assert report.ioc_matches == []
