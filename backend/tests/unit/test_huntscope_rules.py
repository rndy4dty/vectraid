"""Phase 5c - HuntScope detection rules tests (test-first)."""
from app.modules.huntscope.parser import NormalizedEvent
from app.modules.huntscope.rules import Finding, hunt


def _process_event(process: str, cmd: str = "", user: str = "u") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2026-11-01T09:00:00Z",
        hostname="WKS-01",
        event_id=1,
        channel="Sysmon",
        event_type="process",
        process=process,
        command_line=cmd,
        user=user,
        raw={"EventID": 1},
    )


def _network_event(dst_ip: str, dst_port: int) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2026-11-01T09:05:00Z",
        hostname="WKS-01",
        event_id=3,
        channel="Sysmon",
        event_type="network",
        dst_ip=dst_ip,
        dst_port=dst_port,
        raw={"EventID": 3},
    )


def _auth_event(
    event_id: int, user: str = "admin", src_ip: str = "203.0.113.5"
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp="2026-11-01T09:10:00Z",
        hostname="WKS-01",
        event_id=event_id,
        channel="Security",
        event_type="auth",
        user=user,
        src_ip=src_ip,
        raw={"EventID": event_id},
    )


# ---------- Finding shape ----------
def test_finding_shape():
    f = Finding(
        rule_id="x",
        rule_name="X rule",
        severity="high",
        mitre_technique="T1059.001",
        description="desc",
        event=NormalizedEvent(
            timestamp=None,
            hostname=None,
            event_id=None,
            channel=None,
            event_type="process",
            raw={},
        ),
    )
    assert f.rule_id == "x"
    assert f.severity == "high"


# ---------- PowerShell encoded ----------
def test_powershell_enc_detected():
    ev = _process_event(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -enc SQBFAFgA",
    )
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "process_powershell_encoded" in ids


def test_powershell_enc_encodedcommand_detected():
    ev = _process_event("powershell.exe", "powershell.exe -EncodedCommand AAAA")
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "process_powershell_encoded" in ids


def test_powershell_plain_does_not_trigger():
    ev = _process_event("powershell.exe", "powershell.exe Get-Process")
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "process_powershell_encoded" not in ids


# ---------- Rundll32 from Public ----------
def test_rundll32_public_detected():
    ev = _process_event(
        "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe C:\\Users\\Public\\update.dll,EntryPoint",
    )
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "process_rundll32_user_writable" in ids


def test_rundll32_system32_dll_not_triggered():
    ev = _process_event(
        "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL",
    )
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "process_rundll32_user_writable" not in ids


# ---------- Network non-standard port ----------
def test_network_non_standard_port_detected():
    ev = _network_event("203.0.113.10", 4444)
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "network_non_standard_port" in ids


def test_network_https_port_not_triggered():
    ev = _network_event("203.0.113.10", 443)
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "network_non_standard_port" not in ids


def test_network_dns_port_not_triggered():
    ev = _network_event("8.8.8.8", 53)
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "network_non_standard_port" not in ids


# ---------- Auth failed logon ----------
def test_auth_failed_logon_detected():
    ev = _auth_event(4625)
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "auth_failed_logon" in ids


def test_auth_successful_logon_not_flagged():
    ev = _auth_event(4624)
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "auth_failed_logon" not in ids


# ---------- Auth explicit cred ----------
def test_auth_explicit_cred_detected():
    ev = _auth_event(4672)
    result = hunt([ev])
    ids = {f.rule_id for f in result.findings}
    assert "auth_explicit_cred" in ids


# ---------- Combined fixture ----------
def test_hunt_multiple_events():
    events = [
        _process_event("powershell.exe", "powershell.exe -enc AAAA"),
        _process_event(
            "rundll32.exe", "rundll32.exe C:\\Users\\Public\\x.dll,Main"
        ),
        _network_event("203.0.113.10", 4444),
        _auth_event(4625),
        _auth_event(4624),
    ]
    result = hunt(events)
    assert result.event_count == 5
    assert result.finding_count >= 4
    for f in result.findings:
        assert f.rule_id
        assert f.severity in {"info", "low", "medium", "high"}
        assert f.event is not None


# ---------- Fail-soft on broken rule ----------
def test_hunt_survives_broken_rule():
    """If a rule raises, other rules still run; error is collected."""
    from app.modules.huntscope.rules.base import BaseRule

    class BrokenRule(BaseRule):
        rule_id = "broken"
        rule_name = "Broken"
        severity = "info"
        mitre_technique = ""

        def match(self, event):
            raise RuntimeError("boom")

    ev = _process_event("powershell.exe", "powershell.exe -enc X")
    result = hunt([ev], rules=[BrokenRule()])
    assert result.event_count == 1
    assert len(result.errors) >= 1
