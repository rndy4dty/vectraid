"""Phase 3a - EML parser tests (test-first). No network, no DNS."""
from pathlib import Path

import pytest

from app.modules.phishtrace.parser import (
    EmailAttachment,
    EmailHeaders,
    EmailParseResult,
    parse_eml,
)

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests" / "fixtures" / "emails" / "phishing_simulation.eml"
)


def test_fixture_exists():
    assert _FIXTURE.is_file()


def test_parse_returns_result_object():
    raw = _FIXTURE.read_text()
    result = parse_eml(raw)
    assert isinstance(result, EmailParseResult)
    assert isinstance(result.headers, EmailHeaders)
    assert isinstance(result.attachments, list)


def test_parse_headers_basic():
    result = parse_eml(_FIXTURE.read_text())
    h = result.headers
    assert h.from_ == "IT Support <notification@spoofed-sender.test>"
    assert h.reply_to == "attacker@evil-collector.test"
    assert h.return_path == "bounce@compromised-relay.test"
    assert "Verify your account" in (h.subject or "")
    assert h.date is not None


def test_parse_sender_domain():
    result = parse_eml(_FIXTURE.read_text())
    assert result.headers.from_domain == "spoofed-sender.test"
    assert result.headers.reply_to_domain == "evil-collector.test"
    assert result.headers.return_path_domain == "compromised-relay.test"


def test_parse_authentication_results():
    result = parse_eml(_FIXTURE.read_text())
    auth = result.headers.authentication
    assert auth.spf == "fail"
    assert auth.dkim == "fail"
    assert auth.dmarc == "fail"


def test_parse_body_plain_and_html():
    result = parse_eml(_FIXTURE.read_text())
    assert result.body_plain is not None
    assert "unusual activity" in result.body_plain
    assert result.body_html is not None
    assert "<html>" in result.body_html


def test_parse_attachments():
    result = parse_eml(_FIXTURE.read_text())
    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert isinstance(att, EmailAttachment)
    assert att.filename == "verify_account.zip"
    assert att.content_type == "application/zip"
    assert att.size > 0
    assert len(att.sha256) == 64


def test_parse_headers_mismatch_flags():
    result = parse_eml(_FIXTURE.read_text())
    flags = result.mismatch_flags
    assert flags.from_reply_to_mismatch is True
    assert flags.from_return_path_mismatch is True
    assert flags.from_dmarc_fail is True


def test_parse_empty_input_raises():
    with pytest.raises(ValueError):
        parse_eml("")
