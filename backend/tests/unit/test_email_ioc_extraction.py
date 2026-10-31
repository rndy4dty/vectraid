"""Phase 3b - Extract IOC from email body and headers (test-first)."""
from pathlib import Path

from app.modules.phishtrace.extractor import EmailIOCResult, extract_from_email
from app.modules.phishtrace.parser import parse_eml

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests" / "fixtures" / "emails" / "phishing_simulation.eml"
)


def _parse_fixture():
    return parse_eml(_FIXTURE.read_text())


def test_extract_returns_result_object():
    parsed = _parse_fixture()
    result = extract_from_email(parsed)
    assert isinstance(result, EmailIOCResult)


def test_extract_refanged_url_from_body_plain():
    """URL in body is defanged (hxxps://... [.]). Must be refanged."""
    parsed = _parse_fixture()
    result = extract_from_email(parsed)
    urls = [i.value for i in result.iocs if i.ioc_type == "url"]
    assert "https://account-update.spoofed-sender.test/login?next=/dashboard" in urls


def test_extract_refanged_url_from_body_html():
    """HTML body also contains the defanged URL."""
    parsed = _parse_fixture()
    result = extract_from_email(parsed)
    urls = [i.value for i in result.iocs if i.ioc_type == "url"]
    # HTML version doesn't have ?next=... -> different URL path
    assert "https://account-update.spoofed-sender.test/login" in urls


def test_extract_header_domains():
    """from_domain, reply_to_domain, return_path_domain become domain IOCs."""
    parsed = _parse_fixture()
    result = extract_from_email(parsed)
    domains = {i.value for i in result.iocs if i.ioc_type == "domain"}
    assert "spoofed-sender.test" in domains
    assert "evil-collector.test" in domains
    assert "compromised-relay.test" in domains


def test_extract_source_is_tagged():
    """Every IOC has a source tag identifying where it came from."""
    parsed = _parse_fixture()
    result = extract_from_email(parsed)
    sources = {i.source for i in result.iocs}
    # At least body_plain and body_html should appear
    assert any("body" in s for s in sources)
    assert any("header" in s for s in sources)


def test_extract_no_duplicates_across_bodies():
    """Same URL in plain and HTML should not appear twice."""
    parsed = _parse_fixture()
    result = extract_from_email(parsed)
    urls = [i.value for i in result.iocs if i.ioc_type == "url"]
    # Each URL appears at most once
    assert len(urls) == len(set(urls))


def test_extract_empty_email_returns_empty():
    """An email with no IOC-like content returns empty list."""
    from app.modules.phishtrace.parser import EmailAuthentication, EmailHeaders, EmailParseResult

    headers = EmailHeaders(
        from_="a@b.test",
        from_domain="b.test",
        reply_to=None,
        reply_to_domain=None,
        return_path=None,
        return_path_domain=None,
        to=None,
        subject="Hello",
        date=None,
        authentication=EmailAuthentication(),
    )
    parsed = EmailParseResult(
        headers=headers,
        body_plain="Just a friendly hello, nothing to see here.",
        body_html=None,
        attachments=[],
    )
    result = extract_from_email(parsed)
    # Only the header domain should appear as IOC
    ioc_types = {i.ioc_type for i in result.iocs}
    # No URL should be extracted
    assert "url" not in ioc_types
