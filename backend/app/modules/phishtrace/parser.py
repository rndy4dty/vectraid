"""PhishTrace EML parser - Phase 3a.

Parses RFC 822 email messages into structured artifacts.

Design rules:
  - No network, no DNS, no SMTP. Pure parsing.
  - Authentication results are read from existing headers
    (Authentication-Results, Received-SPF). If absent -> 'unknown'.
  - Attachments are NOT opened for analysis. Only metadata + SHA256.
  - All string values are safe to serialize to JSON.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_string, policy
from email.message import EmailMessage, Message
from email.utils import parseaddr, parsedate_to_datetime
from typing import cast


@dataclass(frozen=True)
class EmailAuthentication:
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"


@dataclass(frozen=True)
class EmailHeaders:
    from_: str
    from_domain: str | None
    reply_to: str | None
    reply_to_domain: str | None
    return_path: str | None
    return_path_domain: str | None
    to: str | None
    subject: str | None
    date: datetime | None
    authentication: EmailAuthentication


@dataclass(frozen=True)
class EmailAttachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass(frozen=True)
class EmailMismatchFlags:
    from_reply_to_mismatch: bool
    from_return_path_mismatch: bool
    from_dmarc_fail: bool


@dataclass(frozen=True)
class EmailParseResult:
    headers: EmailHeaders
    body_plain: str | None
    body_html: str | None
    attachments: list[EmailAttachment] = field(default_factory=list)
    mismatch_flags: EmailMismatchFlags | None = None
    raw_auth_header: str | None = None


def parse_eml(raw: str) -> EmailParseResult:
    """Parse a raw RFC 822 email string."""
    if not raw or not raw.strip():
        raise ValueError("empty email input")

    parsed = message_from_string(raw, policy=policy.default)
    msg = cast(EmailMessage, parsed)

    headers = _parse_headers(msg)
    body_plain, body_html, attachments = _walk_parts(msg)
    flags = _compute_flags(headers)

    raw_auth = msg.get("Authentication-Results")
    return EmailParseResult(
        headers=headers,
        body_plain=body_plain,
        body_html=body_html,
        attachments=attachments,
        mismatch_flags=flags,
        raw_auth_header=str(raw_auth) if raw_auth else None,
    )


# ---------- header helpers ----------
def _extract_domain(addr: str | None) -> str | None:
    """Extract domain from a From/Reply-To/Return-Path value."""
    if not addr:
        return None
    _, address = parseaddr(addr)
    if not address or "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().lower()
    return domain or None


def _clean_addr(value: str | None) -> str | None:
    """Strip surrounding whitespace; if it is a bare <addr>, remove angle brackets."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if value.startswith("<") and value.endswith(">") and value.count("<") == 1:
        inner = value[1:-1].strip()
        if inner:
            return inner
    return value


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


def _parse_auth_results(msg: Message) -> EmailAuthentication:
    """Read SPF/DKIM/DMARC from Authentication-Results and Received-SPF headers."""
    spf = "unknown"
    dkim = "unknown"
    dmarc = "unknown"

    for header in msg.get_all("Authentication-Results") or []:
        text = str(header).lower()
        for token in text.replace(";", " ").split():
            token = token.strip()
            if token.startswith("spf="):
                spf = token.split("=", 1)[1]
            elif token.startswith("dkim="):
                dkim = token.split("=", 1)[1]
            elif token.startswith("dmarc="):
                dmarc = token.split("=", 1)[1]

    if spf == "unknown":
        received_spf = msg.get("Received-SPF")
        if received_spf:
            text = str(received_spf).strip().lower()
            for candidate in ("pass", "fail", "softfail", "neutral", "none"):
                if text.startswith(candidate):
                    spf = candidate
                    break

    return EmailAuthentication(spf=spf, dkim=dkim, dmarc=dmarc)


def _parse_headers(msg: Message) -> EmailHeaders:
    from_raw = _clean_addr(msg.get("From"))
    reply_raw = _clean_addr(msg.get("Reply-To"))
    rp_raw = _clean_addr(msg.get("Return-Path"))

    return EmailHeaders(
        from_=from_raw or "",
        from_domain=_extract_domain(from_raw),
        reply_to=reply_raw,
        reply_to_domain=_extract_domain(reply_raw),
        return_path=rp_raw,
        return_path_domain=_extract_domain(rp_raw),
        to=_clean_addr(msg.get("To")),
        subject=_clean_addr(msg.get("Subject")),
        date=_parse_date(msg.get("Date")),
        authentication=_parse_auth_results(msg),
    )


# ---------- body / attachment walking ----------
def _walk_parts(msg: EmailMessage) -> tuple[str | None, str | None, list[EmailAttachment]]:
    body_plain: str | None = None
    body_html: str | None = None
    attachments: list[EmailAttachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            part_em = cast(EmailMessage, part)
            ctype = part_em.get_content_type()
            disposition = (part_em.get("Content-Disposition") or "").lower()

            if "attachment" in disposition or part_em.get_filename():
                attachments.append(_attachment_metadata(part_em))
                continue

            payload = _safe_text_payload(part_em)
            if payload is None:
                continue
            if ctype == "text/plain" and body_plain is None:
                body_plain = payload
            elif ctype == "text/html" and body_html is None:
                body_html = payload
    else:
        ctype = msg.get_content_type()
        payload = _safe_text_payload(msg)
        if ctype == "text/plain" and payload:
            body_plain = payload
        elif ctype == "text/html" and payload:
            body_html = payload

    return body_plain, body_html, attachments


def _safe_text_payload(part: EmailMessage) -> str | None:
    try:
        content = part.get_content()
    except Exception:
        return None
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return None
    if isinstance(content, str):
        return content
    return None


def _attachment_metadata(part: EmailMessage) -> EmailAttachment:
    filename = part.get_filename() or "unnamed"
    ctype = part.get_content_type()
    try:
        raw_payload = part.get_payload(decode=True)
    except Exception:
        raw_payload = None
    payload = cast(bytes, raw_payload) if raw_payload is not None else b""
    size = len(payload)
    sha256 = hashlib.sha256(payload).hexdigest()
    return EmailAttachment(
        filename=filename,
        content_type=ctype,
        size=size,
        sha256=sha256,
    )


# ---------- mismatch computation ----------
def _compute_flags(headers: EmailHeaders) -> EmailMismatchFlags:
    from_d = headers.from_domain
    reply_d = headers.reply_to_domain
    rp_d = headers.return_path_domain

    from_reply_mismatch = bool(from_d and reply_d and from_d != reply_d)
    from_return_mismatch = bool(from_d and rp_d and from_d != rp_d)
    dmarc_fail = headers.authentication.dmarc == "fail"

    return EmailMismatchFlags(
        from_reply_to_mismatch=from_reply_mismatch,
        from_return_path_mismatch=from_return_mismatch,
        from_dmarc_fail=dmarc_fail,
    )
