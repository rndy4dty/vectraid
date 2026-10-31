"""PhishTrace email IOC extractor - Phase 3b.

Combines parsed email artifacts (Phase 3a) with the generic IOC extractor
(Phase 1d) to produce a deduplicated list of IOCs with source tags.

Design rules:
  - Three sources: body_plain, body_html, and header domains.
  - Dedup across sources: first source wins (plain -> html -> header).
  - The generic extractor already refangs (hxxp -> http, [.] -> .).
  - No enrichment, no network. Pure extraction.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.engine.extraction.ioc_extractor import extract_iocs
from app.modules.phishtrace.parser import EmailParseResult


@dataclass(frozen=True)
class EmailIOC:
    value: str
    ioc_type: str
    source: str
    raw_context: str = ""


@dataclass(frozen=True)
class EmailIOCResult:
    iocs: list[EmailIOC] = field(default_factory=list)


def extract_from_email(parsed: EmailParseResult) -> EmailIOCResult:
    """Extract IOCs from email body and headers, deduplicated by value+type."""
    seen: set[tuple[str, str]] = set()
    out: list[EmailIOC] = []

    def add(value: str, ioc_type: str, source: str, context: str = "") -> None:
        if not value:
            return
        key = (value.lower(), ioc_type)
        if key in seen:
            return
        seen.add(key)
        out.append(
            EmailIOC(
                value=value,
                ioc_type=ioc_type,
                source=source,
                raw_context=context[:120],
            )
        )

    # 1. Header domains first (so they show up as header-sourced)
    h = parsed.headers
    if h.from_domain:
        add(h.from_domain, "domain", "header:from")
    if h.reply_to_domain:
        add(h.reply_to_domain, "domain", "header:reply_to")
    if h.return_path_domain:
        add(h.return_path_domain, "domain", "header:return_path")

    # 2. Body: plain first, then html
    if parsed.body_plain:
        for ioc in extract_iocs(parsed.body_plain, source="body_plain").iocs:
            add(ioc.value, ioc.ioc_type, "body_plain", ioc.raw_context)

    if parsed.body_html:
        for ioc in extract_iocs(parsed.body_html, source="body_html").iocs:
            add(ioc.value, ioc.ioc_type, "body_html", ioc.raw_context)

    return EmailIOCResult(iocs=out)
