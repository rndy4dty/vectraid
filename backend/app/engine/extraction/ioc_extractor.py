"""IOC extractor - Phase 1d.

Extracts IOC candidates from free text. Permissive: collects everything,
then filters through validators. Never raises on bad input; errors go
to ExtractionResult.errors.

Extraction order matters:
  1. Refang the text (hxxp -> http, [.] -> .)
  2. Extract URLs (before domains, so URLs win)
  3. Extract emails
  4. Extract hashes (32/40/64 hex)
  5. Extract IPv4 (via validator)
  6. Extract domains (via validator), skipping IP-shaped matches
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.engine.validation.ioc_validator import (
    is_valid_domain,
    is_valid_hash,
    is_valid_ipv4,
    is_valid_url,
)


@dataclass
class ExtractedIOC:
    value: str
    ioc_type: str
    source: str
    raw_context: str = ""


@dataclass
class ExtractionResult:
    iocs: list[ExtractedIOC] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------- regexes ----------
_URL_RE = re.compile(r"(?:https?|hxxps?)://[^\s\"'<>()\[\]{}]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_IPV4_CANDIDATE_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_CANDIDATE_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
)


def _refang(text: str) -> str:
    """Undo common defanging so downstream regexes see canonical forms."""
    out = text
    out = re.sub(r"hxxp", "http", out, flags=re.IGNORECASE)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    out = out.replace("[:]", ":").replace("(:)", ":")
    out = out.replace("[@]", "@").replace("(@)", "@")
    return out


def _add(result: ExtractionResult, seen: set[tuple[str, str]],
         value: str, ioc_type: str, source: str, context: str = "") -> None:
    key = (value.lower(), ioc_type)
    if key in seen:
        return
    seen.add(key)
    result.iocs.append(
        ExtractedIOC(value=value, ioc_type=ioc_type, source=source,
                     raw_context=context[:120])
    )


def extract_iocs(text: str | None, source: str = "manual") -> ExtractionResult:
    """Extract IOC candidates from text.

    Returns an ExtractionResult. Never raises on bad input; problems
    are appended to result.errors.
    """
    result = ExtractionResult()

    if text is None:
        result.errors.append("input is None")
        return result
    if not isinstance(text, str):
        result.errors.append(f"input is not str: {type(text).__name__}")
        return result
    if not text.strip():
        return result

    try:
        body = _refang(text)
    except Exception as exc:  # defensive; refang is simple
        result.errors.append(f"refang failed: {exc}")
        return result

    seen: set[tuple[str, str]] = set()

    # 1. URLs
    for match in _URL_RE.finditer(body):
        value = match.group(0).rstrip(".,;:!?)")
        if is_valid_url(value):
            _add(result, seen, value, "url", source, body)

    # 2. Emails
    for match in _EMAIL_RE.finditer(body):
        value = match.group(0)
        _add(result, seen, value, "email", source, body)

    # 3. Hashes
    for match in _HASH_RE.finditer(body):
        value = match.group(0)
        if is_valid_hash(value):
            length = len(value)
            if length == 32:
                _add(result, seen, value, "md5", source, body)
            elif length == 40:
                _add(result, seen, value, "sha1", source, body)
            elif length == 64:
                _add(result, seen, value, "sha256", source, body)

    # 4. IPv4
    for match in _IPV4_CANDIDATE_RE.finditer(body):
        value = match.group(0)
        if is_valid_ipv4(value):
            _add(result, seen, value, "ipv4", source, body)

    # 5. Domains (skip IP-shaped and URLs already captured)
    url_spans = [(m.start(), m.end()) for m in _URL_RE.finditer(body)]
    for match in _DOMAIN_CANDIDATE_RE.finditer(body):
        start, end = match.span()
        if any(s <= start and end <= e for s, e in url_spans):
            continue
        value = match.group(0)
        if is_valid_ipv4(value):
            continue
        if is_valid_domain(value):
            _add(result, seen, value, "domain", source, body)

    return result
