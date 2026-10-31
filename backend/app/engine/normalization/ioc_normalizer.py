"""IOC normalizer - Phase 1.

Pure, deterministic normalization. No network, no side effects.
Idempotent: normalize(normalize(x)) == normalize(x) for all supported types.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

_SUPPORTED = {"domain", "ipv4", "url", "md5", "sha1", "sha256", "email"}
_HASH_TYPES = {"md5", "sha1", "sha256"}


def normalize(value: str, ioc_type: str) -> str:
    """Return the canonical form of an IOC value.

    Raises:
        ValueError: if value is empty, or ioc_type is unsupported.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("value must be a non-empty string")

    kind = (ioc_type or "").lower()
    if kind not in _SUPPORTED:
        raise ValueError(f"unsupported ioc_type: {ioc_type!r}")

    raw = value.strip()

    if kind == "domain":
        return _normalize_domain(raw)
    if kind == "ipv4":
        return raw
    if kind == "url":
        return _normalize_url(raw)
    if kind in _HASH_TYPES:
        return raw.lower()
    if kind == "email":
        return _normalize_email(raw)

    # Unreachable, but keeps static analyzers happy.
    raise ValueError(f"unsupported ioc_type: {ioc_type!r}")


def _normalize_domain(value: str) -> str:
    # Lowercase, strip trailing dot (FQDN form), strip whitespace already done.
    out = value.lower()
    if out.endswith("."):
        out = out[:-1]
    return out


def _normalize_url(value: str) -> str:
    # Preserve path/query case; lowercase only scheme and host.
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()

    # Rebuild netloc with host only (drop userinfo/port handling for Phase 1b;
    # preserve explicit port if present).
    netloc = host
    if parts.port is not None:
        netloc = f"{host}:{parts.port}"

    # Drop fragment.
    rebuilt = urlunsplit((scheme, netloc, parts.path, parts.query, ""))
    return rebuilt


def _normalize_email(value: str) -> str:
    # Local-part case preserved (RFC 5321); domain lowercased.
    if "@" not in value:
        return value  # caller should validate; normalizer is permissive here
    local, _, domain = value.rpartition("@")
    return f"{local}@{domain.lower()}"
