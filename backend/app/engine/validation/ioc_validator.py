"""IOC validator — Phase 1.

Pure, deterministic validation. No network, no side effects.
Each function returns True/False and never raises on bad input.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# ---------- IPv4 ----------
# Strict dotted-quad: 4 octets, 0-255, no leading zero (except "0" itself).
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)"
_IPV4_RE = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}$")

# ---------- Domain ----------
# Label: 1-63 chars, alnum, may contain hyphen not at start/end.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[A-Za-z]{{2,63}}$")

# ---------- URL ----------
_ALLOWED_SCHEMES = {"http", "https", "hxxp", "hxxps"}

# ---------- Hash ----------
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


def is_valid_ipv4(value: str) -> bool:
    """Strict IPv4 validation. Rejects leading zeros, wrong octet count, etc."""
    if not isinstance(value, str) or not value:
        return False
    if not _IPV4_RE.match(value):
        return False
    # Double-check via stdlib (defensive; regex already enforces range).
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def is_valid_domain(value: str) -> bool:
    """Validate a domain name per label rules and overall length."""
    if not isinstance(value, str) or not value:
        return False
    if len(value) > 253:
        return False
    if value.endswith("."):
        value = value[:-1]  # allow trailing dot (FQDN form)
    if not _DOMAIN_RE.match(value):
        return False
    # Any label > 63 chars? (regex already prevents, kept for clarity)
    for label in value.split("."):
        if len(label) > 63:
            return False
    return True


def is_valid_url(value: str) -> bool:
    """Validate URL with allowed schemes and a well-formed host."""
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False
    host = parsed.hostname
    if not host:
        return False
    # Host must be a valid domain or IPv4 (URLs pointing to IPs are common).
    return is_valid_domain(host) or is_valid_ipv4(host)


def is_valid_hash(value: str, algo: str | None = None) -> bool:
    """Validate hex hash. If algo is None, auto-detect by length."""
    if not isinstance(value, str) or not value:
        return False
    if not _HEX_RE.match(value):
        return False
    length = len(value)
    if algo is None:
        return length in _HASH_LENGTHS.values()
    algo = algo.lower()
    expected = _HASH_LENGTHS.get(algo)
    if expected is None:
        return False
    return length == expected
