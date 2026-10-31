# Phase 1 — Core Engine

## Goal
Python Core Engine that can read and process IOCs with tests.

## Acceptance criteria
- Extract IPv4, domain, URL, MD5/SHA1/SHA256, email
- Reject invalid formats
- Normalize to lowercase domain, decoded URL
- Deterministic hash for known sample bytes
- Unit tests in `tests/unit/`
