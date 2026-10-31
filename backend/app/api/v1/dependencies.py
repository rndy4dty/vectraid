"""API dependencies - Phase 9b.

Each create_app() call builds its own CaseStore and EvidenceStore and
exposes them on app.state. This keeps test runs isolated.
"""
from __future__ import annotations

from fastapi import Request

from app.modules.investigation.case_store import CaseIDGenerator, CaseStore
from app.modules.investigation.evidence import EvidenceStore


def get_case_store(request: Request) -> CaseStore:
    return request.app.state.case_store


def get_evidence_store(request: Request) -> EvidenceStore:
    return request.app.state.evidence_store


def get_case_id_generator(request: Request) -> CaseIDGenerator:
    return request.app.state.case_id_generator
