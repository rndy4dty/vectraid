"""EvidenceRepository integration tests - Phase 11a.

Runs against a real PostgreSQL test database (vectraid_test).
"""
from __future__ import annotations

import pytest

from app.modules.investigation.evidence import Evidence, EvidenceType
from app.repositories.base import RepositoryError
from app.repositories.evidence_repository import EvidenceRepository


def _evidence(eid: str = "ev-001", case_id: str = "CASE-001") -> Evidence:
    return Evidence(
        evidence_id=eid,
        case_id=case_id,
        source_module="phishtrace",
        evidence_type=EvidenceType.EMAIL_ANALYSIS,
        raw_reference=f"raw:{eid}",
        finding="Test finding",
        timestamp="2026-11-01T09:00:00Z",
        confidence=80,
        provenance={"ioc_value": "evil.test"},
    )


@pytest.mark.asyncio
async def test_add_and_get_evidence(db_session):
    repo = EvidenceRepository(db_session)
    await repo.add(_evidence())
    fetched = await repo.get("ev-001")
    assert fetched is not None
    assert fetched.evidence_id == "ev-001"
    assert fetched.case_id == "CASE-001"
    assert fetched.confidence == 80
    assert fetched.provenance["ioc_value"] == "evil.test"


@pytest.mark.asyncio
async def test_add_duplicate_raises(db_session):
    repo = EvidenceRepository(db_session)
    await repo.add(_evidence())
    with pytest.raises(RepositoryError):
        await repo.add(_evidence())


@pytest.mark.asyncio
async def test_get_missing_returns_none(db_session):
    repo = EvidenceRepository(db_session)
    assert await repo.get("ev-999") is None


@pytest.mark.asyncio
async def test_list_by_case(db_session):
    repo = EvidenceRepository(db_session)
    await repo.add(_evidence("ev-001", "CASE-A"))
    await repo.add(_evidence("ev-002", "CASE-A"))
    await repo.add(_evidence("ev-003", "CASE-B"))
    case_a = await repo.list_by_case("CASE-A")
    assert {e.evidence_id for e in case_a} == {"ev-001", "ev-002"}


@pytest.mark.asyncio
async def test_list_all(db_session):
    repo = EvidenceRepository(db_session)
    await repo.add(_evidence("ev-001"))
    await repo.add(_evidence("ev-002"))
    assert len(await repo.list_all()) == 2


@pytest.mark.asyncio
async def test_timestamp_round_trip(db_session):
    repo = EvidenceRepository(db_session)
    await repo.add(_evidence())
    fetched = await repo.get("ev-001")
    assert fetched.timestamp == "2026-11-01T09:00:00Z"
