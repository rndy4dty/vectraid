"""EvidenceRepository - Phase 11a.

Bridges the immutable Evidence dataclass (Phase 7a) and EvidenceORM.
All methods are async and take an AsyncSession.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import EvidenceORM
from app.modules.investigation.evidence import Evidence, EvidenceType
from app.repositories.base import RepositoryError


class EvidenceRepository:
    """Persist and retrieve Evidence via PostgreSQL."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, evidence: Evidence) -> None:
        existing = await self._session.get(EvidenceORM, evidence.evidence_id)
        if existing is not None:
            raise RepositoryError(
                f"evidence already exists: {evidence.evidence_id}"
            )
        self._session.add(self._to_orm(evidence))
        await self._session.flush()

    async def get(self, evidence_id: str) -> Evidence | None:
        orm = await self._session.get(EvidenceORM, evidence_id)
        return self._to_domain(orm) if orm else None

    async def list_by_case(self, case_id: str) -> list[Evidence]:
        stmt = (
            select(EvidenceORM)
            .where(EvidenceORM.case_id == case_id)
            .order_by(EvidenceORM.timestamp)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [self._to_domain(o) for o in rows]

    async def list_all(self) -> list[Evidence]:
        stmt = select(EvidenceORM).order_by(EvidenceORM.timestamp)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [self._to_domain(o) for o in rows]

    @staticmethod
    def _to_orm(ev: Evidence) -> EvidenceORM:
        return EvidenceORM(
            evidence_id=ev.evidence_id,
            case_id=ev.case_id,
            source_module=ev.source_module,
            evidence_type=ev.evidence_type.value,
            raw_reference=ev.raw_reference,
            finding=ev.finding,
            timestamp=_parse_ts(ev.timestamp),
            confidence=ev.confidence,
            provenance=dict(ev.provenance),
        )

    @staticmethod
    def _to_domain(orm: EvidenceORM) -> Evidence:
        return Evidence(
            evidence_id=orm.evidence_id,
            case_id=orm.case_id,
            source_module=orm.source_module,
            evidence_type=EvidenceType(orm.evidence_type),
            raw_reference=orm.raw_reference,
            finding=orm.finding,
            timestamp=_format_ts(orm.timestamp),
            confidence=orm.confidence,
            provenance=dict(orm.provenance),
        )


def _parse_ts(value: str) -> datetime:
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    return datetime.fromisoformat(v)


def _format_ts(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
