"""CaseRepository - Phase 11a.

Bridges the immutable Case dataclass (Phase 8a) and CaseORM.
All methods are async and take an AsyncSession.

Upsert strategy: update scalar fields, then sync children (events,
notes, decisions, evidence_links) by append-only. Existing children
are never deleted, so audit trail and primary keys are preserved.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.case import CaseORM
from app.models.case_decision import CaseDecisionORM
from app.models.case_event import CaseEventORM
from app.models.case_evidence_link import CaseEvidenceLinkORM
from app.models.case_note import CaseNoteORM
from app.modules.investigation.case import (
    Case,
    CaseEvent,
    CaseNote,
    CasePriority,
    CaseStatus,
)
from app.modules.investigation.case_decisions import AnalystDecision, DecisionOutcome
from app.repositories.base import RepositoryError


class CaseRepository:
    """Persist and retrieve Case via PostgreSQL."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ---------- write ----------
    async def add(self, case: Case) -> None:
        existing = await self._session.get(CaseORM, case.case_id)
        if existing is not None:
            raise RepositoryError(f"case already exists: {case.case_id}")

        orm = CaseORM(
            case_id=case.case_id,
            title=case.title,
            status=case.status.value,
            priority=case.priority.value,
            created_by=case.created_by,
            assignee=case.assignee,
        )
        self._session.add(orm)

        # children
        for ev in case.history:
            self._session.add(_event_to_orm(orm.case_id, ev))
        for note in case.notes:
            self._session.add(_note_to_orm(orm.case_id, note))
        for dec in case.decisions:
            self._session.add(_decision_to_orm(orm.case_id, dec))
        for eid in case.evidence_ids:
            self._session.add(
                CaseEvidenceLinkORM(
                    case_id=orm.case_id,
                    evidence_id=eid,
                    linked_by=case.created_by,
                )
            )

        await self._session.flush()

    async def update(self, case: Case) -> None:
        """Append-only upsert: update scalars, append new children."""
        orm = await self._session.get(CaseORM, case.case_id)
        if orm is None:
            raise RepositoryError(f"case not found: {case.case_id}")

        # Eager-load relationships so we can access them without lazy IO.
        await self._session.refresh(
            orm,
            ["events", "notes", "decisions", "evidence_links"],
        )

        orm.title = case.title
        orm.status = case.status.value
        orm.priority = case.priority.value
        orm.assignee = case.assignee
        orm.updated_at = datetime.now(UTC)

        # Append events not yet stored (dedupe by timestamp+action+actor)
        existing_events = {
            (e.timestamp, e.action, e.actor) for e in orm.events
        }
        for ev in case.history:
            ev_key = (_parse_ts(ev.timestamp), ev.action, ev.actor)
            if ev_key not in existing_events:
                self._session.add(_event_to_orm(orm.case_id, ev))

        existing_notes = {
            (n.timestamp, n.author, n.text) for n in orm.notes
        }
        for note in case.notes:
            note_key = (_parse_ts(note.timestamp), note.author, note.text)
            if note_key not in existing_notes:
                self._session.add(_note_to_orm(orm.case_id, note))

        existing_decisions = {
            (d.timestamp, d.analyst, d.outcome, d.rationale)
            for d in orm.decisions
        }
        for dec in case.decisions:
            dec_key = (
                _parse_ts(dec.timestamp),
                dec.analyst,
                dec.outcome,
                dec.rationale,
            )
            if dec_key not in existing_decisions:
                self._session.add(_decision_to_orm(orm.case_id, dec))

        existing_links = {e.evidence_id for e in orm.evidence_links}
        for eid in case.evidence_ids:
            if eid not in existing_links:
                self._session.add(
                    CaseEvidenceLinkORM(
                        case_id=orm.case_id,
                        evidence_id=eid,
                        linked_by=case.assignee or "system",
                    )
                )

        await self._session.flush()

    async def remove(self, case_id: str) -> None:
        orm = await self._session.get(CaseORM, case_id)
        if orm is not None:
            await self._session.delete(orm)
            await self._session.flush()

    # ---------- read ----------
    async def get(self, case_id: str) -> Case | None:
        stmt = (
            select(CaseORM)
            .where(CaseORM.case_id == case_id)
            .options(
                selectinload(CaseORM.events),
                selectinload(CaseORM.notes),
                selectinload(CaseORM.decisions),
                selectinload(CaseORM.evidence_links),
            )
        )
        orm = (await self._session.execute(stmt)).scalar_one_or_none()
        return self._to_domain(orm) if orm else None

    async def list_all(self) -> list[Case]:
        stmt = select(CaseORM).options(
            selectinload(CaseORM.events),
            selectinload(CaseORM.notes),
            selectinload(CaseORM.decisions),
            selectinload(CaseORM.evidence_links),
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [self._to_domain(o) for o in rows]

    async def list_by_status(self, status: CaseStatus) -> list[Case]:
        stmt = (
            select(CaseORM)
            .where(CaseORM.status == status.value)
            .options(
                selectinload(CaseORM.events),
                selectinload(CaseORM.notes),
                selectinload(CaseORM.decisions),
                selectinload(CaseORM.evidence_links),
            )
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [self._to_domain(o) for o in rows]

    async def list_by_assignee(self, assignee: str) -> list[Case]:
        target = assignee.strip().lower()
        stmt = (
            select(CaseORM)
            .where(CaseORM.assignee.is_not(None))
            .options(
                selectinload(CaseORM.events),
                selectinload(CaseORM.notes),
                selectinload(CaseORM.decisions),
                selectinload(CaseORM.evidence_links),
            )
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [
            self._to_domain(o)
            for o in rows
            if (o.assignee or "").lower() == target
        ]

    async def find(self, query: str) -> list[Case]:
        if not query or not query.strip():
            return []
        stmt = (
            select(CaseORM)
            .where(CaseORM.title.ilike(f"%{query.strip()}%"))
            .options(
                selectinload(CaseORM.events),
                selectinload(CaseORM.notes),
                selectinload(CaseORM.decisions),
                selectinload(CaseORM.evidence_links),
            )
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [self._to_domain(o) for o in rows]

    # ---------- converters ----------
    @staticmethod
    def _to_domain(orm: CaseORM) -> Case:
        return Case(
            case_id=orm.case_id,
            title=orm.title,
            status=CaseStatus(orm.status),
            priority=CasePriority(orm.priority),
            created_by=orm.created_by,
            assignee=orm.assignee,
            notes=[
                CaseNote(
                    timestamp=_format_ts(n.timestamp),
                    author=n.author,
                    text=n.text,
                )
                for n in orm.notes
            ],
            decisions=[
                AnalystDecision(
                    timestamp=_format_ts(d.timestamp),
                    analyst=d.analyst,
                    outcome=DecisionOutcome(d.outcome),
                    rationale=d.rationale,
                    evidence_reference=d.evidence_reference,
                )
                for d in orm.decisions
            ],
            history=[
                CaseEvent(
                    timestamp=_format_ts(e.timestamp),
                    actor=e.actor,
                    action=e.action,
                    detail=dict(e.detail),
                )
                for e in orm.events
            ],
            evidence_ids=[link.evidence_id for link in orm.evidence_links],
        )


# ---------- helpers ----------
def _event_to_orm(case_id: str, ev: CaseEvent) -> CaseEventORM:
    return CaseEventORM(
        case_id=case_id,
        timestamp=_parse_ts(ev.timestamp),
        actor=ev.actor,
        action=ev.action,
        detail=dict(ev.detail),
    )


def _note_to_orm(case_id: str, note: CaseNote) -> CaseNoteORM:
    return CaseNoteORM(
        case_id=case_id,
        timestamp=_parse_ts(note.timestamp),
        author=note.author,
        text=note.text,
    )


def _decision_to_orm(case_id: str, dec: AnalystDecision) -> CaseDecisionORM:
    return CaseDecisionORM(
        case_id=case_id,
        timestamp=_parse_ts(dec.timestamp),
        analyst=dec.analyst,
        outcome=dec.outcome.value,
        rationale=dec.rationale,
        evidence_reference=dec.evidence_reference,
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
