"""API dependencies - Phase 11a-4.

Each request gets its own AsyncSession and repository instances.
Sessions are committed on success, rolled back on exception.
"""
from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.case_repository import CaseRepository
from app.repositories.evidence_repository import EvidenceRepository


async def get_db_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    session_maker = request.app.state.session_maker
    async with session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_case_repository(
    session: AsyncSession = Depends(get_db_session),
) -> CaseRepository:
    return CaseRepository(session)


def get_evidence_repository(
    session: AsyncSession = Depends(get_db_session),
) -> EvidenceRepository:
    return EvidenceRepository(session)
