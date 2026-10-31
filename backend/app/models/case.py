"""Case ORM - Phase 11a."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.case_decision import CaseDecisionORM
    from app.models.case_event import CaseEventORM
    from app.models.case_evidence_link import CaseEvidenceLinkORM
    from app.models.case_note import CaseNoteORM


class CaseORM(Base):
    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    events: Mapped[list[CaseEventORM]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseEventORM.timestamp",
    )
    notes: Mapped[list[CaseNoteORM]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseNoteORM.timestamp",
    )
    decisions: Mapped[list[CaseDecisionORM]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseDecisionORM.timestamp",
    )
    evidence_links: Mapped[list[CaseEvidenceLinkORM]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseEvidenceLinkORM.linked_at",
    )
