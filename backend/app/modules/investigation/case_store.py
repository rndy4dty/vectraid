"""Case Store - Phase 8b.

In-memory store for Case objects with filtering and search.

Design rules:
  - Case IDs are generated via CaseIDGenerator (CASE-YYYY-NNNN).
  - Store rejects duplicate case_id on add; requires existing case_id on update.
  - get() returns None for missing cases (read paths must not raise).
  - list_* methods return deterministic order (insertion order of keys).
  - find() is case-insensitive substring search on title.
"""
from __future__ import annotations

from app.modules.investigation.case import Case, CasePriority, CaseStatus


class CaseIDGenerator:
    """Generate case IDs of form CASE-YYYY-NNNN, per year."""

    def __init__(self, year: int, start: int = 0) -> None:
        self._year = year
        self._counter = start

    def next(self) -> str:
        self._counter += 1
        return f"CASE-{self._year}-{self._counter:04d}"


class CaseStore:
    """In-memory case store. Insertion-ordered."""

    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}

    # ---------- write ----------
    def add(self, case: Case) -> None:
        if case.case_id in self._cases:
            raise ValueError(f"case already exists: {case.case_id}")
        self._cases[case.case_id] = case

    def update(self, case: Case) -> None:
        if case.case_id not in self._cases:
            raise ValueError(f"case not found: {case.case_id}")
        self._cases[case.case_id] = case

    def remove(self, case_id: str) -> None:
        self._cases.pop(case_id, None)

    # ---------- read ----------
    def get(self, case_id: str) -> Case | None:
        return self._cases.get(case_id)

    def count(self) -> int:
        return len(self._cases)

    def list_all(self) -> list[Case]:
        return list(self._cases.values())

    def list_by_status(self, status: CaseStatus) -> list[Case]:
        return [c for c in self._cases.values() if c.status == status]

    def list_by_assignee(self, assignee: str) -> list[Case]:
        target = assignee.strip().lower()
        return [
            c for c in self._cases.values()
            if c.assignee and c.assignee.lower() == target
        ]

    def list_by_priority(self, priority: CasePriority) -> list[Case]:
        return [c for c in self._cases.values() if c.priority == priority]

    # ---------- search ----------
    def find(self, query: str) -> list[Case]:
        if not query:
            return []
        q = query.strip().lower()
        return [c for c in self._cases.values() if q in c.title.lower()]
