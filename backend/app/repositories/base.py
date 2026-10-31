"""Base helpers for repositories - Phase 11a."""
from __future__ import annotations


class RepositoryError(Exception):
    """Raised when a repository invariant is violated."""
