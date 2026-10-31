"""Error taxonomy and async retry helper for TI provider adapters - Phase 2b.

Two pieces:
  - classify_error: turn an exception into a stable string tag for storage.
  - retry_async: retry transient failures (timeout, 5xx, 429) with backoff.

Design rules (locked by tests):
  - Adapter errors must be fail-soft: caller never sees exceptions from safe_query.
  - Retry only on transient errors: timeout, connect, 429, 5xx.
  - Never retry on 4xx (except 429): the request itself is wrong.
  - Error tags are stable strings, suitable for aggregation and dashboards.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

import httpx

T = TypeVar("T")

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


def classify_error(exc: BaseException) -> str:
    """Return a stable string tag for a provider-side exception.

    Tags:
      - 'timeout'               : request timed out
      - 'network_error'         : could not connect / DNS / TLS
      - 'rate_limited'          : HTTP 429
      - 'provider_error: <code>': HTTP 5xx from provider
      - 'client_error: <code>'  : HTTP 4xx (non-429) from client side
      - 'unknown: <repr>'       : anything else
    """
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "network_error"
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 429:
            return "rate_limited"
        if 500 <= status < 600:
            return f"provider_error: {status}"
        if 400 <= status < 500:
            return f"client_error: {status}"
        return f"unknown_status: {status}"
    return f"unknown: {type(exc).__name__}"


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (httpx.TimeoutException, httpx.ConnectError)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE_STATUS
    return False


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    *,
    max_attempts: int = 3,
    base_delay: float = 0.5,
) -> T:
    """Retry an async callable on transient errors with exponential backoff.

    On non-retryable errors, raises immediately.
    On exhaustion, re-raises the last exception.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    last_exc: BaseException | None = None
    for attempt in range(max_attempts):
        try:
            return await fn()
        except BaseException as exc:  # noqa: BLE001 - we classify below
            if not _is_retryable(exc):
                raise
            last_exc = exc
            if attempt < max_attempts - 1 and base_delay > 0:
                await asyncio.sleep(base_delay * (2 ** attempt))

    assert last_exc is not None
    raise last_exc
