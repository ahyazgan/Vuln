"""Shared FastAPI dependencies: DB session and the scan enqueuer.

``get_db`` is re-exported from :mod:`vulnscan.db` so routes depend on a single
symbol (and tests override that one). ``get_enqueuer`` returns the callable that
hands a scan to the Celery worker — abstracted as a dependency so tests can
inject a recorder instead of touching a real broker (CLAUDE.md §2.1).
"""

from __future__ import annotations

from collections.abc import Callable

from vulnscan.db import get_db

# Type alias for readability in route signatures.
EnqueueScan = Callable[[dict], str]


def default_enqueue_scan(payload: dict) -> str:
    """Hand a scan to the Celery worker and return its task id (§2.1)."""
    from vulnscan.workers.app import run_scan  # lazy: avoid broker import at startup

    return run_scan.delay(payload).id


def get_enqueuer() -> EnqueueScan:
    """Dependency yielding the scan enqueuer (overridden in tests)."""
    return default_enqueue_scan


__all__ = ["get_db", "get_enqueuer", "default_enqueue_scan", "EnqueueScan"]
