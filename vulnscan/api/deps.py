"""Shared FastAPI dependencies: DB session, scan enqueuer, payment gateway.

``get_db`` is re-exported from :mod:`vulnscan.db` so routes depend on a single
symbol (and tests override that one). ``get_enqueuer`` returns the callable that
hands a scan to the Celery worker, and ``get_payment_gateway`` returns the
Stripe gateway — both abstracted as dependencies so tests inject a recorder/fake
instead of touching a real broker or payment provider (CLAUDE.md §2.1 / §6).
"""

from __future__ import annotations

from collections.abc import Callable

from vulnscan.db import get_db
from vulnscan.payments.gateway import PaymentGateway, StripePaymentGateway

# Type alias for readability in route signatures.
EnqueueScan = Callable[[dict], str]


def default_enqueue_scan(payload: dict) -> str:
    """Hand a scan to the Celery worker and return its task id (§2.1)."""
    from vulnscan.workers.app import run_scan  # lazy: avoid broker import at startup

    return run_scan.delay(payload).id


def get_enqueuer() -> EnqueueScan:
    """Dependency yielding the scan enqueuer (overridden in tests)."""
    return default_enqueue_scan


def get_payment_gateway() -> PaymentGateway:
    """Dependency yielding the payment gateway (overridden in tests).

    The default is Stripe; it reads its keys from the environment lazily and
    never connects at import time.
    """
    return StripePaymentGateway()


__all__ = [
    "get_db",
    "get_enqueuer",
    "default_enqueue_scan",
    "EnqueueScan",
    "get_payment_gateway",
]
