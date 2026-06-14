"""All enum classes for the VulnScan AI domain.

These are the single source of truth for the categorical values used across
the database models, Pydantic schemas, and the AI engine. Every enum subclasses
``str`` so that values serialize cleanly to JSON and compare naturally against
the lowercase string values stored in the database.

Severity levels mirror CLAUDE.md §2.3 (Critical / High / Medium / Low / Info)
and every finding must carry one of them alongside a CVSS 3.1 score.
"""

from __future__ import annotations

import enum


class PlanType(str, enum.Enum):
    """Subscription plan for a tenant."""

    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class UserRole(str, enum.Enum):
    """Platform role. See CLAUDE.md §1 for capabilities per role."""

    HACKER = "hacker"
    COMPANY = "company"
    ADMIN = "admin"


class Severity(str, enum.Enum):
    """Vulnerability severity. Always paired with a CVSS 3.1 score."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric ordering, higher = more severe. Useful for sorting/clamping."""
        return _SEVERITY_RANK[self]


class ScanStatus(str, enum.Enum):
    """Lifecycle of a scan job."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SubmissionStatus(str, enum.Enum):
    """Lifecycle of a bounty submission."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PAID = "paid"


class PaymentStatus(str, enum.Enum):
    """Lifecycle of a bounty reward payment (Stripe-backed).

    A payment starts ``pending`` when the company initiates it; the Stripe
    webhook flips it to ``succeeded`` or ``failed``. ``refunded`` covers a
    reversed payout.
    """

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


__all__ = [
    "PlanType",
    "UserRole",
    "Severity",
    "ScanStatus",
    "SubmissionStatus",
    "PaymentStatus",
]
