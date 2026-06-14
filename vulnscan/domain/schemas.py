"""Pydantic v2 schemas for VulnScan AI.

Conventions:
* ``*Create`` — request bodies for creation (no server-managed fields).
* ``*Update`` — partial updates; every field optional.
* ``*Read``   — API responses; include ids/timestamps, read from ORM objects
  via ``model_config = ConfigDict(from_attributes=True)``.

Read schemas never expose secrets (e.g. ``User.hashed_password`` is omitted).
The finding shape mirrors the structured JSON contract Claude must return
(CLAUDE.md §5.2): ``{severity, title, description, cvss_score,
proof_of_concept, recommendation, references}``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from vulnscan.domain.enums import (
    PaymentStatus,
    PlanType,
    ScanStatus,
    Severity,
    SubmissionStatus,
    UserRole,
)

# Reusable config for response models read straight off ORM instances.
_ORM = ConfigDict(from_attributes=True)


class TimestampedRead(BaseModel):
    """Common read fields shared by every persisted entity."""

    model_config = _ORM

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None


# --------------------------------------------------------------------------- #
# Tenant
# --------------------------------------------------------------------------- #
class TenantBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    plan: PlanType = PlanType.STARTER


class TenantCreate(TenantBase):
    pass


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    plan: PlanType | None = None


class TenantRead(TenantBase, TimestampedRead):
    pass


# --------------------------------------------------------------------------- #
# User
# --------------------------------------------------------------------------- #
class UserBase(BaseModel):
    email: EmailStr
    role: UserRole


class UserCreate(UserBase):
    # Plaintext password on the way in only; it is hashed before persistence
    # and never stored or returned in clear (CLAUDE.md §7.3).
    password: str = Field(min_length=8, max_length=128)
    tenant_id: uuid.UUID | None = None  # assigned server-side during registration


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: UserRole | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserRead(UserBase, TimestampedRead):
    tenant_id: uuid.UUID
    # NOTE: hashed_password is deliberately never exposed.


# --------------------------------------------------------------------------- #
# BountyProgram
# --------------------------------------------------------------------------- #
class BountyProgramBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scope_domains: list[str] = Field(default_factory=list)
    max_severity: Severity = Severity.CRITICAL
    reward_table: dict[str, float] = Field(default_factory=dict)
    is_active: bool = True


class BountyProgramCreate(BountyProgramBase):
    pass


class BountyProgramUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    scope_domains: list[str] | None = None
    max_severity: Severity | None = None
    reward_table: dict[str, float] | None = None
    is_active: bool | None = None


class BountyProgramRead(BountyProgramBase, TimestampedRead):
    tenant_id: uuid.UUID


# --------------------------------------------------------------------------- #
# ScanJob
# --------------------------------------------------------------------------- #
class ScanJobBase(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    scan_level: int = Field(default=1, ge=1, le=6)


class ScanJobCreate(ScanJobBase):
    program_id: uuid.UUID | None = None


class ScanJobRead(ScanJobBase, TimestampedRead):
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    program_id: uuid.UUID | None = None
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


# --------------------------------------------------------------------------- #
# ScanFinding
# --------------------------------------------------------------------------- #
class FindingBase(BaseModel):
    """Mirrors the structured JSON Claude must emit per finding."""

    title: str = Field(min_length=1, max_length=512)
    severity: Severity
    cvss_score: float = Field(ge=0.0, le=10.0)
    description: str
    proof_of_concept: str | None = None
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingCreate(FindingBase):
    scan_job_id: uuid.UUID
    is_chained: bool = False
    chain_parent_ids: list[uuid.UUID] = Field(default_factory=list)


class ScanFindingRead(FindingBase, TimestampedRead):
    tenant_id: uuid.UUID
    scan_job_id: uuid.UUID
    is_chained: bool = False
    chain_parent_ids: list[uuid.UUID] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# BountySubmission
# --------------------------------------------------------------------------- #
class BountySubmissionCreate(BaseModel):
    finding_id: uuid.UUID
    company_tenant_id: uuid.UUID
    # hacker_user_id / tenant_id are derived from the authenticated user.


class BountySubmissionReview(BaseModel):
    """Company decision payload for accept/reject."""

    status: SubmissionStatus
    reward_amount: Decimal | None = Field(default=None, ge=0)
    reason: str | None = None


class BountySubmissionRead(TimestampedRead):
    tenant_id: uuid.UUID
    finding_id: uuid.UUID
    hacker_user_id: uuid.UUID
    company_tenant_id: uuid.UUID
    status: SubmissionStatus
    reward_amount: Decimal | None = None
    submitted_at: datetime
    reviewed_at: datetime | None = None


# --------------------------------------------------------------------------- #
# Payment
# --------------------------------------------------------------------------- #
class PaymentCreate(BaseModel):
    """Initiate a reward payment for an accepted submission.

    The amount defaults to the submission's reviewed ``reward_amount``; a company
    may override it (e.g. a partial payout) but never below zero.
    """

    amount: Decimal | None = Field(default=None, ge=0)
    currency: str = Field(default="usd", min_length=3, max_length=3)


class PaymentRead(TimestampedRead):
    tenant_id: uuid.UUID
    submission_id: uuid.UUID
    amount: Decimal
    currency: str
    status: PaymentStatus
    provider: str
    provider_payment_id: str | None = None
    error_message: str | None = None


class PaymentInitiated(PaymentRead):
    """Payment response that also carries the provider client secret.

    ``client_secret`` is returned only on creation so a frontend can confirm the
    payment with Stripe.js. It is never persisted (§7.3) and never read back.
    """

    client_secret: str | None = None


__all__ = [
    "TimestampedRead",
    "TenantBase",
    "TenantCreate",
    "TenantUpdate",
    "TenantRead",
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserRead",
    "BountyProgramBase",
    "BountyProgramCreate",
    "BountyProgramUpdate",
    "BountyProgramRead",
    "ScanJobBase",
    "ScanJobCreate",
    "ScanJobRead",
    "FindingBase",
    "FindingCreate",
    "ScanFindingRead",
    "BountySubmissionCreate",
    "BountySubmissionReview",
    "BountySubmissionRead",
    "PaymentCreate",
    "PaymentRead",
    "PaymentInitiated",
]
