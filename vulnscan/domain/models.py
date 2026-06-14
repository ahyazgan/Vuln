"""SQLAlchemy models for VulnScan AI.

Design rules enforced here (see CLAUDE.md §2 & §7):

* **UUID primary keys** on every table (``id``), generated client-side.
* **``tenant_id`` on every tenant-owned table, indexed** — multi-tenant
  isolation requires that every query filters by ``tenant_id``. The ``Tenant``
  table itself is the tenant root: its ``id`` *is* the tenant id, so it does
  not carry a redundant self-referential ``tenant_id``.
* **``created_at`` / ``updated_at``** timestamps on every table.
* **Soft delete** via a nullable ``deleted_at`` — rows are never hard-deleted
  in normal operation; queries filter ``deleted_at IS NULL``.

Enum columns are stored as portable ``VARCHAR + CHECK`` (``native_enum=False``)
using the lowercase enum *values*, so the schema works identically on
PostgreSQL (production) and SQLite (tests) with no native ENUM type to manage.

JSON columns use the generic ``JSON`` type (portable across PostgreSQL/SQLite);
we never query *into* these blobs, so ``JSONB`` would buy us nothing here.
"""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from vulnscan.domain.enums import (
    PaymentStatus,
    PlanType,
    ScanStatus,
    Severity,
    SubmissionStatus,
    UserRole,
)

# Stable constraint/index naming so Alembic autogenerate stays deterministic.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        ident = getattr(self, "id", None)
        return f"<{type(self).__name__} id={ident}>"


def _enum(enum_cls: type, name: str) -> SAEnum:
    """Portable enum column: VARCHAR + CHECK storing the lowercase enum values."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        validate_strings=True,
        values_callable=lambda e: [member.value for member in e],
    )


# --------------------------------------------------------------------------- #
# Mixins
# --------------------------------------------------------------------------- #
class UUIDPrimaryKeyMixin:
    """Adds a client-generated UUID primary key."""

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    """Adds created/updated timestamps and a soft-delete marker."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class TenantScopedMixin:
    """Adds an indexed ``tenant_id`` FK — required on every tenant-owned table."""

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An isolated account boundary. A company or an individual hacker org.

    The tenant is the root of multi-tenant isolation: its ``id`` is the value
    that every other table references via ``tenant_id``.
    """

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan: Mapped[PlanType] = mapped_column(
        _enum(PlanType, "plan_type"), nullable=False, default=PlanType.STARTER
    )

    users: Mapped[list["User"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    programs: Mapped[list["BountyProgram"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


class User(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A platform user. Email is unique *within* a tenant."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),)

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(_enum(UserRole, "user_role"), nullable=False)

    tenant: Mapped["Tenant"] = relationship(back_populates="users")


class BountyProgram(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A company-defined bounty program: scope + reward table.

    ``tenant_id`` here is the *company* tenant that owns the program.
    ``scope_domains`` is the whitelist enforced before any scan request (§7.2).
    """

    __tablename__ = "bounty_programs"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # JSON array of in-scope domains/paths, e.g. ["example.com", "*.api.example.com"]
    scope_domains: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    max_severity: Mapped[Severity] = mapped_column(
        _enum(Severity, "max_severity"), nullable=False, default=Severity.CRITICAL
    )
    # JSON map of severity -> reward amount, e.g. {"critical": 5000, "high": 1500}
    reward_table: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="programs")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="program")


class ScanJob(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A queued/running/finished scan against a target URL.

    ``tenant_id`` is the tenant that *runs* the scan (the hacker's tenant).
    ``program_id`` is nullable at the DB layer for flexibility, but the API
    (POST /scans) requires a program and validates the target against its
    scope before queueing (§4 / §7.2).
    """

    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint("scan_level >= 1 AND scan_level <= 6", name="ck_scan_jobs_scan_level"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    program_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("bounty_programs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"),
        nullable=False,
        default=ScanStatus.QUEUED,
        index=True,
    )
    scan_level: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    program: Mapped["BountyProgram | None"] = relationship(back_populates="scan_jobs")
    findings: Mapped[list["ScanFinding"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )


class ScanFinding(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A single vulnerability finding produced by the AI analysis engine.

    Mirrors the structured JSON contract in CLAUDE.md §5.2. ``is_chained`` /
    ``chain_parent_ids`` express multi-step attack chains (pipeline step 5):
    a chained finding references the ids of the individual findings combined.
    """

    __tablename__ = "scan_findings"
    __table_args__ = (
        CheckConstraint("cvss_score >= 0 AND cvss_score <= 10", name="ck_scan_findings_cvss_range"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        _enum(Severity, "finding_severity"), nullable=False, index=True
    )
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    proof_of_concept: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON array of reference URLs/CVE ids. ("references" is a reserved SQL word;
    # SQLAlchemy quotes it automatically in DDL.)
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_chained: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # JSON array of parent finding ids (stored as strings) when is_chained is true.
    chain_parent_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="findings")
    submissions: Mapped[list["BountySubmission"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class BountySubmission(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A hacker's finding submitted to a company for bounty review.

    Submissions are inherently cross-tenant: ``tenant_id`` (from the mixin) is
    the *submitting hacker's* tenant — used for the hacker-side isolation
    filter — while ``company_tenant_id`` is the *company* tenant that reviews
    and pays. Both are indexed so each side can list its own submissions.
    """

    __tablename__ = "bounty_submissions"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hacker_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    company_tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[SubmissionStatus] = mapped_column(
        _enum(SubmissionStatus, "submission_status"),
        nullable=False,
        default=SubmissionStatus.PENDING,
        index=True,
    )
    reward_amount: Mapped[Decimal | None] = mapped_column(Numeric(12, 2), nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    finding: Mapped["ScanFinding"] = relationship(back_populates="submissions")
    payments: Mapped[list["Payment"]] = relationship(
        back_populates="submission", cascade="all, delete-orphan"
    )


class Payment(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A bounty reward payment for an accepted submission (Stripe-backed).

    ``tenant_id`` is the *paying company's* tenant (the one that owns the program
    and reviews submissions), so every read filters by it (§2.6). Only payment
    *metadata* is persisted — amount, currency, status, and the Stripe object id;
    never card data, tokens, or any secret (§7.3 / §2.5). The Stripe API key
    lives in the environment and is read by the gateway, never stored here.
    """

    __tablename__ = "payments"
    __table_args__ = (CheckConstraint("amount >= 0", name="ck_payments_amount_non_negative"),)

    submission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("bounty_submissions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="usd")
    status: Mapped[PaymentStatus] = mapped_column(
        _enum(PaymentStatus, "payment_status"),
        nullable=False,
        default=PaymentStatus.PENDING,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="stripe")
    # The Stripe PaymentIntent id (e.g. "pi_..."). Indexed for webhook lookup.
    provider_payment_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    submission: Mapped["BountySubmission"] = relationship(back_populates="payments")


class AuditLog(UUIDPrimaryKeyMixin, TenantScopedMixin, Base):
    """Append-only audit record (CLAUDE.md §7.5).

    Captures who (``user_id`` / ``tenant_id``), what (``action`` + ``target``),
    when (``created_at``), and what was found (``detail`` JSON). Deliberately
    has NO ``updated_at`` / ``deleted_at`` and no mutators — audit rows are
    written once and never changed or deleted.
    """

    __tablename__ = "audit_logs"

    # Nullable so system-originated events (no acting user) can still be logged.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # Arbitrary structured context (scan id, severity counts, decision, …).
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


__all__ = [
    "Base",
    "Tenant",
    "User",
    "BountyProgram",
    "ScanJob",
    "ScanFinding",
    "BountySubmission",
    "Payment",
    "AuditLog",
]
