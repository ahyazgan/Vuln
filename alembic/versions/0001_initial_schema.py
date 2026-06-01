"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-06-01

Creates the six core tables for VulnScan AI. Every tenant-owned table carries
an indexed ``tenant_id``; all tables have UUID primary keys, created/updated
timestamps, and a nullable ``deleted_at`` for soft deletes. Enums are stored as
VARCHAR + CHECK (portable across PostgreSQL and SQLite).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from vulnscan.domain.enums import (
    PlanType,
    ScanStatus,
    Severity,
    SubmissionStatus,
    UserRole,
)

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _enum(enum_cls, name: str) -> sa.Enum:
    """VARCHAR + CHECK enum storing lowercase values — matches models._enum."""
    return sa.Enum(
        *[m.value for m in enum_cls],
        name=name,
        native_enum=False,
    )


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    ]


def upgrade() -> None:
    # ---- tenants --------------------------------------------------------- #
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("plan", _enum(PlanType, "plan_type"), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_tenants"),
    )

    # ---- users ----------------------------------------------------------- #
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", _enum(UserRole, "user_role"), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_users_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    # ---- bounty_programs ------------------------------------------------- #
    op.create_table(
        "bounty_programs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scope_domains", sa.JSON(), nullable=False),
        sa.Column("max_severity", _enum(Severity, "max_severity"), nullable=False),
        sa.Column("reward_table", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_bounty_programs"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_bounty_programs_tenant_id_tenants", ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_bounty_programs_tenant_id", "bounty_programs", ["tenant_id"]
    )

    # ---- scan_jobs ------------------------------------------------------- #
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("program_id", sa.Uuid(), nullable=True),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("status", _enum(ScanStatus, "scan_status"), nullable=False),
        sa.Column("scan_level", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_scan_jobs"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_scan_jobs_tenant_id_tenants", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name="fk_scan_jobs_user_id_users", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["program_id"], ["bounty_programs.id"],
            name="fk_scan_jobs_program_id_bounty_programs", ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "scan_level >= 1 AND scan_level <= 6", name="ck_scan_jobs_scan_level"
        ),
    )
    op.create_index("ix_scan_jobs_tenant_id", "scan_jobs", ["tenant_id"])
    op.create_index("ix_scan_jobs_user_id", "scan_jobs", ["user_id"])
    op.create_index("ix_scan_jobs_program_id", "scan_jobs", ["program_id"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])

    # ---- scan_findings --------------------------------------------------- #
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column(
            "severity", _enum(Severity, "finding_severity"), nullable=False
        ),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("proof_of_concept", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("is_chained", sa.Boolean(), nullable=False),
        sa.Column("chain_parent_ids", sa.JSON(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_scan_findings"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_scan_findings_tenant_id_tenants", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"], ["scan_jobs.id"],
            name="fk_scan_findings_scan_job_id_scan_jobs", ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "cvss_score >= 0 AND cvss_score <= 10",
            name="ck_scan_findings_cvss_range",
        ),
    )
    op.create_index("ix_scan_findings_tenant_id", "scan_findings", ["tenant_id"])
    op.create_index(
        "ix_scan_findings_scan_job_id", "scan_findings", ["scan_job_id"]
    )
    op.create_index("ix_scan_findings_severity", "scan_findings", ["severity"])

    # ---- bounty_submissions ---------------------------------------------- #
    op.create_table(
        "bounty_submissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("hacker_user_id", sa.Uuid(), nullable=False),
        sa.Column("company_tenant_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status", _enum(SubmissionStatus, "submission_status"), nullable=False
        ),
        sa.Column("reward_amount", sa.Numeric(precision=12, scale=2), nullable=True),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_bounty_submissions"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_bounty_submissions_tenant_id_tenants", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["scan_findings.id"],
            name="fk_bounty_submissions_finding_id_scan_findings",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["hacker_user_id"], ["users.id"],
            name="fk_bounty_submissions_hacker_user_id_users", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["company_tenant_id"], ["tenants.id"],
            name="fk_bounty_submissions_company_tenant_id_tenants",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_bounty_submissions_tenant_id", "bounty_submissions", ["tenant_id"]
    )
    op.create_index(
        "ix_bounty_submissions_finding_id", "bounty_submissions", ["finding_id"]
    )
    op.create_index(
        "ix_bounty_submissions_hacker_user_id",
        "bounty_submissions",
        ["hacker_user_id"],
    )
    op.create_index(
        "ix_bounty_submissions_company_tenant_id",
        "bounty_submissions",
        ["company_tenant_id"],
    )
    op.create_index(
        "ix_bounty_submissions_status", "bounty_submissions", ["status"]
    )


def downgrade() -> None:
    op.drop_table("bounty_submissions")
    op.drop_table("scan_findings")
    op.drop_table("scan_jobs")
    op.drop_table("bounty_programs")
    op.drop_table("users")
    op.drop_table("tenants")
