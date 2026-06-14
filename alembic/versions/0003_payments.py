"""payments

Revision ID: 0003_payments
Revises: 0002_audit_logs
Create Date: 2026-06-14

Adds the ``payments`` table: bounty reward payments for accepted submissions
(Stripe-backed). Stores only payment *metadata* — amount, currency, status, and
the Stripe object id — never card data or provider secrets (CLAUDE.md §7.3 /
§2.5). ``tenant_id`` is the paying company's tenant; every read filters by it.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from vulnscan.domain.enums import PaymentStatus

revision: str = "0003_payments"
down_revision: Union[str, None] = "0002_audit_logs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _enum(enum_cls, name: str) -> sa.Enum:
    return sa.Enum(*[m.value for m in enum_cls], name=name, native_enum=False)


def upgrade() -> None:
    op.create_table(
        "payments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("submission_id", sa.Uuid(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("status", _enum(PaymentStatus, "payment_status"), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_payment_id", sa.String(length=255), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_payments")),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_payments_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["bounty_submissions.id"],
            name=op.f("fk_payments_submission_id_bounty_submissions"),
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("amount >= 0", name="ck_payments_amount_non_negative"),
    )
    op.create_index(op.f("ix_payments_tenant_id"), "payments", ["tenant_id"])
    op.create_index(op.f("ix_payments_submission_id"), "payments", ["submission_id"])
    op.create_index(op.f("ix_payments_status"), "payments", ["status"])
    op.create_index(
        op.f("ix_payments_provider_payment_id"), "payments", ["provider_payment_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_payments_provider_payment_id"), table_name="payments")
    op.drop_index(op.f("ix_payments_status"), table_name="payments")
    op.drop_index(op.f("ix_payments_submission_id"), table_name="payments")
    op.drop_index(op.f("ix_payments_tenant_id"), table_name="payments")
    op.drop_table("payments")
