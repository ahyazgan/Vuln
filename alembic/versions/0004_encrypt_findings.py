"""encrypt findings at rest

Revision ID: 0004_encrypt_findings
Revises: 0003_payments
Create Date: 2026-06-14

Sensitive finding content is now encrypted at rest (CLAUDE.md §7.4): the columns
store Fernet ciphertext, which is longer than the plaintext and no longer JSON.
This widens ``scan_findings.title`` (VARCHAR(512) -> TEXT) and changes
``scan_findings.references`` (JSON -> TEXT). The ``description`` /
``proof_of_concept`` / ``recommendation`` columns are already TEXT at the DB
level, so only the application-side type changes for those — no DDL needed.

Encryption/decryption happens in the app layer (``domain.encryption``); the
database only ever sees ciphertext.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_encrypt_findings"
down_revision: Union[str, None] = "0003_payments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("scan_findings") as batch:
        batch.alter_column("title", type_=sa.Text(), existing_nullable=False)
        batch.alter_column(
            "references",
            type_=sa.Text(),
            existing_nullable=False,
            postgresql_using='"references"::text',
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_findings") as batch:
        batch.alter_column(
            "references",
            type_=sa.JSON(),
            existing_nullable=False,
            postgresql_using='"references"::json',
        )
        batch.alter_column("title", type_=sa.String(length=512), existing_nullable=False)
