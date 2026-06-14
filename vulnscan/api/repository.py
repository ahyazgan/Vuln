"""Tenant-scoped query helpers (CLAUDE.md §2.6 — multi-tenant isolation).

§2.6 requires every query to filter by ``tenant_id``, enforced at the
repository layer rather than left to each caller to remember. Routes go through
these helpers instead of building raw ``select`` statements, so the tenant
filter (and the soft-delete filter) can't be forgotten.

The one deliberate exception is :func:`get_active_program`: a ``BountyProgram``
is a *published* listing that hackers from other tenants scan against, so it is
readable cross-tenant — but only when active. Everything else is tenant-private.
"""

from __future__ import annotations

import uuid
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.domain.models import AuditLog, BountyProgram

T = TypeVar("T")


async def get_scoped(
    session: AsyncSession, model: type[T], obj_id: uuid.UUID, tenant_id: uuid.UUID
) -> T | None:
    """Fetch one live row by id, scoped to ``tenant_id`` (excludes soft-deleted)."""
    stmt = (
        select(model)
        .where(model.id == obj_id)
        .where(model.tenant_id == tenant_id)
        .where(model.deleted_at.is_(None))
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_scoped(session: AsyncSession, model: type[T], tenant_id: uuid.UUID) -> list[T]:
    """List all live rows of ``model`` for ``tenant_id`` (newest first)."""
    stmt = (
        select(model)
        .where(model.tenant_id == tenant_id)
        .where(model.deleted_at.is_(None))
        .order_by(model.created_at.desc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def get_active_program(session: AsyncSession, program_id: uuid.UUID) -> BountyProgram | None:
    """Read a published, active program by id — cross-tenant by design.

    Programs define public scope that hackers from other tenants test against,
    so this read is intentionally NOT tenant-filtered. It still excludes
    inactive and soft-deleted programs.
    """
    stmt = (
        select(BountyProgram)
        .where(BountyProgram.id == program_id)
        .where(BountyProgram.is_active.is_(True))
        .where(BountyProgram.deleted_at.is_(None))
    )
    return (await session.execute(stmt)).scalar_one_or_none()


def write_audit(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID | None,
    action: str,
    target: str | None = None,
    detail: dict | None = None,
) -> AuditLog:
    """Append an audit record (CLAUDE.md §7.5). Caller owns the commit.

    Audit rows are write-once; this only ever inserts, never updates.
    """
    row = AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        target=target,
        detail=detail or {},
    )
    session.add(row)
    return row


__all__ = ["get_scoped", "list_scoped", "get_active_program", "write_audit"]
