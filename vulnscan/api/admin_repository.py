"""Platform-admin queries — the ONE sanctioned cross-tenant plane.

CLAUDE.md §2.6 (LOCKED) forbids cross-tenant reads for tenant business logic.
§1, however, defines an **Admin** role that "manages the platform: tenants,
users, plans, abuse, global config" — which is inherently platform-wide. These
two coexist by isolating *all* cross-tenant access to this module, reached only
by the ADMIN role (``require_roles(UserRole.ADMIN)``) and always audited at the
route layer. Tenant-scoped code keeps going through ``repository.py``; nothing
here is importable into a hacker/company code path by accident.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.domain.models import (
    AuditLog,
    BountyProgram,
    BountySubmission,
    Payment,
    ScanFinding,
    ScanJob,
    Tenant,
    User,
)


async def _count(session: AsyncSession, model: type, *, live_only: bool = True) -> int:
    stmt = select(func.count()).select_from(model)
    if live_only and hasattr(model, "deleted_at"):
        stmt = stmt.where(model.deleted_at.is_(None))
    return int((await session.execute(stmt)).scalar_one())


async def platform_stats(session: AsyncSession) -> dict[str, int]:
    """Whole-platform row counts for the admin dashboard."""
    return {
        "tenants": await _count(session, Tenant),
        "users": await _count(session, User),
        "programs": await _count(session, BountyProgram),
        "scans": await _count(session, ScanJob),
        "findings": await _count(session, ScanFinding),
        "submissions": await _count(session, BountySubmission),
        "payments": await _count(session, Payment),
    }


async def list_tenants(session: AsyncSession) -> list[tuple[Tenant, int, int]]:
    """All tenants (including suspended) with their user and scan counts."""
    user_counts = (
        select(User.tenant_id, func.count().label("n"))
        .where(User.deleted_at.is_(None))
        .group_by(User.tenant_id)
        .subquery()
    )
    scan_counts = (
        select(ScanJob.tenant_id, func.count().label("n"))
        .where(ScanJob.deleted_at.is_(None))
        .group_by(ScanJob.tenant_id)
        .subquery()
    )
    stmt = (
        select(
            Tenant,
            func.coalesce(user_counts.c.n, 0),
            func.coalesce(scan_counts.c.n, 0),
        )
        .outerjoin(user_counts, user_counts.c.tenant_id == Tenant.id)
        .outerjoin(scan_counts, scan_counts.c.tenant_id == Tenant.id)
        .order_by(Tenant.created_at.desc())
    )
    return [(t, int(u), int(s)) for t, u, s in (await session.execute(stmt)).all()]


async def get_tenant(session: AsyncSession, tenant_id: uuid.UUID) -> Tenant | None:
    """Fetch any tenant by id (cross-tenant; admin only). Includes suspended."""
    return (
        await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()


async def recent_audit(
    session: AsyncSession, *, limit: int = 100, action: str | None = None
) -> list[AuditLog]:
    """Recent audit records across all tenants for abuse monitoring (§7.5)."""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    return list((await session.execute(stmt)).scalars().all())


__all__ = [
    "platform_stats",
    "list_tenants",
    "get_tenant",
    "recent_audit",
]
