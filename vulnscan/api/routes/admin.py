"""Admin routes — platform management (CLAUDE.md §1).

ADMIN-only. These are the platform's cross-tenant operations (tenants, plans,
abuse monitoring), the sanctioned exception to §2.6 — all reads/writes go through
``admin_repository`` and every mutation is audited (§7.5). Admins are provisioned
out-of-band (``scripts/create_admin.py``); self-registration as admin is refused.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.api import admin_repository as admin_repo
from vulnscan.api.auth import CurrentUser, require_roles
from vulnscan.api.deps import get_db
from vulnscan.api.repository import write_audit
from vulnscan.api.schemas import AdminStats, AuditLogRead, TenantAdminRead, TenantPlanUpdate
from vulnscan.domain.enums import UserRole

router = APIRouter(prefix="/admin", tags=["admin"])

# Every admin endpoint requires the ADMIN role.
_admin = require_roles(UserRole.ADMIN)


@router.get("/stats", response_model=AdminStats)
async def get_stats(
    _: CurrentUser = Depends(_admin),
    session: AsyncSession = Depends(get_db),
) -> AdminStats:
    return AdminStats(**await admin_repo.platform_stats(session))


@router.get("/tenants", response_model=list[TenantAdminRead])
async def list_tenants(
    _: CurrentUser = Depends(_admin),
    session: AsyncSession = Depends(get_db),
) -> list[TenantAdminRead]:
    return [
        TenantAdminRead(
            id=t.id,
            name=t.name,
            plan=t.plan,
            created_at=t.created_at,
            deleted_at=t.deleted_at,
            user_count=users,
            scan_count=scans,
        )
        for t, users, scans in await admin_repo.list_tenants(session)
    ]


@router.patch("/tenants/{tenant_id}", response_model=TenantAdminRead)
async def update_tenant(
    tenant_id: uuid.UUID,
    body: TenantPlanUpdate,
    user: CurrentUser = Depends(_admin),
    session: AsyncSession = Depends(get_db),
) -> TenantAdminRead:
    tenant = await admin_repo.get_tenant(session, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")

    changes: dict = {}
    if body.plan is not None:
        tenant.plan = body.plan
        changes["plan"] = body.plan.value
    if body.name is not None:
        tenant.name = body.name
        changes["name"] = body.name

    write_audit(
        session,
        tenant_id=tenant.id,
        user_id=user.id,
        action="admin.tenant_updated",
        target=str(tenant.id),
        detail=changes,
    )
    await session.commit()
    await session.refresh(tenant)
    return await _tenant_admin_read(session, tenant_id)


@router.delete("/tenants/{tenant_id}", response_model=TenantAdminRead)
async def suspend_tenant(
    tenant_id: uuid.UUID,
    user: CurrentUser = Depends(_admin),
    session: AsyncSession = Depends(get_db),
) -> TenantAdminRead:
    """Suspend a tenant (soft-delete) for abuse control (§1). Reversible by clearing
    ``deleted_at`` directly; left as an explicit admin DB action for now."""
    tenant = await admin_repo.get_tenant(session, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    if tenant.deleted_at is None:
        tenant.deleted_at = datetime.now(UTC)
    write_audit(
        session,
        tenant_id=tenant.id,
        user_id=user.id,
        action="admin.tenant_suspended",
        target=str(tenant.id),
        detail={},
    )
    await session.commit()
    return await _tenant_admin_read(session, tenant_id)


@router.get("/audit", response_model=list[AuditLogRead])
async def list_audit(
    _: CurrentUser = Depends(_admin),
    session: AsyncSession = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None),
) -> list[AuditLogRead]:
    rows = await admin_repo.recent_audit(session, limit=limit, action=action)
    return [AuditLogRead.model_validate(r) for r in rows]


async def _tenant_admin_read(session: AsyncSession, tenant_id: uuid.UUID) -> TenantAdminRead:
    for t, users, scans in await admin_repo.list_tenants(session):
        if t.id == tenant_id:
            return TenantAdminRead(
                id=t.id,
                name=t.name,
                plan=t.plan,
                created_at=t.created_at,
                deleted_at=t.deleted_at,
                user_count=users,
                scan_count=scans,
            )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")


__all__ = ["router"]
