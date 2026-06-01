"""Scan routes — the heart of the API (CLAUDE.md §2.1 / §4 / §7.2).

``POST /scans`` validates the target against the program scope (§7.2), records
the job and an audit entry (§7.5), enqueues the async pipeline, and returns a
job id immediately — it never blocks on the scan (§2.1). Reads are tenant-scoped
(§2.6).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.api.auth import CurrentUser, require_roles
from vulnscan.api.deps import EnqueueScan, get_db, get_enqueuer
from vulnscan.api.repository import get_active_program, get_scoped, list_scoped, write_audit
from vulnscan.api.schemas import ScanCreatedResponse, ScanCreateRequest
from vulnscan.domain.enums import ScanStatus, UserRole
from vulnscan.domain.models import ScanFinding, ScanJob
from vulnscan.domain.schemas import ScanFindingRead, ScanJobRead
from vulnscan.scanners.base import ScopeValidator

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanCreatedResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanCreateRequest,
    user: CurrentUser = Depends(require_roles(UserRole.HACKER)),
    session: AsyncSession = Depends(get_db),
    enqueue: EnqueueScan = Depends(get_enqueuer),
) -> ScanCreatedResponse:
    # 1. The program defines the authorized scope. Programs are public listings,
    #    so this read is intentionally cross-tenant (only active ones).
    program = await get_active_program(session, body.program_id)
    if program is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="active program not found"
        )

    # 2. Scope gate (§7.2): refuse a target outside the program whitelist BEFORE
    #    any job is queued — out-of-scope targets are never scanned.
    if not ScopeValidator(program.scope_domains).is_in_scope(body.target_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target_url is outside the program scope",
        )

    # 3. Record the queued job + an append-only audit entry (§7.5).
    job = ScanJob(
        tenant_id=user.tenant_id,
        user_id=user.id,
        program_id=program.id,
        target_url=body.target_url,
        scan_level=body.scan_level,
        status=ScanStatus.QUEUED,
    )
    session.add(job)
    await session.flush()
    previous = await _previous_findings(session, user.tenant_id, body.target_url)
    write_audit(
        session,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="scan.created",
        target=body.target_url,
        detail={"scan_id": str(job.id), "program_id": str(program.id),
                "scan_level": body.scan_level},
    )
    await session.commit()

    # 4. Hand off to the worker; return immediately (§2.1).
    enqueue(
        {
            "scan_id": str(job.id),
            "tenant_id": str(user.tenant_id),
            "target_url": job.target_url,
            "scope_domains": list(program.scope_domains),
            "scan_level": job.scan_level,
            "previous_findings": previous,
        }
    )
    return ScanCreatedResponse(scan_id=job.id, status=job.status)


@router.get("", response_model=list[ScanJobRead])
async def list_scans(
    user: CurrentUser = Depends(require_roles(UserRole.HACKER, UserRole.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[ScanJob]:
    return await list_scoped(session, ScanJob, user.tenant_id)


@router.get("/{scan_id}", response_model=ScanJobRead)
async def get_scan(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(UserRole.HACKER, UserRole.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> ScanJob:
    job = await get_scoped(session, ScanJob, scan_id, user.tenant_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return job


@router.get("/{scan_id}/findings", response_model=list[ScanFindingRead])
async def get_scan_findings(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(UserRole.HACKER, UserRole.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[ScanFinding]:
    job = await get_scoped(session, ScanJob, scan_id, user.tenant_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    stmt = (
        select(ScanFinding)
        .where(ScanFinding.tenant_id == user.tenant_id)
        .where(ScanFinding.scan_job_id == scan_id)
        .where(ScanFinding.deleted_at.is_(None))
        .order_by(ScanFinding.severity)
    )
    return list((await session.execute(stmt)).scalars().all())


async def _previous_findings(
    session: AsyncSession, tenant_id: uuid.UUID, target_url: str
) -> list[dict]:
    """Compact prior findings for the same target (CLAUDE.md §2.2 context)."""
    stmt = (
        select(ScanFinding.title, ScanFinding.severity, ScanFinding.cvss_score)
        .join(ScanJob, ScanJob.id == ScanFinding.scan_job_id)
        .where(ScanFinding.tenant_id == tenant_id)
        .where(ScanJob.target_url == target_url)
        .where(ScanFinding.deleted_at.is_(None))
        .limit(50)
    )
    rows = (await session.execute(stmt)).all()
    return [
        {"title": t, "severity": s.value, "cvss_score": c} for (t, s, c) in rows
    ]


__all__ = ["router"]
