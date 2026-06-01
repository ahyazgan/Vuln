"""Bounty program routes — companies define scope + reward tables (CLAUDE.md §1).

A company creates and lists programs under its own tenant; all reads/writes are
tenant-scoped (§2.6) via the repository helpers. Programs are the source of the
scope whitelist that ``POST /scans`` enforces (§7.2).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.api.auth import CurrentUser, require_roles
from vulnscan.api.deps import get_db
from vulnscan.api.repository import get_scoped, list_scoped
from vulnscan.domain.enums import UserRole
from vulnscan.domain.models import BountyProgram
from vulnscan.domain.schemas import BountyProgramCreate, BountyProgramRead

router = APIRouter(prefix="/programs", tags=["programs"])


@router.post("", response_model=BountyProgramRead, status_code=status.HTTP_201_CREATED)
async def create_program(
    body: BountyProgramCreate,
    user: CurrentUser = Depends(require_roles(UserRole.COMPANY)),
    session: AsyncSession = Depends(get_db),
) -> BountyProgram:
    program = BountyProgram(tenant_id=user.tenant_id, **body.model_dump())
    session.add(program)
    await session.commit()
    await session.refresh(program)
    return program


@router.get("", response_model=list[BountyProgramRead])
async def list_programs(
    user: CurrentUser = Depends(require_roles(UserRole.COMPANY, UserRole.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[BountyProgram]:
    return await list_scoped(session, BountyProgram, user.tenant_id)


@router.get("/{program_id}", response_model=BountyProgramRead)
async def get_program(
    program_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(UserRole.COMPANY, UserRole.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> BountyProgram:
    program = await get_scoped(session, BountyProgram, program_id, user.tenant_id)
    if program is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="program not found")
    return program


__all__ = ["router"]
