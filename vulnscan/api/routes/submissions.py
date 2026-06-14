"""Bounty submission routes — hacker submits, company reviews (CLAUDE.md §1).

Submissions are inherently cross-tenant: the submitting hacker's tenant
(``tenant_id``) and the reviewing company's tenant (``company_tenant_id``) are
different. Each side only ever sees its own submissions, and only the owning
company may review one (CLAUDE.md §2.6). Payment is modelled as a status
transition only — no payment processor is wired here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.api.auth import CurrentUser, get_current_user, require_roles
from vulnscan.api.deps import get_db
from vulnscan.api.repository import get_scoped, write_audit
from vulnscan.domain.enums import SubmissionStatus, UserRole
from vulnscan.domain.models import BountySubmission, ScanFinding
from vulnscan.domain.schemas import (
    BountySubmissionCreate,
    BountySubmissionRead,
    BountySubmissionReview,
)

router = APIRouter(prefix="/submissions", tags=["submissions"])


@router.post("", response_model=BountySubmissionRead, status_code=status.HTTP_201_CREATED)
async def create_submission(
    body: BountySubmissionCreate,
    user: CurrentUser = Depends(require_roles(UserRole.HACKER)),
    session: AsyncSession = Depends(get_db),
) -> BountySubmission:
    # The finding must belong to the submitting hacker's tenant (§2.6).
    finding = await get_scoped(session, ScanFinding, body.finding_id, user.tenant_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    submission = BountySubmission(
        tenant_id=user.tenant_id,
        finding_id=finding.id,
        hacker_user_id=user.id,
        company_tenant_id=body.company_tenant_id,
        status=SubmissionStatus.PENDING,
    )
    session.add(submission)
    await session.flush()
    write_audit(
        session,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="submission.created",
        target=str(finding.id),
        detail={
            "submission_id": str(submission.id),
            "company_tenant_id": str(body.company_tenant_id),
        },
    )
    await session.commit()
    await session.refresh(submission)
    return submission


@router.get("", response_model=list[BountySubmissionRead])
async def list_submissions(
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[BountySubmission]:
    """Hackers see their submitted reports; companies see ones sent to them."""
    stmt = select(BountySubmission).where(BountySubmission.deleted_at.is_(None))
    if user.role == UserRole.COMPANY:
        stmt = stmt.where(BountySubmission.company_tenant_id == user.tenant_id)
    else:  # hacker (admin would need a dedicated view; out of scope here)
        stmt = stmt.where(BountySubmission.tenant_id == user.tenant_id)
    stmt = stmt.order_by(BountySubmission.submitted_at.desc())
    return list((await session.execute(stmt)).scalars().all())


@router.post("/{submission_id}/review", response_model=BountySubmissionRead)
async def review_submission(
    submission_id: uuid.UUID,
    body: BountySubmissionReview,
    user: CurrentUser = Depends(require_roles(UserRole.COMPANY)),
    session: AsyncSession = Depends(get_db),
) -> BountySubmission:
    submission = await session.get(BountySubmission, submission_id)
    # Only the company the report was sent to may review it (§2.6).
    if submission is None or submission.company_tenant_id != user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="submission not found")

    submission.status = body.status
    submission.reward_amount = body.reward_amount
    submission.reviewed_at = datetime.now(UTC)
    write_audit(
        session,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="submission.reviewed",
        target=str(submission.id),
        detail={
            "status": body.status.value,
            "reward_amount": str(body.reward_amount) if body.reward_amount else None,
            "reason": body.reason,
        },
    )
    await session.commit()
    await session.refresh(submission)
    return submission


__all__ = ["router"]
