"""Payment routes — a company pays the bounty for an accepted submission.

Flow (CLAUDE.md §1):

* ``POST /payments/submissions/{id}/pay`` — the reviewing company initiates a
  Stripe payment for an **accepted** submission. Returns immediately with the
  payment record (and a ``client_secret`` to confirm with Stripe.js).
* ``POST /payments/stripe/webhook`` — Stripe calls back when the payment
  settles. The signature is verified over the raw body; on success the payment
  flips to ``succeeded`` and the submission to ``paid``.

Security:
* Tenant isolation (§2.6): a company only ever sees/pays under its own tenant.
  The webhook is the one deliberate cross-tenant path — it is an unauthenticated
  system callback, gated by Stripe signature verification, that resolves the
  payment by its provider id and then acts within that payment's own tenant.
* Audit (§7.5): every initiation and settlement writes an append-only record.
* Only payment *metadata* is persisted — never card data or provider secrets
  (§7.3 / §2.5).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.api.auth import CurrentUser, require_roles
from vulnscan.api.deps import get_db, get_payment_gateway
from vulnscan.api.repository import list_scoped, write_audit
from vulnscan.domain.enums import PaymentStatus, SubmissionStatus, UserRole
from vulnscan.domain.models import BountySubmission, Payment
from vulnscan.domain.schemas import PaymentCreate, PaymentInitiated, PaymentRead
from vulnscan.payments.gateway import (
    PaymentGateway,
    PaymentGatewayError,
    WebhookVerificationError,
)

router = APIRouter(prefix="/payments", tags=["payments"])

# Statuses that already hold a "live" payment for a submission — a new one would
# double-pay, so initiation is refused while one of these exists.
_LIVE_PAYMENT_STATUSES = (PaymentStatus.PENDING, PaymentStatus.SUCCEEDED)


@router.post(
    "/submissions/{submission_id}/pay",
    response_model=PaymentInitiated,
    status_code=status.HTTP_201_CREATED,
)
async def pay_submission(
    submission_id: uuid.UUID,
    body: PaymentCreate,
    user: CurrentUser = Depends(require_roles(UserRole.COMPANY)),
    session: AsyncSession = Depends(get_db),
    gateway: PaymentGateway = Depends(get_payment_gateway),
) -> PaymentInitiated:
    submission = await session.get(BountySubmission, submission_id)
    # Only the company the submission was sent to may pay it (§2.6).
    if submission is None or submission.company_tenant_id != user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="submission not found")
    if submission.status != SubmissionStatus.ACCEPTED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="only accepted submissions can be paid",
        )

    amount = body.amount if body.amount is not None else submission.reward_amount
    if amount is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="no reward amount set on the submission; supply one",
        )

    # Idempotency / no double-pay: refuse if a live payment already exists.
    existing = await _live_payment_for(session, submission_id, user.tenant_id)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a payment for this submission is already in progress or done",
        )

    try:
        result = await gateway.create_payment(
            amount=amount,
            currency=body.currency,
            idempotency_key=f"submission:{submission_id}",
            metadata={
                "submission_id": str(submission_id),
                "company_tenant_id": str(user.tenant_id),
            },
        )
    except PaymentGatewayError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"payment provider error: {exc}"
        ) from exc

    payment = Payment(
        tenant_id=user.tenant_id,
        submission_id=submission_id,
        amount=amount,
        currency=body.currency.lower(),
        status=result.status,
        provider="stripe",
        provider_payment_id=result.provider_payment_id,
    )
    session.add(payment)

    # Some flows settle synchronously; reflect that on the submission immediately.
    if result.status == PaymentStatus.SUCCEEDED:
        submission.status = SubmissionStatus.PAID

    await session.flush()
    write_audit(
        session,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="payment.created",
        target=str(submission_id),
        detail={
            "payment_id": str(payment.id),
            "amount": str(amount),
            "currency": payment.currency,
            "status": result.status.value,
            "provider_payment_id": result.provider_payment_id,
        },
    )
    await session.commit()
    await session.refresh(payment)

    return PaymentInitiated.model_validate(payment).model_copy(
        update={"client_secret": result.client_secret}
    )


@router.get("", response_model=list[PaymentRead])
async def list_payments(
    user: CurrentUser = Depends(require_roles(UserRole.COMPANY, UserRole.ADMIN)),
    session: AsyncSession = Depends(get_db),
) -> list[Payment]:
    return await list_scoped(session, Payment, user.tenant_id)


@router.post("/stripe/webhook", status_code=status.HTTP_204_NO_CONTENT)
async def stripe_webhook(
    request: Request,
    session: AsyncSession = Depends(get_db),
    gateway: PaymentGateway = Depends(get_payment_gateway),
) -> None:
    raw = await request.body()
    signature = request.headers.get("Stripe-Signature")
    try:
        event = gateway.verify_webhook(raw, signature)
    except WebhookVerificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid webhook signature"
        ) from exc

    # No actionable mapping (e.g. an event type we don't track) — accept and ignore.
    if event.status is None or event.provider_payment_id is None:
        return None

    # System callback: resolve the payment by its provider id (cross-tenant by
    # design), then act strictly within that payment's own tenant.
    stmt = select(Payment).where(Payment.provider_payment_id == event.provider_payment_id)
    payment = (await session.execute(stmt)).scalar_one_or_none()
    if payment is None:
        return None  # unknown payment — nothing to reconcile

    payment.status = event.status
    if event.status == PaymentStatus.SUCCEEDED:
        submission = await session.get(BountySubmission, payment.submission_id)
        if submission is not None:
            submission.status = SubmissionStatus.PAID
    elif event.status == PaymentStatus.FAILED:
        payment.error_message = f"stripe event: {event.type}"

    write_audit(
        session,
        tenant_id=payment.tenant_id,
        user_id=None,  # system-originated settlement
        action="payment.settled",
        target=str(payment.submission_id),
        detail={
            "payment_id": str(payment.id),
            "status": event.status.value,
            "event_type": event.type,
        },
    )
    await session.commit()
    return None


async def _live_payment_for(
    session: AsyncSession, submission_id: uuid.UUID, tenant_id: uuid.UUID
) -> Payment | None:
    """Return an in-progress/succeeded payment for the submission, if any (§2.6)."""
    stmt = (
        select(Payment)
        .where(Payment.tenant_id == tenant_id)
        .where(Payment.submission_id == submission_id)
        .where(Payment.status.in_(_LIVE_PAYMENT_STATUSES))
        .where(Payment.deleted_at.is_(None))
    )
    return (await session.execute(stmt)).scalars().first()


__all__ = ["router"]
