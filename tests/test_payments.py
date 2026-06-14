"""Integration tests for the payments surface.

Covers the happy path (initiate -> Stripe webhook settles -> submission paid),
the synchronous-settle path, tenant isolation, RBAC, double-pay protection,
state/amount guards, gateway failure mapping, and webhook signature rejection.

The Stripe SDK is never touched: a :class:`FakeGateway` is injected via the
``get_payment_gateway`` dependency override, exactly as the real broker is
replaced for scans.
"""

import json
import uuid

import httpx
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from vulnscan.api.app import API_PREFIX as P
from vulnscan.domain.enums import PaymentStatus, ScanStatus, Severity
from vulnscan.domain.models import Base, ScanFinding, ScanJob
from vulnscan.payments.gateway import (
    PaymentGatewayError,
    PaymentResult,
    WebhookEvent,
    WebhookVerificationError,
)

_WEBHOOK_MAP = {
    "payment_intent.succeeded": PaymentStatus.SUCCEEDED,
    "payment_intent.payment_failed": PaymentStatus.FAILED,
}


class FakeGateway:
    """In-memory stand-in for ``StripePaymentGateway`` (no SDK, no network)."""

    def __init__(self) -> None:
        self.created: list[dict] = []
        self.create_status = PaymentStatus.PENDING
        self.raise_on_create = False
        self._counter = 0

    async def create_payment(self, *, amount, currency, idempotency_key, metadata):
        self.created.append(
            {
                "amount": amount,
                "currency": currency,
                "idempotency_key": idempotency_key,
                "metadata": metadata,
            }
        )
        if self.raise_on_create:
            raise PaymentGatewayError("simulated provider failure")
        self._counter += 1
        pid = f"pi_test_{self._counter}"
        return PaymentResult(
            provider_payment_id=pid,
            status=self.create_status,
            raw_status=self.create_status.value,
            client_secret=f"{pid}_secret",
        )

    def verify_webhook(self, payload: bytes, signature: str | None) -> WebhookEvent:
        # Tests sign with the literal "valid"; anything else is a forgery.
        if signature != "valid":
            raise WebhookVerificationError("bad signature")
        data = json.loads(payload)
        return WebhookEvent(
            type=data["type"],
            provider_payment_id=data.get("pid"),
            status=_WEBHOOK_MAP.get(data["type"]),
            raw=data,
        )


@pytest_asyncio.fixture
async def pay_api():
    """ASGI client wired to an in-memory DB with a fake payment gateway.

    Yields ``(client, gateway, maker)``.
    """
    from vulnscan.api.app import create_app
    from vulnscan.api.deps import get_db, get_payment_gateway

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    app = create_app()
    gateway = FakeGateway()

    async def _override_db():
        async with maker() as s:
            yield s

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_payment_gateway] = lambda: gateway

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, gateway, maker
    await engine.dispose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _register(client, email, role, tenant):
    r = await client.post(
        f"{P}/auth/register",
        json={"email": email, "password": "password123", "role": role, "tenant_name": tenant},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def _me(client, tokens):
    r = await client.get(f"{P}/auth/me", headers=_auth(tokens))
    assert r.status_code == 200, r.text
    return r.json()


async def _seed_finding(maker, tenant_id, user_id) -> uuid.UUID:
    async with maker() as s:
        job = ScanJob(
            tenant_id=tenant_id,
            user_id=user_id,
            target_url="https://example.com/",
            status=ScanStatus.COMPLETED,
            scan_level=6,
        )
        s.add(job)
        await s.flush()
        finding = ScanFinding(
            tenant_id=tenant_id,
            scan_job_id=job.id,
            title="XSS",
            severity=Severity.HIGH,
            cvss_score=7.5,
            description="reflected xss",
        )
        s.add(finding)
        await s.commit()
        return finding.id


async def _accepted_submission(client, maker, *, reward="750.00"):
    """Full flow: build company + hacker, an accepted submission with a reward.

    Returns ``(company_tokens, hacker_tokens, submission_id)``.
    """
    company = await _register(client, "c@co.com", "company", "Company")
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")
    company_me = await _me(client, company)
    hacker_me = await _me(client, hacker)

    finding_id = await _seed_finding(
        maker, uuid.UUID(hacker_me["tenant_id"]), uuid.UUID(hacker_me["id"])
    )
    r = await client.post(
        f"{P}/submissions",
        headers=_auth(hacker),
        json={"finding_id": str(finding_id), "company_tenant_id": company_me["tenant_id"]},
    )
    assert r.status_code == 201, r.text
    submission_id = r.json()["id"]

    review = {"status": "accepted"}
    if reward is not None:
        review["reward_amount"] = reward
    rv = await client.post(
        f"{P}/submissions/{submission_id}/review", headers=_auth(company), json=review
    )
    assert rv.status_code == 200, rv.text
    return company, hacker, submission_id


# --------------------------------------------------------------------------- #
# Happy path: initiate (pending) -> webhook settles -> submission paid
# --------------------------------------------------------------------------- #
async def test_pay_then_webhook_marks_submission_paid(pay_api):
    client, gateway, maker = pay_api
    company, hacker, submission_id = await _accepted_submission(client, maker)

    r = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["client_secret"]  # returned for Stripe.js confirmation
    assert body["amount"] == "750.00"
    # The gateway was called with the reviewed reward and an idempotency key.
    assert len(gateway.created) == 1
    assert str(gateway.created[0]["amount"]) == "750.00"
    assert gateway.created[0]["idempotency_key"] == f"submission:{submission_id}"
    pid = body["provider_payment_id"]

    # Submission is not paid yet — only the webhook settles it.
    subs = await client.get(f"{P}/submissions", headers=_auth(company))
    assert next(s for s in subs.json() if s["id"] == submission_id)["status"] == "accepted"

    # Stripe calls back: payment_intent.succeeded.
    payload = json.dumps({"type": "payment_intent.succeeded", "pid": pid}).encode()
    wh = await client.post(
        f"{P}/payments/stripe/webhook",
        content=payload,
        headers={"Stripe-Signature": "valid"},
    )
    assert wh.status_code == 204, wh.text

    # Payment succeeded and the submission is now paid.
    payments = await client.get(f"{P}/payments", headers=_auth(company))
    assert payments.json()[0]["status"] == "succeeded"
    subs = await client.get(f"{P}/submissions", headers=_auth(company))
    assert next(s for s in subs.json() if s["id"] == submission_id)["status"] == "paid"


async def test_sync_succeeded_payment_marks_paid_immediately(pay_api):
    client, gateway, maker = pay_api
    gateway.create_status = PaymentStatus.SUCCEEDED
    company, _, submission_id = await _accepted_submission(client, maker)

    r = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "succeeded"

    subs = await client.get(f"{P}/submissions", headers=_auth(company))
    assert next(s for s in subs.json() if s["id"] == submission_id)["status"] == "paid"


# --------------------------------------------------------------------------- #
# Guards: state, amount, double-pay, RBAC, tenant isolation, failures
# --------------------------------------------------------------------------- #
async def test_pay_requires_accepted_submission(pay_api):
    client, _, maker = pay_api
    # Build a *pending* (un-reviewed) submission.
    company = await _register(client, "c@co.com", "company", "Company")
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")
    company_me = await _me(client, company)
    hacker_me = await _me(client, hacker)
    finding_id = await _seed_finding(
        maker, uuid.UUID(hacker_me["tenant_id"]), uuid.UUID(hacker_me["id"])
    )
    sub = await client.post(
        f"{P}/submissions",
        headers=_auth(hacker),
        json={"finding_id": str(finding_id), "company_tenant_id": company_me["tenant_id"]},
    )
    submission_id = sub.json()["id"]

    r = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    assert r.status_code == 409


async def test_pay_without_reward_amount_rejected(pay_api):
    client, _, maker = pay_api
    company, _, submission_id = await _accepted_submission(client, maker, reward=None)
    r = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    assert r.status_code == 422


async def test_double_pay_refused(pay_api):
    client, _, maker = pay_api
    company, _, submission_id = await _accepted_submission(client, maker)
    first = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    assert first.status_code == 201
    second = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    assert second.status_code == 409


async def test_other_company_cannot_pay(pay_api):
    client, _, maker = pay_api
    _, _, submission_id = await _accepted_submission(client, maker)
    other = await _register(client, "o@o.com", "company", "Other")
    r = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(other), json={}
    )
    assert r.status_code == 404


async def test_hacker_cannot_pay(pay_api):
    client, _, maker = pay_api
    _, hacker, submission_id = await _accepted_submission(client, maker)
    r = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(hacker), json={}
    )
    assert r.status_code == 403


async def test_gateway_failure_maps_to_502(pay_api):
    client, gateway, maker = pay_api
    gateway.raise_on_create = True
    company, _, submission_id = await _accepted_submission(client, maker)
    r = await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    assert r.status_code == 502
    # Nothing persisted — a retry must be possible afterwards.
    payments = await client.get(f"{P}/payments", headers=_auth(company))
    assert payments.json() == []


async def test_payment_tenant_isolation(pay_api):
    client, _, maker = pay_api
    company, _, submission_id = await _accepted_submission(client, maker)
    await client.post(
        f"{P}/payments/submissions/{submission_id}/pay", headers=_auth(company), json={}
    )
    other = await _register(client, "o@o.com", "company", "Other")
    r = await client.get(f"{P}/payments", headers=_auth(other))
    assert r.status_code == 200 and r.json() == []


async def test_webhook_bad_signature_rejected(pay_api):
    client, _, _ = pay_api
    payload = json.dumps({"type": "payment_intent.succeeded", "pid": "pi_x"}).encode()
    r = await client.post(
        f"{P}/payments/stripe/webhook",
        content=payload,
        headers={"Stripe-Signature": "forged"},
    )
    assert r.status_code == 401


async def test_webhook_unknown_payment_ignored(pay_api):
    client, _, _ = pay_api
    payload = json.dumps({"type": "payment_intent.succeeded", "pid": "pi_unknown"}).encode()
    r = await client.post(
        f"{P}/payments/stripe/webhook",
        content=payload,
        headers={"Stripe-Signature": "valid"},
    )
    assert r.status_code == 204  # accepted, nothing to reconcile


# --------------------------------------------------------------------------- #
# StripePaymentGateway internals (no SDK / network needed)
# --------------------------------------------------------------------------- #
def test_minor_units_conversion():
    from decimal import Decimal

    from vulnscan.payments.gateway import _to_minor_units

    assert _to_minor_units(Decimal("750.00")) == 75000
    assert _to_minor_units(Decimal("0.99")) == 99
    assert _to_minor_units(Decimal("0")) == 0


def test_stripe_status_mapping():
    from vulnscan.payments.gateway import _STRIPE_STATUS_MAP

    assert _STRIPE_STATUS_MAP["succeeded"] == PaymentStatus.SUCCEEDED
    assert _STRIPE_STATUS_MAP["processing"] == PaymentStatus.PENDING
    assert _STRIPE_STATUS_MAP["canceled"] == PaymentStatus.FAILED


def test_verify_webhook_requires_signature_and_secret():
    from vulnscan.payments.gateway import StripePaymentGateway

    gw = StripePaymentGateway(api_key="sk_test", webhook_secret="whsec_test")
    # Missing signature is rejected before the SDK is ever consulted.
    try:
        gw.verify_webhook(b"{}", None)
        raise AssertionError("expected WebhookVerificationError")
    except WebhookVerificationError:
        pass

    # Missing configured secret is also rejected.
    gw_no_secret = StripePaymentGateway(api_key="sk_test", webhook_secret="")
    try:
        gw_no_secret.verify_webhook(b"{}", "t=1,v1=abc")
        raise AssertionError("expected WebhookVerificationError")
    except WebhookVerificationError:
        pass


async def test_create_payment_without_api_key_errors():
    from decimal import Decimal

    from vulnscan.payments.gateway import StripePaymentGateway

    gw = StripePaymentGateway(api_key="")
    try:
        await gw.create_payment(
            amount=Decimal("10.00"), currency="usd", idempotency_key="k", metadata={}
        )
        raise AssertionError("expected PaymentGatewayError")
    except PaymentGatewayError:
        pass
