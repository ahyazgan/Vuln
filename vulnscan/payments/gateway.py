"""Payment gateway abstraction over Stripe (CLAUDE.md §6 / §7.3 / §8).

All payment-provider access funnels through the :class:`PaymentGateway`
protocol, exactly as all Claude access funnels through ``ai/engine.py``. Routes
depend on the protocol (injected via ``api.deps.get_payment_gateway``) so the
default :class:`StripePaymentGateway` can be swapped for a fake in tests without
touching the ``stripe`` SDK or the network.

Security:
* The Stripe **secret key** and **webhook secret** are read from the environment
  at call time and never persisted (§7.3). Nothing here stores card data, tokens,
  or any provider secret.
* Every provider call has a **timeout** and a **bounded exponential-backoff
  retry** on transient errors (§6).
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol, runtime_checkable

from vulnscan.domain.enums import PaymentStatus

logger = logging.getLogger("vulnscan.payments")

# §6 external-call defaults: 30s per-operation timeout, 2 retries, 2s base backoff.
DEFAULT_TIMEOUT = 30.0
MAX_RETRIES = 2
BACKOFF_BASE = 2.0

# Stripe PaymentIntent statuses that mean the money has not (yet) moved but the
# intent is alive, vs. terminal success/failure.
_STRIPE_STATUS_MAP: dict[str, PaymentStatus] = {
    "succeeded": PaymentStatus.SUCCEEDED,
    "processing": PaymentStatus.PENDING,
    "requires_payment_method": PaymentStatus.PENDING,
    "requires_confirmation": PaymentStatus.PENDING,
    "requires_action": PaymentStatus.PENDING,
    "requires_capture": PaymentStatus.PENDING,
    "canceled": PaymentStatus.FAILED,
}

# Webhook event type -> resulting payment status.
_WEBHOOK_STATUS_MAP: dict[str, PaymentStatus] = {
    "payment_intent.succeeded": PaymentStatus.SUCCEEDED,
    "payment_intent.payment_failed": PaymentStatus.FAILED,
    "payment_intent.canceled": PaymentStatus.FAILED,
    "charge.refunded": PaymentStatus.REFUNDED,
}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class PaymentError(Exception):
    """Base class for all payment-gateway failures."""


class PaymentGatewayError(PaymentError):
    """The provider rejected or failed a payment operation."""


class WebhookVerificationError(PaymentError):
    """An inbound webhook payload failed signature verification."""


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PaymentResult:
    """Outcome of creating a payment with the provider."""

    provider_payment_id: str
    status: PaymentStatus
    raw_status: str
    # Returned to the client to confirm with Stripe.js; never persisted (§7.3).
    client_secret: str | None = None


@dataclass(frozen=True)
class WebhookEvent:
    """A verified inbound provider event, normalized for our domain."""

    type: str
    provider_payment_id: str | None
    status: PaymentStatus | None
    raw: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Protocol
# --------------------------------------------------------------------------- #
@runtime_checkable
class PaymentGateway(Protocol):
    """The seam every route depends on; ``StripePaymentGateway`` is the default."""

    async def create_payment(
        self,
        *,
        amount: Decimal,
        currency: str,
        idempotency_key: str,
        metadata: dict[str, str],
    ) -> PaymentResult: ...

    def verify_webhook(self, payload: bytes, signature: str | None) -> WebhookEvent: ...


# --------------------------------------------------------------------------- #
# Stripe implementation
# --------------------------------------------------------------------------- #
def _to_minor_units(amount: Decimal) -> int:
    """Convert a major-unit decimal (e.g. 750.00 USD) to integer cents."""
    return int((amount * 100).to_integral_value())


class StripePaymentGateway:
    """Default :class:`PaymentGateway`, backed by the Stripe SDK.

    ``stripe`` is imported lazily inside methods so importing this module — and
    the whole API — never requires the SDK or any key to be present.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        webhook_secret: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        # Read from the environment at construction; never stored to the DB (§7.3).
        self._api_key = api_key or os.getenv("STRIPE_API_KEY", "")
        self._webhook_secret = webhook_secret or os.getenv("STRIPE_WEBHOOK_SECRET", "")
        self._timeout = timeout

    def _stripe(self):
        import stripe  # lazy: keep the SDK off the import path of the API

        if not self._api_key:
            raise PaymentGatewayError("STRIPE_API_KEY is not configured")
        stripe.api_key = self._api_key
        return stripe

    async def create_payment(
        self,
        *,
        amount: Decimal,
        currency: str,
        idempotency_key: str,
        metadata: dict[str, str],
    ) -> PaymentResult:
        stripe = self._stripe()
        last_exc: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                intent = await asyncio.wait_for(
                    asyncio.to_thread(
                        stripe.PaymentIntent.create,
                        amount=_to_minor_units(amount),
                        currency=currency.lower(),
                        metadata=metadata,
                        idempotency_key=idempotency_key,
                    ),
                    timeout=self._timeout,
                )
                raw_status = str(intent["status"])
                return PaymentResult(
                    provider_payment_id=str(intent["id"]),
                    status=_STRIPE_STATUS_MAP.get(raw_status, PaymentStatus.PENDING),
                    raw_status=raw_status,
                    client_secret=intent.get("client_secret"),
                )
            except Exception as exc:  # noqa: BLE001 - classified just below
                last_exc = exc
                if not _is_transient(stripe, exc) or attempt == MAX_RETRIES:
                    break
                backoff = BACKOFF_BASE * (2**attempt)
                logger.warning(
                    "stripe create_payment retry",
                    extra={"attempt": attempt + 1, "backoff_s": backoff},
                )
                await asyncio.sleep(backoff)

        raise PaymentGatewayError(f"stripe payment failed: {last_exc}") from last_exc

    def verify_webhook(self, payload: bytes, signature: str | None) -> WebhookEvent:
        if not signature:
            raise WebhookVerificationError("missing webhook signature")
        if not self._webhook_secret:
            raise WebhookVerificationError("STRIPE_WEBHOOK_SECRET is not configured")

        import stripe

        try:
            event = stripe.Webhook.construct_event(payload, signature, self._webhook_secret)
        except Exception as exc:  # noqa: BLE001 - any verify failure is a 401
            raise WebhookVerificationError(str(exc)) from exc

        obj = (event.get("data") or {}).get("object") or {}
        return WebhookEvent(
            type=str(event.get("type", "")),
            provider_payment_id=obj.get("id"),
            status=_WEBHOOK_STATUS_MAP.get(str(event.get("type", ""))),
            raw=dict(event),
        )


def _is_transient(stripe_mod, exc: Exception) -> bool:
    """True for Stripe errors worth retrying (connection blips, rate limits)."""
    transient = (
        getattr(stripe_mod.error, "APIConnectionError", ()),
        getattr(stripe_mod.error, "RateLimitError", ()),
    )
    return isinstance(exc, transient) or isinstance(exc, (TimeoutError, asyncio.TimeoutError))


__all__ = [
    "PaymentError",
    "PaymentGatewayError",
    "WebhookVerificationError",
    "PaymentResult",
    "WebhookEvent",
    "PaymentGateway",
    "StripePaymentGateway",
]
