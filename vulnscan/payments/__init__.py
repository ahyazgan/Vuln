"""Payments package — the single integration point for the Stripe gateway.

Mirrors the ``ai/engine.py`` rule (CLAUDE.md §6): all payment-provider access
goes through :mod:`vulnscan.payments.gateway`. Routes never import ``stripe``
directly, so the provider can be swapped or faked (in tests) behind one seam.
"""

from vulnscan.payments.gateway import (
    PaymentError,
    PaymentGateway,
    PaymentGatewayError,
    PaymentResult,
    StripePaymentGateway,
    WebhookEvent,
    WebhookVerificationError,
)

__all__ = [
    "PaymentError",
    "PaymentGateway",
    "PaymentGatewayError",
    "PaymentResult",
    "StripePaymentGateway",
    "WebhookEvent",
    "WebhookVerificationError",
]
