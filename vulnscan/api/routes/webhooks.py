"""Webhook routes — signed event delivery (CLAUDE.md §3 / §4.6).

The report step emits a webhook when a scan completes; downstream systems can
also call back in. Both directions are HMAC-SHA256 signed with a shared secret
so neither side trusts an unauthenticated payload.

This module provides the signing primitive (:func:`sign`,
:func:`build_signed_headers` — used by the worker to emit) and an inbound
endpoint that verifies the signature over the *raw* request body. Per-program
webhook-URL registration is a later extension; the signing contract is fixed
here.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import APIRouter, HTTPException, Request, status

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

WEBHOOK_SECRET = os.getenv("VULNSCAN_WEBHOOK_SECRET", "dev-insecure-webhook-secret")
SIGNATURE_HEADER = "X-VulnScan-Signature"


def sign(body: bytes) -> str:
    """Hex HMAC-SHA256 of ``body`` under the shared webhook secret."""
    return hmac.new(WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()


def build_signed_headers(body: bytes) -> dict[str, str]:
    """Headers a worker attaches when emitting an outbound webhook."""
    return {SIGNATURE_HEADER: sign(body), "Content-Type": "application/json"}


def verify(body: bytes, signature: str | None) -> bool:
    """Constant-time check that ``signature`` matches ``body``."""
    if not signature:
        return False
    return hmac.compare_digest(sign(body), signature)


@router.post("/inbound", status_code=status.HTTP_204_NO_CONTENT)
async def inbound(request: Request) -> None:
    """Accept a signed inbound event. Rejects an unsigned/forged body with 401."""
    raw = await request.body()
    if not verify(raw, request.headers.get(SIGNATURE_HEADER)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid webhook signature"
        )
    # A real handler would dispatch on the event type here; for now, accept.
    return None


__all__ = ["router", "sign", "verify", "build_signed_headers", "SIGNATURE_HEADER"]
