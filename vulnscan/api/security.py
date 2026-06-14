"""Password hashing and JWT issue/verify (CLAUDE.md §8).

Passwords are bcrypt-hashed (never stored in clear — §7.3). Auth uses short-lived
**access** tokens plus longer-lived **refresh** tokens (§8), both signed HS256.
The signing secret comes from ``VULNSCAN_JWT_SECRET``; a hard-coded fallback is
used only for local/dev and must be overridden in production.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

# Dev fallback is ≥32 bytes (HS256 minimum). MUST be overridden in production.
JWT_SECRET = os.getenv("VULNSCAN_JWT_SECRET", "dev-insecure-secret-change-me-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(minutes=int(os.getenv("VULNSCAN_ACCESS_TTL_MIN", "15")))
REFRESH_TOKEN_TTL = timedelta(days=int(os.getenv("VULNSCAN_REFRESH_TTL_DAYS", "7")))


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired, or the wrong type."""


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# JWTs
# --------------------------------------------------------------------------- #
def _encode(
    *, user_id: uuid.UUID, tenant_id: uuid.UUID, role: str, token_type: str, ttl: timedelta
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "tenant": str(tenant_id),
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_access_token(*, user_id: uuid.UUID, tenant_id: uuid.UUID, role: str) -> str:
    return _encode(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        token_type="access",
        ttl=ACCESS_TOKEN_TTL,
    )


def create_refresh_token(*, user_id: uuid.UUID, tenant_id: uuid.UUID, role: str) -> str:
    return _encode(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        token_type="refresh",
        ttl=REFRESH_TOKEN_TTL,
    )


def decode_token(token: str, *, expected_type: str) -> dict:
    """Decode and validate a token, enforcing its ``type`` claim.

    Raises :class:`TokenError` on any failure (expired, bad signature, wrong
    type) so callers map a single exception to HTTP 401.
    """
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if claims.get("type") != expected_type:
        raise TokenError(f"expected a {expected_type} token")
    return claims


__all__ = [
    "TokenError",
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "ACCESS_TOKEN_TTL",
    "REFRESH_TOKEN_TTL",
]
