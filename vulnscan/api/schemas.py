"""API-specific request/response schemas (Pydantic v2).

Domain schemas (``vulnscan.domain.schemas``) are reused for entity bodies; this
module only adds the auth and scan-dispatch DTOs that are specific to the HTTP
surface.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, EmailStr, Field

from vulnscan.domain.enums import ScanStatus, UserRole


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    # Self-service registration creates a hacker or company org; admins are
    # provisioned out-of-band, never via the public endpoint.
    role: UserRole = UserRole.HACKER
    tenant_name: str = Field(min_length=1, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    # Email is unique only within a tenant; supply tenant_id to disambiguate
    # when the same email exists in more than one tenant.
    tenant_id: uuid.UUID | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class AccessToken(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
class ScanCreateRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    program_id: uuid.UUID  # required: scope is validated against the program
    scan_level: int = Field(default=6, ge=1, le=6)


class ScanCreatedResponse(BaseModel):
    """Returned immediately by ``POST /scans`` — the scan runs async (§2.1)."""

    scan_id: uuid.UUID
    status: ScanStatus


__all__ = [
    "RegisterRequest",
    "LoginRequest",
    "RefreshRequest",
    "TokenPair",
    "AccessToken",
    "ScanCreateRequest",
    "ScanCreatedResponse",
]
