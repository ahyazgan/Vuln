"""Authentication: current-user dependency, role guards, and the auth router.

Holds both the security *dependencies* (``get_current_user``, ``require_roles``)
and the auth *endpoints* (register / login / refresh). Every request that
touches tenant data resolves a :class:`CurrentUser` from a bearer access token;
the user is reloaded from the DB each request so a deleted account can't keep
acting on a still-valid token.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscan.api.deps import get_db
from vulnscan.api.schemas import (
    AccessToken,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
)
from vulnscan.api.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from vulnscan.domain.enums import UserRole
from vulnscan.domain.models import Tenant, User
from vulnscan.domain.schemas import UserRead

router = APIRouter(prefix="/auth", tags=["auth"])

_bearer = HTTPBearer(auto_error=True)


@dataclass
class CurrentUser:
    """The authenticated principal, resolved per request."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role: UserRole


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    session: AsyncSession = Depends(get_db),
) -> CurrentUser:
    try:
        claims = decode_token(credentials.credentials, expected_type="access")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = await _load_live_user(session, uuid.UUID(claims["sub"]))
    if user is None or str(user.tenant_id) != claims.get("tenant"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="user no longer valid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(
        id=user.id, tenant_id=user.tenant_id, email=user.email, role=user.role
    )


def require_roles(*roles: UserRole):
    """Dependency factory that admits only the given roles (CLAUDE.md §1)."""

    async def _guard(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role in {[r.value for r in roles]}",
            )
        return user

    return _guard


async def _load_live_user(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    stmt = select(User).where(User.id == user_id).where(User.deleted_at.is_(None))
    return (await session.execute(stmt)).scalar_one_or_none()


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@router.post("/register", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, session: AsyncSession = Depends(get_db)) -> TokenPair:
    """Create a new tenant org + first user. Admin self-registration is refused."""
    if body.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="admins are provisioned out-of-band"
        )

    tenant = Tenant(name=body.tenant_name)
    session.add(tenant)
    await session.flush()
    user = User(
        tenant_id=tenant.id,
        email=str(body.email),
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    session.add(user)
    await session.commit()

    return _issue_pair(user)


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_db)) -> TokenPair:
    stmt = select(User).where(User.email == str(body.email)).where(User.deleted_at.is_(None))
    if body.tenant_id is not None:
        stmt = stmt.where(User.tenant_id == body.tenant_id)
    matches = list((await session.execute(stmt)).scalars().all())

    if len(matches) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="email exists in multiple tenants; supply tenant_id",
        )
    user = matches[0] if matches else None
    # Verify even when the user is missing would leak timing; a constant-ish
    # failure path is acceptable here — reject with a generic message.
    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
        )
    return _issue_pair(user)


@router.post("/refresh", response_model=AccessToken)
async def refresh(body: RefreshRequest, session: AsyncSession = Depends(get_db)) -> AccessToken:
    try:
        claims = decode_token(body.refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc

    user = await _load_live_user(session, uuid.UUID(claims["sub"]))
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown user")
    return AccessToken(
        access_token=create_access_token(
            user_id=user.id, tenant_id=user.tenant_id, role=user.role.value
        )
    )


@router.get("/me", response_model=UserRead)
async def me(
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> User:
    db_user = await _load_live_user(session, user.id)
    if db_user is None:  # pragma: no cover - get_current_user already guarantees this
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown user")
    return db_user


def _issue_pair(user: User) -> TokenPair:
    return TokenPair(
        access_token=create_access_token(
            user_id=user.id, tenant_id=user.tenant_id, role=user.role.value
        ),
        refresh_token=create_refresh_token(
            user_id=user.id, tenant_id=user.tenant_id, role=user.role.value
        ),
    )


__all__ = ["router", "CurrentUser", "get_current_user", "require_roles"]
