"""Provision a platform ADMIN out-of-band (CLAUDE.md §1).

Self-registration as admin is refused by the API, so admins are created here.
The admin gets its own tenant (the platform-operator tenant); its cross-tenant
powers come from the role, not from tenant membership.

Run (against the configured DATABASE_URL)::

    DATABASE_URL=postgresql+asyncpg://vulnscan:vulnscan@127.0.0.1:5432/vulnscan \\
    python scripts/create_admin.py admin@platform.test 'a-strong-password' "Platform Ops"
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

from vulnscan.api.security import hash_password
from vulnscan.db import SessionLocal, dispose_engine
from vulnscan.domain.enums import UserRole
from vulnscan.domain.models import Tenant, User


async def create_admin(email: str, password: str, tenant_name: str) -> None:
    async with SessionLocal() as session:
        existing = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if existing is not None:
            print(f"user {email!r} already exists (id={existing.id}); aborting.")
            return

        tenant = Tenant(name=tenant_name)
        session.add(tenant)
        await session.flush()
        user = User(
            tenant_id=tenant.id,
            email=email,
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
        )
        session.add(user)
        await session.commit()
        print(f"created admin {email!r} (user_id={user.id}, tenant_id={tenant.id})")


def main() -> None:
    if len(sys.argv) != 4:
        print("usage: python scripts/create_admin.py <email> <password> <tenant_name>")
        raise SystemExit(2)
    email, password, tenant_name = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        asyncio.run(create_admin(email, password, tenant_name))
    finally:
        asyncio.run(dispose_engine())


if __name__ == "__main__":
    main()
