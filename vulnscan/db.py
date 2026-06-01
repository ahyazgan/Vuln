"""Async SQLAlchemy engine/session setup and the FastAPI ``get_db`` dependency.

The engine is created lazily-at-import but does not connect until first use, so
importing this module never requires a live database (safe for tests/CLI).

Production uses PostgreSQL via asyncpg; the URL comes from ``DATABASE_URL``,
e.g. ``postgresql+asyncpg://user:pass@host:5432/vulnscan``. Tests inject their
own SQLite engine and do not import the module-level engine.
"""

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vulnscan.domain.models import Base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://vulnscan:vulnscan@localhost:5432/vulnscan",
)

# echo SQL when VULNSCAN_SQL_ECHO is truthy (debugging only).
_ECHO = os.getenv("VULNSCAN_SQL_ECHO", "").lower() in {"1", "true", "yes"}

engine = create_async_engine(
    DATABASE_URL,
    echo=_ECHO,
    pool_pre_ping=True,  # recycle dead connections transparently
    future=True,
)

# expire_on_commit=False keeps ORM objects usable after commit (e.g. returning
# them from a route after the transaction closes).
SessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a session, rolling back on error.

    Routes commit explicitly. On any exception the transaction is rolled back
    and re-raised; the session is always closed by the ``async with`` block.
    """
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_models() -> None:
    """Create all tables from metadata. Convenience for local/dev bootstrapping.

    Production schema changes go through Alembic migrations, not this helper.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Dispose the connection pool (call on app shutdown)."""
    await engine.dispose()


__all__ = [
    "DATABASE_URL",
    "engine",
    "SessionLocal",
    "get_db",
    "init_models",
    "dispose_engine",
]
