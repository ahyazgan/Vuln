"""Per-tenant scan concurrency guard (CLAUDE.md §7.1 — NON-NEGOTIABLE).

Max **one** concurrent scan per tenant: before a scan runs, the worker tries to
acquire the tenant's lock; if another scan already holds it, the new job is
re-queued rather than run concurrently. Two backends, one interface:

* :class:`InMemoryConcurrencyGuard` — tests/dev (single process only).
* :class:`RedisConcurrencyGuard` — production; an atomic ``SET NX`` lock per
  tenant with a TTL so a crashed worker can't wedge a tenant forever.

``acquire`` returns ``True`` if the caller now holds the lock, ``False`` if the
tenant already has a running scan. ``release`` only frees the lock if the caller
owns it (so a re-queued job can't release the running scan's lock).
"""

from __future__ import annotations

import os

# Safety valve: if a worker dies mid-scan, the tenant lock self-expires after
# this many seconds so the tenant isn't blocked forever.
DEFAULT_LOCK_TTL = int(os.getenv("VULNSCAN_SCAN_LOCK_TTL", str(2 * 3600)))


class InMemoryConcurrencyGuard:
    """Process-local tenant lock. Single-worker only — tests/dev."""

    def __init__(self) -> None:
        self._held: dict[str, str] = {}  # tenant_id -> owning scan_id

    async def acquire(self, tenant_id: str, scan_id: str) -> bool:
        if tenant_id in self._held:
            return False
        self._held[tenant_id] = scan_id
        return True

    async def release(self, tenant_id: str, scan_id: str) -> None:
        if self._held.get(tenant_id) == scan_id:
            del self._held[tenant_id]

    async def current(self, tenant_id: str) -> str | None:
        return self._held.get(tenant_id)

    async def aclose(self) -> None:
        """No-op; present so both guards share one interface."""


class RedisConcurrencyGuard:
    """Redis ``SET NX EX`` tenant lock — safe across many workers/hosts."""

    def __init__(self, url: str | None = None, ttl: int = DEFAULT_LOCK_TTL) -> None:
        self.url = url or os.getenv("REDIS_URL", "redis://localhost:6379/2")
        self.ttl = ttl
        self._redis = None

    def _client(self):
        if self._redis is None:
            import redis.asyncio as redis  # lazy import

            self._redis = redis.from_url(self.url, decode_responses=True)
        return self._redis

    @staticmethod
    def _key(tenant_id: str) -> str:
        return f"scan:lock:{tenant_id}"

    async def acquire(self, tenant_id: str, scan_id: str) -> bool:
        # Atomic: only sets (and so only succeeds) if no lock currently exists.
        ok = await self._client().set(self._key(tenant_id), scan_id, nx=True, ex=self.ttl)
        return bool(ok)

    async def release(self, tenant_id: str, scan_id: str) -> None:
        client = self._client()
        key = self._key(tenant_id)
        # Only the owner may release — guard against freeing a different scan's lock.
        if await client.get(key) == scan_id:
            await client.delete(key)

    async def current(self, tenant_id: str) -> str | None:
        return await self._client().get(self._key(tenant_id))

    async def aclose(self) -> None:
        """Close the redis client. Call before the owning event loop ends so the
        client isn't left bound to a closed loop (it is created per task run)."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None


__all__ = [
    "DEFAULT_LOCK_TTL",
    "InMemoryConcurrencyGuard",
    "RedisConcurrencyGuard",
]
