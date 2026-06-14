"""Intermediate scan state, keyed by ``scan_id`` (CLAUDE.md §4).

Each pipeline step persists its intermediate output here so the chain can be
inspected, resumed, or debugged; the final step writes findings to PostgreSQL
(see ``workers.persistence``). Two backends share one duck-typed interface:

* :class:`InMemoryScanStateStore` — used by tests and local/dev runs.
* :class:`RedisScanStateStore` — production; one Redis hash per scan.

State values must be JSON-serializable (scanner ``.model_dump(mode="json")``
output, surface maps, finding dicts).
"""

from __future__ import annotations

import json
import os
from typing import Any

# A scan's intermediate state lives for this long in Redis (seconds) — long
# enough to debug a finished scan, short enough not to hoard memory.
DEFAULT_STATE_TTL = int(os.getenv("VULNSCAN_SCAN_STATE_TTL", str(24 * 3600)))


class InMemoryScanStateStore:
    """Process-local scan state. Not shared across workers — tests/dev only."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}

    async def set(self, scan_id: str, step: str, value: Any) -> None:
        self._data.setdefault(scan_id, {})[step] = value

    async def get(self, scan_id: str, step: str) -> Any | None:
        return self._data.get(scan_id, {}).get(step)

    async def all(self, scan_id: str) -> dict[str, Any]:
        return dict(self._data.get(scan_id, {}))

    async def aclose(self) -> None:
        """No-op; present so both stores share one interface."""


class RedisScanStateStore:
    """Redis-backed scan state: one hash ``scan:{scan_id}`` of step -> JSON."""

    def __init__(self, url: str | None = None, ttl: int = DEFAULT_STATE_TTL) -> None:
        self.url = url or os.getenv("REDIS_URL", "redis://localhost:6379/2")
        self.ttl = ttl
        self._redis: Any = None

    def _client(self) -> Any:
        if self._redis is None:
            import redis.asyncio as redis  # lazy: no connection at import

            self._redis = redis.from_url(self.url, decode_responses=True)
        return self._redis

    @staticmethod
    def _key(scan_id: str) -> str:
        return f"scan:{scan_id}"

    async def set(self, scan_id: str, step: str, value: Any) -> None:
        client = self._client()
        key = self._key(scan_id)
        await client.hset(key, step, json.dumps(value, default=str))
        await client.expire(key, self.ttl)

    async def get(self, scan_id: str, step: str) -> Any | None:
        raw = await self._client().hget(self._key(scan_id), step)
        return json.loads(raw) if raw is not None else None

    async def all(self, scan_id: str) -> dict[str, Any]:
        raw = await self._client().hgetall(self._key(scan_id))
        return {k: json.loads(v) for k, v in raw.items()}

    async def aclose(self) -> None:
        """Close the redis client before the owning event loop ends."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None


__all__ = [
    "DEFAULT_STATE_TTL",
    "InMemoryScanStateStore",
    "RedisScanStateStore",
]
