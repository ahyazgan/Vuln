"""Tests for the scan state store, per-tenant concurrency guard, and the
worker's acquire→run→release orchestration (CLAUDE.md §7.1)."""

from vulnscan.workers.concurrency import InMemoryConcurrencyGuard
from vulnscan.workers.pipeline import ScanRequest
from vulnscan.workers.state import InMemoryScanStateStore


# --------------------------------------------------------------------------- #
# State store
# --------------------------------------------------------------------------- #
async def test_state_set_get_all():
    store = InMemoryScanStateStore()
    await store.set("scan1", "recon", {"status": 200})
    await store.set("scan1", "report", {"max_severity": "high"})

    assert await store.get("scan1", "recon") == {"status": 200}
    assert await store.get("scan1", "missing") is None
    assert set((await store.all("scan1")).keys()) == {"recon", "report"}
    assert await store.all("other") == {}


# --------------------------------------------------------------------------- #
# Concurrency guard (CLAUDE.md §7.1)
# --------------------------------------------------------------------------- #
async def test_one_scan_per_tenant():
    guard = InMemoryConcurrencyGuard()
    assert await guard.acquire("tenantA", "scan1") is True
    # A second scan for the same tenant is refused while the first runs.
    assert await guard.acquire("tenantA", "scan2") is False
    # A different tenant is unaffected.
    assert await guard.acquire("tenantB", "scan3") is True


async def test_release_frees_the_tenant():
    guard = InMemoryConcurrencyGuard()
    await guard.acquire("tenantA", "scan1")
    await guard.release("tenantA", "scan1")
    assert await guard.acquire("tenantA", "scan2") is True


async def test_release_only_by_owner():
    guard = InMemoryConcurrencyGuard()
    await guard.acquire("tenantA", "scan1")
    # A non-owning scan must not be able to free the running scan's lock.
    await guard.release("tenantA", "scan2")
    assert await guard.acquire("tenantA", "scan3") is False
    assert await guard.current("tenantA") == "scan1"


async def test_guards_and_stores_have_aclose():
    # Both in-memory backends expose aclose() so the worker can clean up either
    # backend uniformly before its event loop ends.
    await InMemoryConcurrencyGuard().aclose()
    await InMemoryScanStateStore().aclose()


# --------------------------------------------------------------------------- #
# Worker orchestration: acquire -> run -> release (single event loop)
# --------------------------------------------------------------------------- #
def _req(scan_id: str, tenant_id: str) -> ScanRequest:
    return ScanRequest(
        scan_id=scan_id,
        tenant_id=tenant_id,
        target_url="http://example.com/",
        scope_domains=["example.com"],
        scan_level=1,
    )


async def test_acquire_run_release_runs_and_frees_lock(monkeypatch):
    from vulnscan.workers import app as wapp

    guard = InMemoryConcurrencyGuard()
    monkeypatch.setattr(wapp, "RedisConcurrencyGuard", lambda: guard)

    async def fake_run_and_persist(req):
        # The tenant lock must be held *while* the scan runs.
        assert await guard.current(req.tenant_id) == req.scan_id
        return {"scan_id": req.scan_id, "findings_persisted": 0}

    monkeypatch.setattr(wapp, "_run_and_persist", fake_run_and_persist)

    result = await wapp._acquire_run_release(_req("s1", "t1"))
    assert result == {"scan_id": "s1", "findings_persisted": 0}
    # Lock released after the scan completes (§7.1) — no leak.
    assert await guard.current("t1") is None


async def test_acquire_run_release_skips_when_tenant_busy(monkeypatch):
    from vulnscan.workers import app as wapp

    guard = InMemoryConcurrencyGuard()
    await guard.acquire("t1", "already-running")  # tenant is busy
    monkeypatch.setattr(wapp, "RedisConcurrencyGuard", lambda: guard)

    async def fail_if_called(req):  # pragma: no cover - must not run
        raise AssertionError("scan must not run while the tenant is busy")

    monkeypatch.setattr(wapp, "_run_and_persist", fail_if_called)

    result = await wapp._acquire_run_release(_req("s2", "t1"))
    assert result is None  # caller (run_scan) re-queues on None
    # The original owner's lock is untouched — not freed by the refused scan.
    assert await guard.current("t1") == "already-running"


def test_worker_engine_uses_nullpool():
    # Each Celery task runs in a fresh event loop; pooled asyncpg connections
    # can't cross loops, so the worker engine must pool nothing.
    from sqlalchemy.pool import NullPool

    from vulnscan.db import worker_engine

    assert isinstance(worker_engine.pool, NullPool)
