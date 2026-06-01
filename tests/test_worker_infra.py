"""Tests for the scan state store and per-tenant concurrency guard."""

from vulnscan.workers.concurrency import InMemoryConcurrencyGuard
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
