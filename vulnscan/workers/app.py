"""Celery app and the ``run_scan`` task (CLAUDE.md §2.1 / §4 / §7.1).

The API never blocks on a scan: ``POST /scans`` enqueues ``run_scan`` and returns
a job id immediately. This module wires the offline pipeline to real Redis/DB:

* enforce one concurrent scan per tenant (§7.1) — re-queue if the tenant is busy,
* run the six-step pipeline over real scanners + the Claude engine,
* persist findings to PostgreSQL (§4 final step),
* always release the tenant lock.

Importing this module constructs the Celery app but opens no broker connection,
so it's safe to import without a running Redis (e.g. for ``celery inspect`` or
to register the task in the API process).
"""

from __future__ import annotations

import asyncio
import logging
import os

from celery import Celery

from vulnscan.ai.engine import AnalysisEngine
from vulnscan.db import SessionLocal
from vulnscan.workers.concurrency import RedisConcurrencyGuard
from vulnscan.workers.persistence import persist_scan_result
from vulnscan.workers.pipeline import ScannerFactory, ScanPipeline, ScanRequest
from vulnscan.workers.state import RedisScanStateStore

logger = logging.getLogger("vulnscan.workers")

BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
# Seconds to wait before retrying a scan blocked by the tenant's running scan.
SCAN_REQUEUE_DELAY = int(os.getenv("VULNSCAN_SCAN_RETRY_SECONDS", "30"))

celery_app = Celery("vulnscan", broker=BROKER_URL, backend=RESULT_BACKEND)
celery_app.conf.update(
    task_acks_late=True,           # re-deliver if a worker dies mid-scan
    worker_prefetch_multiplier=1,  # one long scan at a time per worker process
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
)


async def _run_and_persist(request: ScanRequest) -> dict:
    """Run the pipeline against live dependencies and persist the findings."""
    factory = ScannerFactory(request.scope_domains, scan_id=request.scan_id)
    engine = AnalysisEngine()
    state = RedisScanStateStore()
    try:
        result = await ScanPipeline().run(
            request, scanner_factory=factory, engine=engine, state=state
        )
    finally:
        await factory.aclose()

    async with SessionLocal() as session:
        summary = await persist_scan_result(session, request, result)
    return {**summary, "report": result.report}


@celery_app.task(bind=True, name="vulnscan.run_scan", max_retries=None)
def run_scan(self, request: dict) -> dict:
    """Entry point enqueued by the API. ``request`` is a ``ScanRequest`` dict.

    Enforces the per-tenant concurrency limit (§7.1): if the tenant already has a
    running scan, the task re-queues itself rather than running a second one.
    """
    req = ScanRequest(**request)
    guard = RedisConcurrencyGuard()

    if not asyncio.run(guard.acquire(req.tenant_id, req.scan_id)):
        logger.info(
            '{"event": "scan_requeued_tenant_busy", "tenant": "%s", "scan": "%s"}',
            req.tenant_id, req.scan_id,
        )
        raise self.retry(countdown=SCAN_REQUEUE_DELAY)

    try:
        return asyncio.run(_run_and_persist(req))
    finally:
        asyncio.run(guard.release(req.tenant_id, req.scan_id))


__all__ = ["celery_app", "run_scan", "SCAN_REQUEUE_DELAY"]
