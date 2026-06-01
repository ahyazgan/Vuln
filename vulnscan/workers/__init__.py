"""Background scan workers (CLAUDE.md §4 / §7.1).

The scan pipeline runs asynchronously via Celery — the API never blocks on a
scan (§2.1). This package exposes the pure orchestration pieces (pipeline,
state store, tenant concurrency guard, persistence); the Celery app itself lives
in :mod:`vulnscan.workers.app` and is imported separately so this package can be
used without a broker (e.g. in tests).
"""

from vulnscan.workers.concurrency import (
    InMemoryConcurrencyGuard,
    RedisConcurrencyGuard,
)
from vulnscan.workers.persistence import persist_scan_result
from vulnscan.workers.pipeline import (
    PipelineResult,
    ScannerFactory,
    ScanPipeline,
    ScanRequest,
)
from vulnscan.workers.state import (
    InMemoryScanStateStore,
    RedisScanStateStore,
)

__all__ = [
    "ScanRequest",
    "PipelineResult",
    "ScanPipeline",
    "ScannerFactory",
    "InMemoryScanStateStore",
    "RedisScanStateStore",
    "InMemoryConcurrencyGuard",
    "RedisConcurrencyGuard",
    "persist_scan_result",
]
