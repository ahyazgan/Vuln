"""Persist pipeline findings to PostgreSQL — the final step of §4.

Intermediate scan state lives in Redis (``workers.state``); the *findings* are
the durable output and land in the database here. Every row carries the scan's
``tenant_id`` (CLAUDE.md §2.6 / §7) and only vulnerability metadata is stored —
never target user data (§2.5); the scanners already redact secrets upstream.

Chained findings reference their parents by the local ``F1``/``F2`` ids the
chain step assigned. This maps those to the real DB UUIDs of the individual
findings inserted in the same transaction, so ``chain_parent_ids`` is a valid
cross-reference once persisted.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from vulnscan.ai.chains import ChainedFinding
from vulnscan.domain.enums import ScanStatus
from vulnscan.domain.models import ScanFinding, ScanJob
from vulnscan.workers.pipeline import PipelineResult, ScanRequest


async def persist_scan_result(session, request: ScanRequest, result: PipelineResult) -> dict:
    """Write findings + chained findings and mark the scan job completed.

    Returns a small summary dict. Commits the transaction. Caller owns the
    session lifecycle.
    """
    tenant_id = uuid.UUID(str(request.tenant_id))
    scan_job_id = uuid.UUID(str(request.scan_id))

    # 1. Individual findings — insert and remember each one's local id -> row.
    id_map: dict[str, ScanFinding] = {}
    inserted: list[ScanFinding] = []
    for i, f in enumerate(result.findings):
        row = ScanFinding(
            tenant_id=tenant_id,
            scan_job_id=scan_job_id,
            title=f.title,
            severity=f.severity,
            cvss_score=f.cvss_score,
            description=f.description,
            proof_of_concept=f.proof_of_concept,
            recommendation=f.recommendation,
            references=list(f.references),
            is_chained=False,
            chain_parent_ids=[],
        )
        session.add(row)
        inserted.append(row)
        id_map[f"F{i + 1}"] = row

    # Flush so the individual rows get their UUIDs before we reference them.
    await session.flush()

    # 2. Chained findings — resolve local parent ids to real UUIDs.
    for c in result.chained_findings:
        parent_uuids = [
            str(id_map[pid].id) for pid in c.chain_parent_ids if pid in id_map
        ]
        row = ScanFinding(
            tenant_id=tenant_id,
            scan_job_id=scan_job_id,
            title=c.title,
            severity=c.severity,
            cvss_score=c.cvss_score,
            description=c.description,
            proof_of_concept=c.proof_of_concept,
            recommendation=c.recommendation,
            references=list(c.references),
            is_chained=True,
            chain_parent_ids=parent_uuids,
        )
        session.add(row)
        inserted.append(row)

    # 3. Mark the scan job completed (if it exists — it always does in prod).
    job = await session.get(ScanJob, scan_job_id)
    if job is not None:
        job.status = ScanStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)

    await session.commit()
    return {
        "scan_id": request.scan_id,
        "findings_persisted": len(inserted),
        "completed_step": result.completed_step,
    }


__all__ = ["persist_scan_result"]
