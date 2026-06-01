"""Tests for persisting pipeline findings to the database (tenant-scoped)."""

import uuid

from sqlalchemy import select

from vulnscan.ai.chains import ChainedFinding
from vulnscan.domain.enums import ScanStatus, Severity, UserRole
from vulnscan.domain.models import ScanFinding, ScanJob, Tenant, User
from vulnscan.domain.schemas import FindingBase
from vulnscan.workers.persistence import persist_scan_result
from vulnscan.workers.pipeline import PipelineResult, ScanRequest


async def _seed_scan_job(session) -> ScanJob:
    tenant = Tenant(name="Acme")
    session.add(tenant)
    await session.flush()
    user = User(
        tenant_id=tenant.id, email="h@acme.test",
        hashed_password="x", role=UserRole.HACKER,
    )
    session.add(user)
    await session.flush()
    job = ScanJob(
        tenant_id=tenant.id, user_id=user.id,
        target_url="https://example.com/", status=ScanStatus.RUNNING, scan_level=6,
    )
    session.add(job)
    await session.commit()
    return job


def _result(scan_id: str) -> PipelineResult:
    findings = [
        FindingBase(title="Verbose server header", severity=Severity.LOW,
                    cvss_score=2.0, description="d"),
        FindingBase(title="Reflected parameter", severity=Severity.MEDIUM,
                    cvss_score=5.0, description="d"),
    ]
    chained = [
        ChainedFinding(title="Reflected XSS via leaked context", severity=Severity.HIGH,
                       cvss_score=8.1, description="F1+F2", chain_parent_ids=["F1", "F2"]),
    ]
    return PipelineResult(
        scan_id=scan_id, target_url="https://example.com/", scan_level=6,
        completed_step=6, tech_stack=["nginx"], findings=findings,
        chained_findings=chained, report={"max_severity": "high"}, step_summaries=[],
    )


async def test_persist_writes_tenant_scoped_findings(session):
    job = await _seed_scan_job(session)
    request = ScanRequest(
        scan_id=str(job.id), tenant_id=str(job.tenant_id),
        target_url="https://example.com/", scope_domains=["example.com"],
    )

    summary = await persist_scan_result(session, request, _result(str(job.id)))
    assert summary["findings_persisted"] == 3

    rows = (
        await session.execute(
            select(ScanFinding).where(ScanFinding.tenant_id == job.tenant_id)
        )
    ).scalars().all()
    assert len(rows) == 3
    # Every row carries the tenant id (CLAUDE.md §2.6).
    assert all(r.tenant_id == job.tenant_id for r in rows)
    assert all(r.scan_job_id == job.id for r in rows)


async def test_chained_finding_links_to_real_finding_uuids(session):
    job = await _seed_scan_job(session)
    request = ScanRequest(
        scan_id=str(job.id), tenant_id=str(job.tenant_id),
        target_url="https://example.com/", scope_domains=["example.com"],
    )
    await persist_scan_result(session, request, _result(str(job.id)))

    individuals = (
        await session.execute(
            select(ScanFinding).where(ScanFinding.is_chained == False)  # noqa: E712
        )
    ).scalars().all()
    chained = (
        await session.execute(
            select(ScanFinding).where(ScanFinding.is_chained == True)  # noqa: E712
        )
    ).scalars().all()

    assert len(individuals) == 2 and len(chained) == 1
    # Local F1/F2 ids resolved to the real UUIDs of the two individual findings.
    individual_ids = {str(r.id) for r in individuals}
    assert set(chained[0].chain_parent_ids) == individual_ids


async def test_persist_marks_job_completed(session):
    job = await _seed_scan_job(session)
    request = ScanRequest(
        scan_id=str(job.id), tenant_id=str(job.tenant_id),
        target_url="https://example.com/", scope_domains=["example.com"],
    )
    await persist_scan_result(session, request, _result(str(job.id)))

    refreshed = await session.get(ScanJob, job.id)
    assert refreshed.status == ScanStatus.COMPLETED
    assert refreshed.completed_at is not None
