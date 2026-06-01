"""Tests for the domain models: creation, defaults, tenant isolation, soft delete.

Run against an in-memory SQLite database (see conftest.py).
"""

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from vulnscan.domain.enums import (
    PlanType,
    ScanStatus,
    Severity,
    SubmissionStatus,
    UserRole,
)
from vulnscan.domain.models import (
    BountyProgram,
    BountySubmission,
    ScanFinding,
    ScanJob,
    Tenant,
    User,
)


# --------------------------------------------------------------------------- #
# Factory helpers
# --------------------------------------------------------------------------- #
async def make_tenant(session, name="Acme", plan=PlanType.PRO) -> Tenant:
    t = Tenant(name=name, plan=plan)
    session.add(t)
    await session.flush()
    return t


async def make_user(session, tenant, email="hacker@acme.com", role=UserRole.HACKER):
    u = User(
        tenant_id=tenant.id,
        email=email,
        hashed_password="$argon2id$fakehash",
        role=role,
    )
    session.add(u)
    await session.flush()
    return u


async def make_program(session, tenant, name="Web App Program"):
    p = BountyProgram(
        tenant_id=tenant.id,
        name=name,
        scope_domains=["example.com", "*.api.example.com"],
        max_severity=Severity.CRITICAL,
        reward_table={"critical": 5000, "high": 1500, "medium": 400},
    )
    session.add(p)
    await session.flush()
    return p


async def make_scan_job(session, tenant, user, program, level=3):
    j = ScanJob(
        tenant_id=tenant.id,
        user_id=user.id,
        program_id=program.id,
        target_url="https://example.com/login",
        scan_level=level,
    )
    session.add(j)
    await session.flush()
    return j


async def make_finding(session, tenant, job, severity=Severity.HIGH, cvss=7.5):
    f = ScanFinding(
        tenant_id=tenant.id,
        scan_job_id=job.id,
        title="Reflected XSS in login form",
        severity=severity,
        cvss_score=cvss,
        description="User input reflected unescaped into the HTML body.",
        proof_of_concept="POST /login q=<script>alert(1)</script>",
        recommendation="Context-aware output encoding; add CSP.",
        references=["https://owasp.org/www-community/attacks/xss/"],
    )
    session.add(f)
    await session.flush()
    return f


# --------------------------------------------------------------------------- #
# Creation & defaults
# --------------------------------------------------------------------------- #
async def test_full_object_graph_persists(session):
    tenant = await make_tenant(session)
    user = await make_user(session, tenant)
    program = await make_program(session, tenant)
    job = await make_scan_job(session, tenant, user, program)
    finding = await make_finding(session, tenant, job)
    await session.commit()

    # UUID primary keys generated client-side.
    assert isinstance(tenant.id, uuid.UUID)
    assert isinstance(finding.id, uuid.UUID)

    # Defaults applied.
    assert program.is_active is True
    assert job.status is ScanStatus.QUEUED
    assert finding.is_chained is False
    assert finding.chain_parent_ids == []

    # Timestamps populated by the DB.
    await session.refresh(tenant)
    assert tenant.created_at is not None
    assert tenant.updated_at is not None
    assert tenant.deleted_at is None


async def test_json_columns_round_trip(session):
    tenant = await make_tenant(session)
    program = await make_program(session, tenant)
    await session.commit()
    program_id = program.id  # capture before expiring (avoids sync lazy-load)
    session.expire_all()

    loaded = await session.get(BountyProgram, program_id)
    assert loaded.scope_domains == ["example.com", "*.api.example.com"]
    assert loaded.reward_table["critical"] == 5000


async def test_enum_stored_as_lowercase_value(session):
    await make_tenant(session, name="EnumCo", plan=PlanType.ENTERPRISE)
    await session.commit()

    # Raw stored value must be the lowercase enum *value*, not its name.
    raw = (await session.execute(text("SELECT plan FROM tenants"))).scalar_one()
    assert raw == "enterprise"


async def test_chained_finding_references_parents(session):
    tenant = await make_tenant(session)
    user = await make_user(session, tenant)
    program = await make_program(session, tenant)
    job = await make_scan_job(session, tenant, user, program)
    low1 = await make_finding(session, tenant, job, Severity.LOW, 3.1)
    low2 = await make_finding(session, tenant, job, Severity.LOW, 2.0)

    chained = ScanFinding(
        tenant_id=tenant.id,
        scan_job_id=job.id,
        title="Account takeover via chained low findings",
        severity=Severity.HIGH,
        cvss_score=8.1,
        description="Combining info leak + open redirect enables ATO.",
        references=[],
        is_chained=True,
        chain_parent_ids=[str(low1.id), str(low2.id)],  # JSON-safe string ids
    )
    session.add(chained)
    await session.commit()
    chained_id = chained.id
    expected_parents = set(chained.chain_parent_ids)  # capture before expiring
    session.expire_all()

    loaded = await session.get(ScanFinding, chained_id)
    assert loaded.is_chained is True
    assert set(loaded.chain_parent_ids) == expected_parents


async def test_submission_dual_tenant_and_money(session):
    hacker_tenant = await make_tenant(session, name="HackerOrg")
    company_tenant = await make_tenant(session, name="CompanyOrg")
    hacker = await make_user(session, hacker_tenant, email="h@hack.io")
    program = await make_program(session, company_tenant)
    job = await make_scan_job(session, hacker_tenant, hacker, program)
    finding = await make_finding(session, hacker_tenant, job)

    sub = BountySubmission(
        tenant_id=hacker_tenant.id,          # submitter side
        company_tenant_id=company_tenant.id,  # reviewer side
        finding_id=finding.id,
        hacker_user_id=hacker.id,
        reward_amount=Decimal("1500.00"),
    )
    session.add(sub)
    await session.commit()
    sub_id = sub.id  # capture ids before expiring (avoids sync lazy-load)
    hacker_tid, company_tid = hacker_tenant.id, company_tenant.id
    session.expire_all()

    loaded = await session.get(BountySubmission, sub_id)
    assert loaded.status is SubmissionStatus.PENDING
    assert loaded.tenant_id == hacker_tid
    assert loaded.company_tenant_id == company_tid
    assert loaded.reward_amount == Decimal("1500.00")


# --------------------------------------------------------------------------- #
# Tenant isolation (CLAUDE.md §2.6)
# --------------------------------------------------------------------------- #
async def test_tenant_isolation_filters_by_tenant_id(session):
    t1 = await make_tenant(session, name="TenantOne")
    t2 = await make_tenant(session, name="TenantTwo")
    await make_user(session, t1, email="a@one.com")
    await make_user(session, t2, email="b@two.com")
    await make_user(session, t2, email="c@two.com")
    await session.commit()

    t1_users = (
        await session.execute(
            select(User).where(User.tenant_id == t1.id, User.deleted_at.is_(None))
        )
    ).scalars().all()
    t2_users = (
        await session.execute(
            select(User).where(User.tenant_id == t2.id, User.deleted_at.is_(None))
        )
    ).scalars().all()

    assert {u.email for u in t1_users} == {"a@one.com"}
    assert {u.email for u in t2_users} == {"b@two.com", "c@two.com"}
    # No row from t1 ever appears in a t2-scoped query.
    assert all(u.tenant_id == t2.id for u in t2_users)


async def test_findings_do_not_leak_across_tenants(session):
    t1 = await make_tenant(session, name="One")
    t2 = await make_tenant(session, name="Two")
    u1 = await make_user(session, t1, email="x@one.com")
    u2 = await make_user(session, t2, email="y@two.com")
    p1 = await make_program(session, t1)
    p2 = await make_program(session, t2)
    j1 = await make_scan_job(session, t1, u1, p1)
    j2 = await make_scan_job(session, t2, u2, p2)
    await make_finding(session, t1, j1, Severity.CRITICAL, 9.8)
    await make_finding(session, t2, j2, Severity.MEDIUM, 5.0)
    await session.commit()

    rows = (
        await session.execute(
            select(ScanFinding).where(ScanFinding.tenant_id == t1.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].severity is Severity.CRITICAL
    assert rows[0].tenant_id == t1.id


async def test_email_unique_within_tenant_but_reusable_across_tenants(session):
    t1 = await make_tenant(session, name="One")
    t2 = await make_tenant(session, name="Two")
    await make_user(session, t1, email="dup@example.com")
    # Same email in a *different* tenant is allowed.
    await make_user(session, t2, email="dup@example.com")
    await session.commit()

    # Same email in the *same* tenant violates the unique constraint.
    session.add(
        User(
            tenant_id=t1.id,
            email="dup@example.com",
            hashed_password="x",
            role=UserRole.HACKER,
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


# --------------------------------------------------------------------------- #
# Soft delete
# --------------------------------------------------------------------------- #
async def test_soft_delete_excludes_row_from_active_query(session):
    tenant = await make_tenant(session)
    user = await make_user(session, tenant)
    await session.commit()

    user.deleted_at = datetime.now(timezone.utc)
    await session.commit()

    active = (
        await session.execute(
            select(User).where(
                User.tenant_id == tenant.id, User.deleted_at.is_(None)
            )
        )
    ).scalars().all()
    assert active == []

    # The row still physically exists (soft delete, not hard delete).
    all_rows = (
        await session.execute(select(User).where(User.tenant_id == tenant.id))
    ).scalars().all()
    assert len(all_rows) == 1
    assert all_rows[0].deleted_at is not None


# --------------------------------------------------------------------------- #
# Check constraints
# --------------------------------------------------------------------------- #
async def test_scan_level_check_constraint(session):
    tenant = await make_tenant(session)
    user = await make_user(session, tenant)
    program = await make_program(session, tenant)
    session.add(
        ScanJob(
            tenant_id=tenant.id,
            user_id=user.id,
            program_id=program.id,
            target_url="https://example.com",
            scan_level=7,  # out of range 1..6
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


async def test_cvss_score_check_constraint(session):
    tenant = await make_tenant(session)
    user = await make_user(session, tenant)
    program = await make_program(session, tenant)
    job = await make_scan_job(session, tenant, user, program)
    session.add(
        ScanFinding(
            tenant_id=tenant.id,
            scan_job_id=job.id,
            title="bad cvss",
            severity=Severity.LOW,
            cvss_score=11.0,  # out of range 0..10
            description="x",
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()
