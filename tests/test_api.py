"""Integration tests for the HTTP API (auth, scope gate, tenant isolation, RBAC)."""

import uuid

from vulnscan.api.app import API_PREFIX as P
from vulnscan.api.routes.webhooks import sign
from vulnscan.domain.enums import ScanStatus, Severity
from vulnscan.domain.models import ScanFinding, ScanJob


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _register(client, email, role, tenant):
    r = await client.post(
        f"{P}/auth/register",
        json={"email": email, "password": "password123", "role": role, "tenant_name": tenant},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def _me(client, tokens):
    r = await client.get(f"{P}/auth/me", headers=_auth(tokens))
    assert r.status_code == 200, r.text
    return r.json()


async def _make_program(client, company_tokens, scope):
    r = await client.post(
        f"{P}/programs",
        headers=_auth(company_tokens),
        json={"name": "Prog", "scope_domains": scope, "reward_table": {"high": 1000}},
    )
    assert r.status_code == 201, r.text
    return r.json()


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
async def test_register_login_refresh_me(api):
    client, _, _ = api
    tokens = await _register(client, "h@acme.com", "hacker", "Acme")
    assert tokens["access_token"] and tokens["refresh_token"]

    me = await _me(client, tokens)
    assert me["email"] == "h@acme.com"
    assert me["role"] == "hacker"

    login = await client.post(
        f"{P}/auth/login", json={"email": "h@acme.com", "password": "password123"}
    )
    assert login.status_code == 200

    refresh = await client.post(
        f"{P}/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 200 and refresh.json()["access_token"]


async def test_register_rejects_admin(api):
    client, _, _ = api
    r = await client.post(
        f"{P}/auth/register",
        json={"email": "a@x.com", "password": "password123", "role": "admin", "tenant_name": "X"},
    )
    assert r.status_code == 403


async def test_protected_route_requires_token(api):
    client, _, _ = api
    r = await client.get(f"{P}/scans")
    assert r.status_code in (401, 403)  # no bearer credentials at all

    r = await client.get(f"{P}/scans", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


async def test_bad_login_rejected(api):
    client, _, _ = api
    await _register(client, "h@acme.com", "hacker", "Acme")
    r = await client.post(f"{P}/auth/login", json={"email": "h@acme.com", "password": "wrongpass"})
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# RBAC + tenant isolation
# --------------------------------------------------------------------------- #
async def test_hacker_cannot_create_program(api):
    client, _, _ = api
    hacker = await _register(client, "h@acme.com", "hacker", "Acme")
    r = await client.post(
        f"{P}/programs",
        headers=_auth(hacker),
        json={"name": "P", "scope_domains": ["x.com"]},
    )
    assert r.status_code == 403


async def test_program_tenant_isolation(api):
    client, _, _ = api
    company_a = await _register(client, "a@a.com", "company", "CompanyA")
    company_b = await _register(client, "b@b.com", "company", "CompanyB")
    await _make_program(client, company_a, ["a.example.com"])

    # Company B sees none of Company A's programs (§2.6).
    r = await client.get(f"{P}/programs", headers=_auth(company_b))
    assert r.status_code == 200 and r.json() == []


# --------------------------------------------------------------------------- #
# Scans + scope gate (§7.2) + async dispatch (§2.1)
# --------------------------------------------------------------------------- #
async def test_scan_in_scope_enqueues_and_returns_job_id(api):
    client, enqueued, _ = api
    company = await _register(client, "c@acme.com", "company", "Acme")
    program = await _make_program(client, company, ["example.com"])
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")

    r = await client.post(
        f"{P}/scans",
        headers=_auth(hacker),
        json={
            "target_url": "https://example.com/login",
            "program_id": program["id"],
            "scan_level": 4,
        },
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == ScanStatus.QUEUED.value
    uuid.UUID(body["scan_id"])  # valid id

    # Exactly one scan handed to the worker, with the program scope (§2.1).
    assert len(enqueued) == 1
    assert enqueued[0]["scope_domains"] == ["example.com"]
    assert enqueued[0]["scan_level"] == 4
    assert enqueued[0]["scan_id"] == body["scan_id"]


async def test_scan_out_of_scope_refused_and_not_enqueued(api):
    client, enqueued, _ = api
    company = await _register(client, "c@acme.com", "company", "Acme")
    program = await _make_program(client, company, ["example.com"])
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")

    r = await client.post(
        f"{P}/scans",
        headers=_auth(hacker),
        json={"target_url": "https://evil.com/", "program_id": program["id"]},
    )
    assert r.status_code == 422
    assert enqueued == []  # out-of-scope target never queued (§7.2)


async def test_scan_unknown_program_404(api):
    client, enqueued, _ = api
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")
    r = await client.post(
        f"{P}/scans",
        headers=_auth(hacker),
        json={"target_url": "https://example.com/", "program_id": str(uuid.uuid4())},
    )
    assert r.status_code == 404
    assert enqueued == []


# --------------------------------------------------------------------------- #
# Submissions (hacker submits, company reviews)
# --------------------------------------------------------------------------- #
async def _seed_finding(maker, tenant_id, user_id) -> uuid.UUID:
    async with maker() as s:
        job = ScanJob(
            tenant_id=tenant_id,
            user_id=user_id,
            target_url="https://example.com/",
            status=ScanStatus.COMPLETED,
            scan_level=6,
        )
        s.add(job)
        await s.flush()
        finding = ScanFinding(
            tenant_id=tenant_id,
            scan_job_id=job.id,
            title="XSS",
            severity=Severity.HIGH,
            cvss_score=7.5,
            description="reflected xss",
        )
        s.add(finding)
        await s.commit()
        return finding.id


async def test_submission_lifecycle(api):
    client, _, maker = api
    company = await _register(client, "c@co.com", "company", "Company")
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")
    company_me = await _me(client, company)
    hacker_me = await _me(client, hacker)

    finding_id = await _seed_finding(
        maker, uuid.UUID(hacker_me["tenant_id"]), uuid.UUID(hacker_me["id"])
    )

    # Hacker submits the finding to the company.
    r = await client.post(
        f"{P}/submissions",
        headers=_auth(hacker),
        json={"finding_id": str(finding_id), "company_tenant_id": company_me["tenant_id"]},
    )
    assert r.status_code == 201, r.text
    submission_id = r.json()["id"]
    assert r.json()["status"] == "pending"

    # Company sees it; hacker's tenant does too (each its own side).
    company_list = await client.get(f"{P}/submissions", headers=_auth(company))
    assert any(s["id"] == submission_id for s in company_list.json())

    # Company accepts with a reward.
    review = await client.post(
        f"{P}/submissions/{submission_id}/review",
        headers=_auth(company),
        json={"status": "accepted", "reward_amount": "750.00"},
    )
    assert review.status_code == 200
    assert review.json()["status"] == "accepted"

    # A different company cannot review it.
    other = await _register(client, "o@o.com", "company", "Other")
    forbidden = await client.post(
        f"{P}/submissions/{submission_id}/review",
        headers=_auth(other),
        json={"status": "rejected"},
    )
    assert forbidden.status_code == 404


# --------------------------------------------------------------------------- #
# Webhooks
# --------------------------------------------------------------------------- #
async def test_webhook_signature_verified(api):
    client, _, _ = api
    body = b'{"event":"scan.completed"}'
    good = await client.post(
        f"{P}/webhooks/inbound",
        content=body,
        headers={"X-VulnScan-Signature": sign(body), "Content-Type": "application/json"},
    )
    assert good.status_code == 204

    bad = await client.post(
        f"{P}/webhooks/inbound",
        content=body,
        headers={"X-VulnScan-Signature": "deadbeef"},
    )
    assert bad.status_code == 401
