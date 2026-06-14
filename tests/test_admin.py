"""Tests for the admin (platform-management) surface (CLAUDE.md §1).

Admins are provisioned out-of-band, so each test seeds an admin user directly
and logs in for a token. Covers RBAC (non-admins forbidden), platform stats,
tenant listing with usage counts, plan updates, suspension, and the audit feed.
"""

import uuid

from vulnscan.api.app import API_PREFIX as P
from vulnscan.api.security import hash_password
from vulnscan.domain.enums import PlanType, ScanStatus, UserRole
from vulnscan.domain.models import ScanJob, Tenant, User


async def _register(client, email, role, tenant):
    r = await client.post(
        f"{P}/auth/register",
        json={"email": email, "password": "password123", "role": role, "tenant_name": tenant},
    )
    assert r.status_code == 201, r.text
    return r.json()


def _auth(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def _seed_admin(maker, email="admin@ops.com") -> None:
    async with maker() as s:
        tenant = Tenant(name="Platform Ops")
        s.add(tenant)
        await s.flush()
        s.add(
            User(
                tenant_id=tenant.id,
                email=email,
                hashed_password=hash_password("password123"),
                role=UserRole.ADMIN,
            )
        )
        await s.commit()


async def _admin_token(client, maker, email="admin@ops.com") -> dict:
    await _seed_admin(maker, email)
    r = await client.post(f"{P}/auth/login", json={"email": email, "password": "password123"})
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #
async def test_non_admin_forbidden(api):
    client, _, _ = api
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")
    for path in ("/admin/stats", "/admin/tenants", "/admin/audit"):
        r = await client.get(f"{P}{path}", headers=_auth(hacker))
        assert r.status_code == 403, f"{path} -> {r.status_code}"


async def test_admin_requires_auth(api):
    client, _, _ = api
    r = await client.get(f"{P}/admin/stats")
    assert r.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Stats + tenant listing
# --------------------------------------------------------------------------- #
async def test_stats_and_tenant_listing(api):
    client, _, maker = api
    admin = await _admin_token(client, maker)
    # Some platform activity across tenants.
    await _register(client, "c@co.com", "company", "AcmeCorp")
    hacker = await _register(client, "h@hx.com", "hacker", "RedTeam")
    hacker_me = (await client.get(f"{P}/auth/me", headers=_auth(hacker))).json()
    async with maker() as s:
        s.add(
            ScanJob(
                tenant_id=uuid.UUID(hacker_me["tenant_id"]),
                user_id=uuid.UUID(hacker_me["id"]),
                target_url="https://example.com/",
                status=ScanStatus.COMPLETED,
                scan_level=3,
            )
        )
        await s.commit()

    stats = await client.get(f"{P}/admin/stats", headers=_auth(admin))
    assert stats.status_code == 200, stats.text
    body = stats.json()
    assert body["tenants"] >= 3  # admin + company + hacker
    assert body["users"] >= 3
    assert body["scans"] >= 1

    tenants = await client.get(f"{P}/admin/tenants", headers=_auth(admin))
    assert tenants.status_code == 200
    red = next(t for t in tenants.json() if t["name"] == "RedTeam")
    assert red["user_count"] == 1 and red["scan_count"] == 1


# --------------------------------------------------------------------------- #
# Plan update + suspension + audit
# --------------------------------------------------------------------------- #
async def test_update_plan_and_suspend_tenant(api):
    client, _, maker = api
    admin = await _admin_token(client, maker)
    company = await _register(client, "c@co.com", "company", "AcmeCorp")
    company_me = (await client.get(f"{P}/auth/me", headers=_auth(company))).json()
    tenant_id = company_me["tenant_id"]

    upd = await client.patch(
        f"{P}/admin/tenants/{tenant_id}",
        headers=_auth(admin),
        json={"plan": PlanType.ENTERPRISE.value, "name": "Acme Renamed"},
    )
    assert upd.status_code == 200, upd.text
    assert upd.json()["plan"] == "enterprise"
    assert upd.json()["name"] == "Acme Renamed"

    susp = await client.delete(f"{P}/admin/tenants/{tenant_id}", headers=_auth(admin))
    assert susp.status_code == 200
    assert susp.json()["deleted_at"] is not None

    # The mutations are in the audit feed.
    audit = await client.get(f"{P}/admin/audit", headers=_auth(admin))
    assert audit.status_code == 200
    actions = {row["action"] for row in audit.json()}
    assert {"admin.tenant_updated", "admin.tenant_suspended"} <= actions


async def test_update_unknown_tenant_404(api):
    client, _, maker = api
    admin = await _admin_token(client, maker)
    r = await client.patch(
        f"{P}/admin/tenants/{uuid.uuid4()}",
        headers=_auth(admin),
        json={"plan": "pro"},
    )
    assert r.status_code == 404


async def test_audit_action_filter(api):
    client, _, maker = api
    admin = await _admin_token(client, maker)
    company = await _register(client, "c@co.com", "company", "AcmeCorp")
    company_me = (await client.get(f"{P}/auth/me", headers=_auth(company))).json()
    await client.delete(f"{P}/admin/tenants/{company_me['tenant_id']}", headers=_auth(admin))

    r = await client.get(
        f"{P}/admin/audit", headers=_auth(admin), params={"action": "admin.tenant_suspended"}
    )
    assert r.status_code == 200
    assert r.json() and all(row["action"] == "admin.tenant_suspended" for row in r.json())
