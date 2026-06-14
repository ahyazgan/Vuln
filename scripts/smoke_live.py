"""Live end-to-end smoke test of the real API wiring against a SQLite DB.

Exercises the PRODUCTION app (create_app, real get_db/SessionLocal/engine, real
JWT auth, real scope gate, real audit writes) over an ASGI client. Only the
external Celery enqueuer is stubbed (no Redis needed); the AI engine isn't hit
because the scan is only *queued*, not run.

Run:  .\.venv\Scripts\python.exe scripts\smoke_live.py
"""

import asyncio
import os
import pathlib

# Point the real engine at a local SQLite file BEFORE importing vulnscan.db.
_DB_FILE = pathlib.Path("./.smoke.db")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_DB_FILE.as_posix()}"

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from vulnscan.api.app import API_PREFIX as P  # noqa: E402
from vulnscan.api.app import create_app  # noqa: E402
from vulnscan.api.deps import get_enqueuer  # noqa: E402
from vulnscan.db import SessionLocal, dispose_engine, init_models  # noqa: E402
from vulnscan.domain.models import AuditLog  # noqa: E402

OK, FAIL = "PASS", "FAIL"


def check(label: str, cond: bool) -> None:
    print(f"  [{OK if cond else FAIL}] {label}")
    assert cond, label


async def main() -> None:
    if _DB_FILE.exists():
        _DB_FILE.unlink()
    await init_models()  # create all tables in the SQLite file

    app = create_app()
    enqueued: list[dict] = []
    app.dependency_overrides[get_enqueuer] = lambda: (
        lambda payload: enqueued.append(payload) or "task-live"
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://live") as c:
        print("\n== health ==")
        r = await c.get("/health")
        check(f"GET /health -> {r.status_code} {r.json()}", r.status_code == 200)

        print("\n== company registers + creates a program ==")
        comp = (
            await c.post(
                f"{P}/auth/register",
                json={
                    "email": "sec@company.com",
                    "password": "password123",
                    "role": "company",
                    "tenant_name": "AcmeCorp",
                },
            )
        ).json()
        ch = {"Authorization": f"Bearer {comp['access_token']}"}
        prog = await c.post(
            f"{P}/programs",
            headers=ch,
            json={
                "name": "Acme Web",
                "scope_domains": ["example.com", "*.example.com"],
                "reward_table": {"critical": 5000, "high": 1500},
            },
        )
        check(f"POST /programs -> {prog.status_code}", prog.status_code == 201)
        program_id = prog.json()["id"]
        print(f"      program_id = {program_id}  scope = {prog.json()['scope_domains']}")

        print("\n== hacker registers ==")
        hack = (
            await c.post(
                f"{P}/auth/register",
                json={
                    "email": "h4x@research.com",
                    "password": "password123",
                    "role": "hacker",
                    "tenant_name": "RedTeam",
                },
            )
        ).json()
        hh = {"Authorization": f"Bearer {hack['access_token']}"}
        me = (await c.get(f"{P}/auth/me", headers=hh)).json()
        check(f"GET /auth/me -> {me['email']} ({me['role']})", me["role"] == "hacker")

        print("\n== in-scope scan is accepted and queued (async, §2.1) ==")
        s1 = await c.post(
            f"{P}/scans",
            headers=hh,
            json={
                "target_url": "https://api.example.com/login",
                "program_id": program_id,
                "scan_level": 6,
            },
        )
        check(f"POST /scans (in scope) -> {s1.status_code}", s1.status_code == 202)
        print(f"      scan_id = {s1.json()['scan_id']}  status = {s1.json()['status']}")
        check("scan handed to worker queue", len(enqueued) == 1)
        check(
            f"queued scope = {enqueued[0]['scope_domains']}",
            enqueued[0]["scope_domains"] == ["example.com", "*.example.com"],
        )

        print("\n== out-of-scope scan is refused before queueing (§7.2) ==")
        s2 = await c.post(
            f"{P}/scans",
            headers=hh,
            json={"target_url": "https://evil.com/", "program_id": program_id},
        )
        check(f"POST /scans (evil.com) -> {s2.status_code}", s2.status_code == 422)
        check("out-of-scope scan NOT queued", len(enqueued) == 1)

        print("\n== tenant isolation + listing ==")
        scans = await c.get(f"{P}/scans", headers=hh)
        check(f"GET /scans -> {len(scans.json())} own scan(s)", len(scans.json()) == 1)
        # Company cannot read the hacker's scans (different tenant + role).
        forbidden = await c.get(f"{P}/scans", headers=ch)
        check(
            f"company GET /scans -> {forbidden.status_code} (role forbidden)",
            forbidden.status_code == 403,
        )

    print("\n== audit trail persisted to DB (§7.5) ==")
    async with SessionLocal() as session:
        count = (await session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
        rows = (await session.execute(select(AuditLog.action, AuditLog.target))).all()
    check(f"audit_logs rows = {count}", count == 1)
    for action, target in rows:
        print(f"      audit: {action} -> {target}")

    await dispose_engine()
    if _DB_FILE.exists():
        _DB_FILE.unlink()
    print("\nALL LIVE CHECKS PASSED\n")


if __name__ == "__main__":
    asyncio.run(main())
