"""Live verification of the FULL level-6 pipeline against real Postgres + Redis.

Where ``smoke_live.py`` exercises the API/auth/scope wiring over SQLite (and only
*queues* a scan), this harness runs the worker's analysis pipeline end to end:

    recon -> surface -> active testing -> Claude analysis -> chain analysis
    -> report  ==>  findings + chained findings persisted to PostgreSQL

It is the integration the unit tests can't cover: persisting AI-produced findings
(and resolving ``chain_parent_ids`` from the local ``F1``/``F2`` ids to real DB
UUIDs) against a *real* PostgreSQL, plus the six pipeline steps landing in a real
Redis state hash.

No Anthropic API key is needed: a fake Claude client with canned JSON is injected
into the engine (exactly as the test-suite does), so this validates the wiring and
persistence, not the model.

Prereqs (see the README "Live verification" section): a reachable PostgreSQL with
the schema migrated (``alembic upgrade head``), a Redis, and an in-scope target.

Run::

    DATABASE_URL=postgresql+asyncpg://vulnscan:vulnscan@127.0.0.1:5432/vulnscan \\
    REDIS_URL=redis://localhost:6379/0 \\
    TARGET_URL=http://127.0.0.1:8099/ \\
    python scripts/live_pipeline.py
"""

from __future__ import annotations

import asyncio
import os
import uuid
from types import SimpleNamespace

from sqlalchemy import select

from vulnscan.ai.engine import AnalysisEngine
from vulnscan.db import WorkerSessionLocal, worker_engine
from vulnscan.domain.enums import ScanStatus, UserRole
from vulnscan.domain.models import BountyProgram, ScanFinding, ScanJob, Tenant, User
from vulnscan.workers.persistence import persist_scan_result
from vulnscan.workers.pipeline import ScannerFactory, ScanPipeline, ScanRequest
from vulnscan.workers.state import RedisScanStateStore

TARGET_URL = os.getenv("TARGET_URL", "http://127.0.0.1:8099/")

OK, FAIL = "PASS", "FAIL"


def check(label: str, cond: bool) -> None:
    print(f"  [{OK if cond else FAIL}] {label}")
    assert cond, label


# Canned Claude responses, replayed in pipeline order: header, js, xss, chain.
_HEADER = """[{"severity":"medium","title":"Missing security headers",
"description":"No Content-Security-Policy or HSTS present.","cvss_score":5.3,
"proof_of_concept":"curl -I shows no CSP/HSTS","recommendation":"Add CSP + HSTS.",
"references":["https://owasp.org/www-project-secure-headers/"]}]"""

_JS = """[{"severity":"high","title":"Hardcoded API key in app.js",
"description":"An AWS-style access key is embedded in client JavaScript.",
"cvss_score":7.5,"proof_of_concept":"AKIA... found in /static/app.js",
"recommendation":"Rotate the key and remove it from client code.",
"references":["https://cwe.mitre.org/data/definitions/798.html"]}]"""

_XSS = """[{"severity":"medium","title":"Reflected input on login form",
"description":"The username field is reflected without encoding.","cvss_score":6.1,
"proof_of_concept":"username=<script>alert(1)</script>","recommendation":"Encode output.",
"references":[]}]"""

_CHAIN = """[{"severity":"high","title":"Credential theft: reflected XSS + leaked key",
"description":"Chain the reflected XSS with the exposed API key to exfiltrate data.",
"cvss_score":8.8,"proof_of_concept":"Inject XSS to steal session; pivot with the API key.",
"recommendation":"Remediate both the XSS and the exposed key.","references":[],
"chain_parent_ids":["F2","F3"]}]"""


class _FakeAnthropic:
    """Replays canned text responses in order; mimics ``client.messages.create``."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []
        self.messages = self

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        text = self._responses.pop(0) if self._responses else "[]"
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


async def _seed(session) -> ScanRequest:
    """Insert tenant + user + program + queued scan job; return the ScanRequest."""
    tenant = Tenant(name=f"LivePipeline-{uuid.uuid4().hex[:8]}")
    session.add(tenant)
    await session.flush()
    user = User(
        tenant_id=tenant.id,
        email=f"hk-{uuid.uuid4().hex[:6]}@live.test",
        hashed_password="x",
        role=UserRole.HACKER,
    )
    program = BountyProgram(tenant_id=tenant.id, name="Live", scope_domains=["127.0.0.1"])
    session.add_all([user, program])
    await session.flush()
    job = ScanJob(
        tenant_id=tenant.id,
        user_id=user.id,
        program_id=program.id,
        target_url=TARGET_URL,
        scan_level=6,
        status=ScanStatus.QUEUED,
    )
    session.add(job)
    await session.commit()
    return ScanRequest(
        scan_id=str(job.id),
        tenant_id=str(tenant.id),
        target_url=TARGET_URL,
        scope_domains=["127.0.0.1"],
        scan_level=6,
    )


async def main() -> None:
    print(f"\n== seed tenant/user/program/scan in Postgres (target {TARGET_URL}) ==")
    async with WorkerSessionLocal() as session:
        request = await _seed(session)
    print(f"      scan_id = {request.scan_id}")

    print("\n== run the full level-6 pipeline (real scanners + Redis, fake Claude) ==")
    fake = _FakeAnthropic([_HEADER, _JS, _XSS, _CHAIN])
    engine = AnalysisEngine(client=fake)
    factory = ScannerFactory(request.scope_domains, scan_id=request.scan_id)
    state = RedisScanStateStore()
    try:
        result = await ScanPipeline().run(
            request, scanner_factory=factory, engine=engine, state=state
        )
    finally:
        await factory.aclose()

    check(f"pipeline reached step 6 (got {result.completed_step})", result.completed_step == 6)
    check(f"{len(result.findings)} individual findings (expected 3)", len(result.findings) == 3)
    check(
        f"{len(result.chained_findings)} attack chain(s) (expected 1)",
        len(result.chained_findings) == 1,
    )
    check(
        f"report max_severity = {result.report['max_severity']} (expected high)",
        result.report["max_severity"] == "high",
    )

    print("\n== persist findings to Postgres + verify read-back ==")
    async with WorkerSessionLocal() as session:
        summary = await persist_scan_result(session, request, result)
    check(
        f"persist summary: {summary['findings_persisted']} rows (expected 4)",
        summary["findings_persisted"] == 4,
    )

    async with WorkerSessionLocal() as session:
        rows = (
            (
                await session.execute(
                    select(ScanFinding).where(ScanFinding.scan_job_id == uuid.UUID(request.scan_id))
                )
            )
            .scalars()
            .all()
        )
        job = await session.get(ScanJob, uuid.UUID(request.scan_id))

    individuals = [r for r in rows if not r.is_chained]
    chained = [r for r in rows if r.is_chained]
    check(
        f"DB has 3 individual + 1 chained (got {len(individuals)}+{len(chained)})",
        len(individuals) == 3 and len(chained) == 1,
    )

    # chain_parent_ids must be resolved to REAL uuids of two persisted findings.
    parents = chained[0].chain_parent_ids
    individual_ids = {str(r.id) for r in individuals}
    check(
        f"chained finding references 2 real finding UUIDs {parents}",
        len(parents) == 2 and all(p in individual_ids for p in parents),
    )
    check(
        f"scan job marked {job.status.value} (expected completed)",
        job.status == ScanStatus.COMPLETED,
    )

    print("\n== verify all six steps landed in the Redis state hash ==")
    steps = set(await state.all(request.scan_id))
    await state.aclose()
    expected = {
        "recon",
        "surface",
        "active_http",
        "active_js",
        "active_fuzz",
        "findings",
        "chained_findings",
        "report",
    }
    check(f"redis state steps = {sorted(steps)}", expected.issubset(steps))

    await worker_engine.dispose()
    print("\nALL LIVE PIPELINE CHECKS PASSED\n")


if __name__ == "__main__":
    asyncio.run(main())
