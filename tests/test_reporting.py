"""Tests for report assembly, rendering, and the report endpoints (§4.6)."""

import uuid
from datetime import UTC, datetime

from vulnscan.api.app import API_PREFIX as P
from vulnscan.api.reporting import render_html, render_markdown
from vulnscan.api.schemas import ReportSummary, ScanReport
from vulnscan.domain.enums import ScanStatus, Severity
from vulnscan.domain.models import ScanFinding, ScanJob
from vulnscan.domain.schemas import ScanFindingRead


# --------------------------------------------------------------------------- #
# Renderers (pure)
# --------------------------------------------------------------------------- #
def _finding(**over) -> ScanFindingRead:
    base = dict(
        id=uuid.uuid4(),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        tenant_id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        title="Reflected XSS",
        severity=Severity.HIGH,
        cvss_score=7.4,
        description="User input reflected without encoding.",
        proof_of_concept="?q=<script>alert(1)</script>",
        recommendation="Encode output.",
        references=["https://owasp.org/xss"],
        is_chained=False,
        chain_parent_ids=[],
    )
    base.update(over)
    return ScanFindingRead(**base)


def _report() -> ScanReport:
    summary = ReportSummary(
        scan_id=uuid.uuid4(),
        target_url="https://example.com/",
        status=ScanStatus.COMPLETED,
        generated_at=datetime.now(UTC),
        total_findings=2,
        by_severity={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
        max_severity=Severity.HIGH,
        risk_score=28,
    )
    return ScanReport(
        summary=summary,
        findings=[_finding(), _finding(severity=Severity.MEDIUM, title="Missing CSP")],
        chained_findings=[],
    )


def test_render_markdown_contains_summary_and_findings():
    md = render_markdown(_report())
    assert "# Security Report — https://example.com/" in md
    assert "Risk score:** 28/100" in md
    assert "Reflected XSS" in md and "Missing CSP" in md
    assert "?q=<script>alert(1)</script>" in md  # PoC verbatim in a code block


def test_render_html_escapes_content():
    html = render_html(_report())
    assert "<h1>" in html and "Security Report" in html
    # The PoC payload must be HTML-escaped, not live markup.
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_markdown_handles_no_findings():
    summary = ReportSummary(
        scan_id=uuid.uuid4(),
        target_url="https://x/",
        status=ScanStatus.COMPLETED,
        generated_at=datetime.now(UTC),
        total_findings=0,
        by_severity={s.value: 0 for s in Severity},
        max_severity=None,
        risk_score=0,
    )
    md = render_markdown(ScanReport(summary=summary, findings=[], chained_findings=[]))
    assert "No findings reported." in md


# --------------------------------------------------------------------------- #
# Endpoints
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


async def _seed_scan_with_findings(maker, tenant_id, user_id) -> uuid.UUID:
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
        s.add_all(
            [
                ScanFinding(
                    tenant_id=tenant_id,
                    scan_job_id=job.id,
                    title="SQLi",
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    description="Injection.",
                    proof_of_concept="' OR 1=1",
                    recommendation="Parameterize.",
                    references=["https://cwe.mitre.org/89"],
                ),
                ScanFinding(
                    tenant_id=tenant_id,
                    scan_job_id=job.id,
                    title="Missing HSTS",
                    severity=Severity.LOW,
                    cvss_score=2.0,
                    description="No HSTS header.",
                ),
                ScanFinding(
                    tenant_id=tenant_id,
                    scan_job_id=job.id,
                    title="Account takeover chain",
                    severity=Severity.HIGH,
                    cvss_score=8.3,
                    description="Combine the above.",
                    is_chained=True,
                    chain_parent_ids=[str(uuid.uuid4())],
                ),
            ]
        )
        await s.commit()
        return job.id


async def test_report_json_endpoint(api):
    client, _, maker = api
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")
    me = (await client.get(f"{P}/auth/me", headers=_auth(hacker))).json()
    scan_id = await _seed_scan_with_findings(maker, uuid.UUID(me["tenant_id"]), uuid.UUID(me["id"]))

    r = await client.get(f"{P}/scans/{scan_id}/report", headers=_auth(hacker))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["total_findings"] == 3
    assert body["summary"]["max_severity"] == "critical"
    assert body["summary"]["by_severity"]["critical"] == 1
    assert body["summary"]["risk_score"] > 0
    assert len(body["findings"]) == 2  # individuals
    assert len(body["chained_findings"]) == 1
    # Most severe individual first.
    assert body["findings"][0]["severity"] == "critical"


async def test_report_markdown_and_html_downloads(api):
    client, _, maker = api
    hacker = await _register(client, "h@hx.com", "hacker", "HackerOrg")
    me = (await client.get(f"{P}/auth/me", headers=_auth(hacker))).json()
    scan_id = await _seed_scan_with_findings(maker, uuid.UUID(me["tenant_id"]), uuid.UUID(me["id"]))

    md = await client.get(f"{P}/scans/{scan_id}/report.md", headers=_auth(hacker))
    assert md.status_code == 200
    assert md.headers["content-type"].startswith("text/markdown")
    assert "attachment" in md.headers["content-disposition"]
    assert "# Security Report" in md.text

    htm = await client.get(f"{P}/scans/{scan_id}/report.html", headers=_auth(hacker))
    assert htm.status_code == 200
    assert htm.headers["content-type"].startswith("text/html")
    assert "<h1>" in htm.text


async def test_report_tenant_isolation(api):
    client, _, maker = api
    owner = await _register(client, "owner@hx.com", "hacker", "OwnerOrg")
    me = (await client.get(f"{P}/auth/me", headers=_auth(owner))).json()
    scan_id = await _seed_scan_with_findings(maker, uuid.UUID(me["tenant_id"]), uuid.UUID(me["id"]))

    other = await _register(client, "other@hx.com", "hacker", "OtherOrg")
    r = await client.get(f"{P}/scans/{scan_id}/report", headers=_auth(other))
    assert r.status_code == 404  # not the owner's tenant (§2.6)
