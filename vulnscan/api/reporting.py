"""Report assembly + rendering (CLAUDE.md §4.6).

Pure functions that turn a scan job and its persisted findings into an
executive-summary + technical report, plus Markdown / HTML renderers for export.
Kept free of DB/HTTP concerns so it is trivially testable; the route layer reads
the (tenant-scoped, decrypted) findings and hands them here.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from vulnscan.api.schemas import ReportSummary, ScanReport
from vulnscan.domain.enums import Severity
from vulnscan.domain.models import ScanFinding, ScanJob
from vulnscan.domain.schemas import ScanFindingRead

# Weight each severity contributes to the 0–100 risk score (capped at 100).
_RISK_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}


def build_report(job: ScanJob, findings: list[ScanFinding]) -> ScanReport:
    """Assemble the structured report from a scan job and its findings."""
    individuals = [f for f in findings if not f.is_chained]
    chained = [f for f in findings if f.is_chained]

    by_severity = {sev.value: 0 for sev in Severity}
    for f in findings:
        by_severity[f.severity.value] += 1

    max_severity = max((f.severity for f in findings), key=lambda s: s.rank, default=None)
    risk_score = min(100, sum(_RISK_WEIGHT[f.severity] for f in findings))

    summary = ReportSummary(
        scan_id=job.id,
        target_url=job.target_url,
        status=job.status,
        generated_at=datetime.now(UTC),
        total_findings=len(findings),
        by_severity=by_severity,
        max_severity=max_severity,
        risk_score=risk_score,
    )
    # Most severe first within each section.
    key = lambda f: (-f.severity.rank, -f.cvss_score)  # noqa: E731
    return ScanReport(
        summary=summary,
        findings=[ScanFindingRead.model_validate(f) for f in sorted(individuals, key=key)],
        chained_findings=[ScanFindingRead.model_validate(f) for f in sorted(chained, key=key)],
    )


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
def render_markdown(report: ScanReport) -> str:
    s = report.summary
    lines: list[str] = [
        f"# Security Report — {s.target_url}",
        "",
        f"- **Scan ID:** `{s.scan_id}`",
        f"- **Status:** {s.status.value}",
        f"- **Generated:** {s.generated_at.isoformat()}",
        "",
        "## Executive summary",
        "",
        f"- **Risk score:** {s.risk_score}/100",
        f"- **Highest severity:** {s.max_severity.value if s.max_severity else 'none'}",
        f"- **Total findings:** {s.total_findings}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in Severity:
        lines.append(f"| {sev.value} | {s.by_severity.get(sev.value, 0)} |")

    lines += ["", "## Findings", ""]
    sections = [
        ("Individual findings", report.findings),
        ("Attack chains", report.chained_findings),
    ]
    for title, items in sections:
        if not items:
            continue
        lines += [f"### {title}", ""]
        for f in items:
            lines += _md_finding(f)
    if not report.findings and not report.chained_findings:
        lines += ["_No findings reported._", ""]
    return "\n".join(lines).rstrip() + "\n"


def _md_finding(f: ScanFindingRead) -> list[str]:
    out = [
        f"#### [{f.severity.value.upper()}] {f.title}  (CVSS {f.cvss_score:.1f})",
        "",
        f.description,
        "",
    ]
    if f.proof_of_concept:
        out += ["**Proof of concept**", "", "```", f.proof_of_concept, "```", ""]
    if f.recommendation:
        out += ["**Recommendation**", "", f.recommendation, ""]
    if f.references:
        out += ["**References**", ""]
        out += [f"- {ref}" for ref in f.references]
        out += [""]
    return out


def render_html(report: ScanReport) -> str:
    s = report.summary

    def esc(x: object) -> str:
        return html.escape(str(x))

    rows = "".join(
        f"<tr><td>{esc(sev.value)}</td><td>{s.by_severity.get(sev.value, 0)}</td></tr>"
        for sev in Severity
    )
    body = [
        f"<h1>Security Report — {esc(s.target_url)}</h1>",
        f"<p><strong>Scan:</strong> <code>{esc(s.scan_id)}</code> · "
        f"<strong>Status:</strong> {esc(s.status.value)} · "
        f"<strong>Generated:</strong> {esc(s.generated_at.isoformat())}</p>",
        "<h2>Executive summary</h2>",
        f"<p>Risk score <strong>{s.risk_score}/100</strong> · "
        f"highest severity <strong>{esc(s.max_severity.value if s.max_severity else 'none')}</strong> · "
        f"{s.total_findings} finding(s)</p>",
        f"<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>",
        "<h2>Findings</h2>",
    ]
    all_items = [
        ("Individual findings", report.findings),
        ("Attack chains", report.chained_findings),
    ]
    has_any = False
    for title, items in all_items:
        if not items:
            continue
        has_any = True
        body.append(f"<h3>{esc(title)}</h3>")
        for f in items:
            body.append(_html_finding(f, esc))
    if not has_any:
        body.append("<p><em>No findings reported.</em></p>")

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>Security Report — {esc(s.target_url)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:880px;margin:2rem auto;"
        "padding:0 1rem;color:#1a1a1a}code,pre{font-family:ui-monospace,monospace}"
        "pre{background:#f4f4f6;padding:.75rem;border-radius:6px;overflow-x:auto}"
        "table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:.3rem .6rem}"
        "</style></head><body>" + "".join(body) + "</body></html>"
    )


def _html_finding(f: ScanFindingRead, esc) -> str:
    parts = [
        f"<h4>[{esc(f.severity.value.upper())}] {esc(f.title)} (CVSS {f.cvss_score:.1f})</h4>",
        f"<p>{esc(f.description)}</p>",
    ]
    if f.proof_of_concept:
        parts.append(
            f"<p><strong>Proof of concept</strong></p><pre>{esc(f.proof_of_concept)}</pre>"
        )
    if f.recommendation:
        parts.append(f"<p><strong>Recommendation</strong></p><p>{esc(f.recommendation)}</p>")
    if f.references:
        items = "".join(f"<li>{esc(r)}</li>" for r in f.references)
        parts.append(f"<p><strong>References</strong></p><ul>{items}</ul>")
    return "".join(parts)


__all__ = ["build_report", "render_markdown", "render_html"]
