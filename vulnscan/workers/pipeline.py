"""The scan pipeline — the ordered six-step chain of CLAUDE.md §4.

``ScanPipeline.run`` executes, in order and gated by ``scan_level`` (1–6):

1. **Recon** — load the target, map its surface (links, forms, scripts, tech).
2. **Surface mapping** — prioritize risky endpoints/forms for active testing.
3. **Active testing** — security headers, JS secrets, form fuzzing (XSS/SQLi).
4. **Claude analysis** — per-category chains turn raw evidence into findings.
5. **Chain analysis** — combine individual findings into attack paths.
6. **Report generation** — assemble a CVSS-scored, severity-bucketed report.

Each step persists its intermediate output to the state store keyed by
``scan_id``. The pipeline is pure orchestration over injected dependencies
(scanner factory, AI engine, state store) so it runs fully offline in tests;
the network, Redis, Celery, and DB wiring live in ``workers.app`` /
``workers.persistence``.

Scanners are reached only through :class:`ScannerFactory`, which shares one
scope-checked HTTP client across the run (scope enforcement, CLAUDE.md §7.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from vulnscan.ai.chains import (
    ChainAnalysisChain,
    ChainedFinding,
    HeaderAnalysisChain,
    JsSecretAnalysisChain,
    XssAnalysisChain,
)
from vulnscan.ai.engine import AnalysisContext, AnalysisEngine
from vulnscan.domain.enums import Severity
from vulnscan.domain.schemas import FindingBase
from vulnscan.scanners.base import DEFAULT_TIMEOUT, ScanResult, ScopeValidator
from vulnscan.scanners.form_fuzzer import FormFuzzerScanner
from vulnscan.scanners.http import HttpHeaderScanner
from vulnscan.scanners.js import JsSecretScanner
from vulnscan.scanners.recon import ReconScanner

# Endpoint/form substrings that flag a higher-value active-testing target (§4.2).
_RISKY_KEYWORDS = (
    "admin",
    "login",
    "signin",
    "sign-in",
    "auth",
    "upload",
    "account",
    "password",
    "passwd",
    "config",
    "setup",
    "dashboard",
    "checkout",
    "payment",
)


# --------------------------------------------------------------------------- #
# Request / result
# --------------------------------------------------------------------------- #
@dataclass
class ScanRequest:
    """The inputs a worker needs to run one scan."""

    scan_id: str
    tenant_id: str
    target_url: str
    scope_domains: list[str]
    scan_level: int = 6
    # Compact dicts of prior findings for this target, fed to Claude (§2.2).
    previous_findings: list[dict] = field(default_factory=list)


@dataclass
class PipelineResult:
    scan_id: str
    target_url: str
    scan_level: int
    completed_step: int
    tech_stack: list[str]
    findings: list[FindingBase]
    chained_findings: list[ChainedFinding]
    report: dict | None
    step_summaries: list[dict]


# --------------------------------------------------------------------------- #
# Scanner factory (shared scope-checked client)
# --------------------------------------------------------------------------- #
class ScannerFactory:
    """Builds scanners bound to one scope and one shared HTTP client.

    Tests substitute a fake factory exposing the same ``recon`` / ``http_headers``
    / ``js_secrets`` / ``form_fuzzer`` methods.
    """

    def __init__(
        self,
        scope: ScopeValidator | list[str],
        *,
        scan_id: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.scope = scope if isinstance(scope, ScopeValidator) else ScopeValidator(scope)
        self.scan_id = scan_id
        self._client = client
        self._owns_client = client is None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=DEFAULT_TIMEOUT,
                headers={"User-Agent": "VulnScanAI/0.1 (+authorized-scan)"},
            )
        return self._client

    def recon(self, target: str) -> ReconScanner:
        return ReconScanner(target, self.scope, client=self._http(), scan_id=self.scan_id)

    def http_headers(self, target: str) -> HttpHeaderScanner:
        return HttpHeaderScanner(target, self.scope, client=self._http(), scan_id=self.scan_id)

    def js_secrets(self, target: str, script_urls: list[str]) -> JsSecretScanner:
        return JsSecretScanner(
            target,
            self.scope,
            client=self._http(),
            scan_id=self.scan_id,
            script_urls=script_urls,
        )

    def form_fuzzer(self, target: str, forms: list[dict]) -> FormFuzzerScanner:
        return FormFuzzerScanner(
            target, self.scope, client=self._http(), scan_id=self.scan_id, forms=forms
        )

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
class ScanPipeline:
    """Runs the ordered scan chain over injected dependencies."""

    def __init__(
        self,
        *,
        header_chain: HeaderAnalysisChain | None = None,
        js_chain: JsSecretAnalysisChain | None = None,
        xss_chain: XssAnalysisChain | None = None,
        chain_analysis: ChainAnalysisChain | None = None,
    ) -> None:
        self.header_chain = header_chain or HeaderAnalysisChain()
        self.js_chain = js_chain or JsSecretAnalysisChain()
        self.xss_chain = xss_chain or XssAnalysisChain()
        self.chain_analysis = chain_analysis or ChainAnalysisChain()

    async def run(
        self,
        request: ScanRequest,
        *,
        scanner_factory: Any,
        engine: AnalysisEngine,
        state: Any,
    ) -> PipelineResult:
        level = request.scan_level
        sid = request.scan_id
        target = request.target_url
        summaries: list[dict] = []
        findings: list[FindingBase] = []
        chained: list[ChainedFinding] = []

        # --- Step 1: Recon -------------------------------------------------- #
        recon = await scanner_factory.recon(target).safe_run()
        await state.set(sid, "recon", recon.model_dump(mode="json"))
        tech = recon.data.get("tech_stack", []) if not recon.error else []
        summaries.append(_summary(1, "recon", recon))
        completed = 1

        context = AnalysisContext(
            target_url=target, tech_stack=tech, previous_findings=request.previous_findings
        )

        # --- Step 2: Surface mapping --------------------------------------- #
        surface: dict = {}
        if level >= 2:
            surface = _map_surface(recon.data)
            await state.set(sid, "surface", surface)
            summaries.append(
                {
                    "step": 2,
                    "name": "surface_mapping",
                    "status": "ok",
                    "result_summary": (
                        f"{len(surface['priority_forms'])} forms prioritized, "
                        f"{len(surface['risky_endpoints'])} risky endpoints"
                    ),
                }
            )
            completed = 2

        # --- Step 3: Active testing ---------------------------------------- #
        http_res = js_res = fuzz_res = None
        if level >= 3:
            http_res = await scanner_factory.http_headers(target).safe_run()
            scripts = recon.data.get("scripts", [])
            js_res = await scanner_factory.js_secrets(target, scripts).safe_run()
            forms = surface.get("priority_forms") or recon.data.get("forms", [])
            fuzz_res = await scanner_factory.form_fuzzer(target, forms).safe_run()
            for label, res in (("http", http_res), ("js", js_res), ("fuzz", fuzz_res)):
                await state.set(sid, f"active_{label}", res.model_dump(mode="json"))
            summaries.append(_summary(3, "active_testing", http_res, js_res, fuzz_res))
            completed = 3

        # --- Step 4: Claude analysis --------------------------------------- #
        if level >= 4:
            findings += await self.header_chain.analyze(http_res, context, engine)
            findings += await self.js_chain.analyze(js_res, context, engine)
            findings += await self.xss_chain.analyze(fuzz_res, context, engine)
            await state.set(sid, "findings", [f.model_dump(mode="json") for f in findings])
            summaries.append(
                {
                    "step": 4,
                    "name": "claude_analysis",
                    "status": "ok",
                    "result_summary": f"{len(findings)} individual findings",
                }
            )
            completed = 4

        # --- Step 5: Chain analysis ---------------------------------------- #
        if level >= 5:
            chained = await self.chain_analysis.analyze(findings, context, engine)
            await state.set(sid, "chained_findings", [c.model_dump(mode="json") for c in chained])
            summaries.append(
                {
                    "step": 5,
                    "name": "chain_analysis",
                    "status": "ok",
                    "result_summary": f"{len(chained)} attack chains",
                }
            )
            completed = 5

        # --- Step 6: Report generation ------------------------------------- #
        report = None
        if level >= 6:
            report = _build_report(request, findings, chained)
            await state.set(sid, "report", report)
            summaries.append(
                {
                    "step": 6,
                    "name": "report",
                    "status": "ok",
                    "result_summary": f"max_severity={report['max_severity']}",
                }
            )
            completed = 6

        return PipelineResult(
            scan_id=sid,
            target_url=target,
            scan_level=level,
            completed_step=completed,
            tech_stack=tech,
            findings=findings,
            chained_findings=chained,
            report=report,
            step_summaries=summaries,
        )


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
def _summary(step: int, name: str, *results: ScanResult) -> dict:
    status = "ok" if all(not r.error for r in results) else "partial"
    return {
        "step": step,
        "name": name,
        "status": status,
        "result_summary": "; ".join(r.summary() for r in results),
    }


def _map_surface(recon_data: dict) -> dict:
    """Prioritize risky forms/endpoints for active testing (CLAUDE.md §4.2)."""
    forms = recon_data.get("forms", [])
    internal = recon_data.get("links", {}).get("internal", [])

    def is_risky_form(form: dict) -> bool:
        if any(i.get("type", "").lower() == "password" for i in form.get("inputs", [])):
            return True
        action = (form.get("action") or "").lower()
        return any(k in action for k in _RISKY_KEYWORDS)

    # Risky forms first, but every form is still in scope for fuzzing.
    priority_forms = sorted(forms, key=lambda f: 0 if is_risky_form(f) else 1)
    risky_endpoints = [u for u in internal if any(k in u.lower() for k in _RISKY_KEYWORDS)]
    return {
        "priority_forms": priority_forms,
        "risky_endpoints": risky_endpoints,
        "form_count": len(forms),
    }


def _build_report(
    request: ScanRequest,
    findings: list[FindingBase],
    chained: list[ChainedFinding],
) -> dict:
    """Assemble the final CVSS-scored, severity-bucketed report (CLAUDE.md §4.6)."""
    all_findings = list(findings) + list(chained)
    by_severity = {sev.value: 0 for sev in Severity}
    for f in all_findings:
        by_severity[f.severity.value] += 1
    max_severity = max((f.severity for f in all_findings), key=lambda s: s.rank, default=None)
    return {
        "scan_id": request.scan_id,
        "target_url": request.target_url,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "max_severity": max_severity.value if max_severity else None,
        "findings": [f.model_dump(mode="json") for f in findings],
        "chained_findings": [f.model_dump(mode="json") for f in chained],
    }


__all__ = [
    "ScanRequest",
    "PipelineResult",
    "ScannerFactory",
    "ScanPipeline",
]
