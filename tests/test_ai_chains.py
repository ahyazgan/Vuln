"""Tests for the analysis chains and chain-correlation step."""

import json

from vulnscan.ai.chains import (
    ChainAnalysisChain,
    HeaderAnalysisChain,
    JsSecretAnalysisChain,
    XssAnalysisChain,
)
from vulnscan.ai.engine import AnalysisContext, AnalysisEngine
from vulnscan.ai.prompts import (
    HEADER_ANALYSIS_SYSTEM,
    JS_SECRET_ANALYSIS_SYSTEM,
    XSS_ANALYSIS_SYSTEM,
)
from vulnscan.domain.schemas import FindingBase
from vulnscan.scanners.base import ScanResult


class _RecordingEngine:
    """Engine double that records analyze() kwargs and returns canned findings."""

    def __init__(self, findings=None):
        self.findings = findings or []
        self.calls: list[dict] = []

    async def analyze(self, **kwargs):
        self.calls.append(kwargs)
        return self.findings


def _ctx():
    return AnalysisContext(target_url="https://example.com", tech_stack=["nginx"])


def _finding(title, severity="low", cvss=3.0):
    return FindingBase(
        title=title, severity=severity, cvss_score=cvss, description="d", references=[]
    )


# --------------------------------------------------------------------------- #
# Category chains
# --------------------------------------------------------------------------- #
async def test_header_chain_forwards_evidence_and_prompt():
    engine = _RecordingEngine([_finding("Missing HSTS", "high", 6.5)])
    result = ScanResult(
        scanner="http_headers", target="https://example.com",
        data={"missing": [{"header": "Strict-Transport-Security"}]},
    )
    findings = await HeaderAnalysisChain().analyze(result, _ctx(), engine)

    assert len(findings) == 1
    call = engine.calls[0]
    assert call["system"] == HEADER_ANALYSIS_SYSTEM
    assert call["evidence"] == result.data
    assert "headers" in call["evidence_label"]


async def test_errored_scan_short_circuits_without_calling_engine():
    engine = _RecordingEngine([_finding("should not appear")])
    result = ScanResult(
        scanner="http_headers", target="https://example.com",
        success=False, error=True, error_message="boom",
    )
    findings = await HeaderAnalysisChain().analyze(result, _ctx(), engine)
    assert findings == []
    assert engine.calls == []  # engine never invoked on errored evidence


async def test_js_and_xss_chains_use_their_own_prompts():
    engine = _RecordingEngine()
    js_result = ScanResult(scanner="js_secrets", target="x", data={"matches": []})
    xss_result = ScanResult(scanner="form_fuzzer", target="x", data={"probes": []})

    await JsSecretAnalysisChain().analyze(js_result, _ctx(), engine)
    await XssAnalysisChain().analyze(xss_result, _ctx(), engine)

    assert engine.calls[0]["system"] == JS_SECRET_ANALYSIS_SYSTEM
    assert engine.calls[1]["system"] == XSS_ANALYSIS_SYSTEM
    # XSS chain overrides the evidence label.
    assert "form-fuzzing" in engine.calls[1]["evidence_label"]


# --------------------------------------------------------------------------- #
# Chain analysis (correlation)
# --------------------------------------------------------------------------- #
async def test_chain_analysis_needs_at_least_two_findings(fake_anthropic):
    client = fake_anthropic([])  # should never be called
    engine = AnalysisEngine(client=client)
    out = await ChainAnalysisChain().analyze([_finding("solo")], _ctx(), engine)
    assert out == []
    assert client.messages.calls == []


async def test_chain_analysis_builds_chained_finding(fake_anthropic):
    chained = {
        "severity": "high",
        "title": "Info leak enables injection",
        "description": "F1 leaks the stack which makes F2 exploitable.",
        "cvss_score": 8.1,
        "proof_of_concept": "…",
        "recommendation": "Fix both.",
        "references": [],
        "chain_parent_ids": ["F1", "F2"],
    }
    client = fake_anthropic([json.dumps([chained])])
    engine = AnalysisEngine(client=client)

    findings = [_finding("Verbose server header"), _finding("Reflected param")]
    out = await ChainAnalysisChain().analyze(findings, _ctx(), engine)

    assert len(out) == 1
    assert out[0].chain_parent_ids == ["F1", "F2"]
    # The evidence handed to Claude lists each individual finding with an id (§5.4).
    user = client.messages.calls[0]["messages"][0]["content"]
    assert '"id": "F1"' in user and '"id": "F2"' in user


async def test_chain_analysis_filters_unknown_ids_and_weak_chains(fake_anthropic):
    # References F1 (valid) + F9 (unknown) -> only one real parent -> dropped.
    weak = {
        "severity": "medium", "title": "weak", "description": "d",
        "cvss_score": 5.0, "proof_of_concept": "p", "recommendation": "r",
        "references": [], "chain_parent_ids": ["F1", "F9"],
    }
    client = fake_anthropic([json.dumps([weak])])
    engine = AnalysisEngine(client=client)
    out = await ChainAnalysisChain().analyze(
        [_finding("a"), _finding("b")], _ctx(), engine
    )
    assert out == []  # F9 filtered out, leaving <2 real parents -> not a chain
