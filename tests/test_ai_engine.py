"""Tests for the AI analysis engine: context, parsing, repair, drop, validation."""

import json

from vulnscan.ai.engine import AnalysisContext, AnalysisEngine
from vulnscan.ai.prompts import BASE_SYSTEM_PROMPT
from vulnscan.domain.enums import Severity
from vulnscan.domain.schemas import FindingBase

_FINDING = {
    "severity": "high",
    "title": "Missing HSTS",
    "description": "No Strict-Transport-Security header.",
    "cvss_score": 6.5,
    "proof_of_concept": "curl -I https://example.com",
    "recommendation": "Add HSTS.",
    "references": ["https://owasp.org/hsts"],
}


def _ctx() -> AnalysisContext:
    return AnalysisContext(
        target_url="https://example.com",
        tech_stack=["nginx", "PHP"],
        previous_findings=[{"title": "Old finding", "severity": "low"}],
    )


async def test_parses_findings_from_clean_json(fake_anthropic):
    engine = AnalysisEngine(client=fake_anthropic([json.dumps([_FINDING])]))
    findings = await engine.analyze(
        system="focus",
        evidence_label="Raw headers",
        evidence={"missing": ["hsts"]},
        context=_ctx(),
    )
    assert len(findings) == 1
    assert isinstance(findings[0], FindingBase)
    assert findings[0].severity is Severity.HIGH
    assert findings[0].cvss_score == 6.5


async def test_strips_markdown_fences_and_prose(fake_anthropic):
    fenced = "Here are the findings:\n```json\n" + json.dumps([_FINDING]) + "\n```"
    engine = AnalysisEngine(client=fake_anthropic([fenced]))
    findings = await engine.analyze(
        system="focus", evidence_label="Raw headers", evidence={}, context=_ctx()
    )
    assert len(findings) == 1


async def test_empty_array_returns_no_findings(fake_anthropic):
    engine = AnalysisEngine(client=fake_anthropic(["[]"]))
    findings = await engine.analyze(
        system="focus", evidence_label="Raw headers", evidence={}, context=_ctx()
    )
    assert findings == []


async def test_malformed_json_triggers_repair_then_succeeds(fake_anthropic):
    client = fake_anthropic(["not json at all", json.dumps([_FINDING])])
    engine = AnalysisEngine(client=client)
    findings = await engine.analyze(
        system="focus", evidence_label="Raw headers", evidence={}, context=_ctx()
    )
    assert len(findings) == 1
    # Exactly two calls: original + one repair attempt.
    assert len(client.messages.calls) == 2


async def test_unrecoverable_json_is_dropped(fake_anthropic):
    client = fake_anthropic(["garbage", "still garbage"])
    engine = AnalysisEngine(client=client)
    findings = await engine.analyze(
        system="focus", evidence_label="Raw headers", evidence={}, context=_ctx()
    )
    assert findings == []  # dropped rather than shipped
    assert len(client.messages.calls) == 2  # original + one repair, then give up


async def test_invalid_finding_item_skipped_valid_kept(fake_anthropic):
    bad = {**_FINDING, "severity": "extreme"}  # not a valid Severity
    worse = {**_FINDING, "cvss_score": 99}  # out of 0..10 range
    engine = AnalysisEngine(client=fake_anthropic([json.dumps([_FINDING, bad, worse])]))
    findings = await engine.analyze(
        system="focus", evidence_label="Raw headers", evidence={}, context=_ctx()
    )
    assert len(findings) == 1  # only the valid one survives


async def test_call_includes_mandatory_context_and_cached_base_prompt(fake_anthropic):
    client = fake_anthropic([json.dumps([_FINDING])])
    engine = AnalysisEngine(client=client)
    await engine.analyze(
        system="HEADER FOCUS",
        evidence_label="Raw headers scan output",
        evidence={"missing": ["hsts"]},
        context=_ctx(),
    )
    call = client.messages.calls[0]

    # System: cached base prompt first, then the category focus prompt (§5.5).
    system = call["system"]
    assert system[0]["text"] == BASE_SYSTEM_PROMPT
    assert system[0]["cache_control"] == {"type": "ephemeral"}
    assert system[1]["text"] == "HEADER FOCUS"

    # User message carries the §2.2 mandatory context + raw evidence.
    user = call["messages"][0]["content"]
    assert "Target URL: https://example.com" in user
    assert "nginx, PHP" in user  # tech stack
    assert "Old finding" in user  # previous findings
    assert "Raw headers scan output" in user
    assert "hsts" in user  # raw evidence echoed

    # Model id is the constitution-pinned analysis model (§5.6).
    assert call["model"] == engine.model
