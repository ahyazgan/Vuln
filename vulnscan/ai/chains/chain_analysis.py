"""Chain-analysis step — combine individual findings into attack paths (§4.5/§5.4).

Pipeline step 5: take the individual (often Low) findings for one target and ask
Claude to identify multi-step attack paths that combine them into a single,
usually higher-severity, chained finding. Per CLAUDE.md §5.4 the prompt must
explicitly list every individual finding with an id; this chain assigns each one
a stable ``F1``, ``F2``… id and validates the model's ``chain_parent_ids`` back
against that set.
"""

from __future__ import annotations

from pydantic import Field

from vulnscan.ai.engine import AnalysisContext, AnalysisEngine
from vulnscan.ai.prompts import CHAIN_ANALYSIS_SYSTEM
from vulnscan.domain.schemas import FindingBase


class ChainedFinding(FindingBase):
    """A finding that combines two or more individual findings (§5.4).

    ``chain_parent_ids`` holds the local ids (``F1``…) of the contributing
    findings, as returned by Claude and filtered to known ids by the chain.
    """

    chain_parent_ids: list[str] = Field(default_factory=list)


class ChainAnalysisChain:
    """Correlate individual findings into multi-step attack paths."""

    category = "chain_analysis"
    system_prompt = CHAIN_ANALYSIS_SYSTEM

    async def analyze(
        self,
        findings: list[FindingBase],
        context: AnalysisContext,
        engine: AnalysisEngine,
    ) -> list[ChainedFinding]:
        """Return chained findings. Needs ≥2 individual findings to be meaningful."""
        if len(findings) < 2:
            return []

        # Assign each individual finding a stable id the model can reference.
        indexed = [
            {"id": f"F{i + 1}", **f.model_dump(mode="json")}
            for i, f in enumerate(findings)
        ]
        known_ids = {item["id"] for item in indexed}

        chained = await engine.analyze(
            system=self.system_prompt,
            evidence_label="Individual findings to correlate (each carries an id)",
            evidence=indexed,
            context=context,
            schema=ChainedFinding,
        )

        # Keep only references to ids we actually supplied, and drop "chains"
        # that reference fewer than two real findings (not a multi-step path).
        result: list[ChainedFinding] = []
        for cf in chained:
            cf.chain_parent_ids = [pid for pid in cf.chain_parent_ids if pid in known_ids]
            if len(cf.chain_parent_ids) >= 2:
                result.append(cf)
        return result


__all__ = ["ChainAnalysisChain", "ChainedFinding"]
