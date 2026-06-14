"""Base class for per-category analysis chains (CLAUDE.md §3 / §4.4).

A chain maps one scanner's raw :class:`~vulnscan.scanners.base.ScanResult` to a
list of validated findings by calling the shared :class:`AnalysisEngine`. Chains
hold only a category label and a focus system prompt — all Claude access goes
through the engine (CLAUDE.md §6); no chain imports ``anthropic``.
"""

from __future__ import annotations

from abc import ABC
from typing import Any

from vulnscan.ai.engine import AnalysisContext, AnalysisEngine
from vulnscan.domain.schemas import FindingBase
from vulnscan.scanners.base import ScanResult


class BaseChain(ABC):  # noqa: B024 - marker base; subclasses override hooks/attrs, not methods
    """One analysis chain == one finding category (CLAUDE.md §4.4)."""

    #: Short category id, used in the evidence label and logs.
    category: str = "base"
    #: Per-category focus prompt constant from ``ai.prompts`` (never inlined).
    system_prompt: str = ""

    def build_evidence(self, scan_result: ScanResult) -> Any:
        """Extract the raw evidence to hand Claude. Default: the scanner data."""
        return scan_result.data

    @property
    def evidence_label(self) -> str:
        return f"Raw {self.category} scan output"

    async def analyze(
        self,
        scan_result: ScanResult,
        context: AnalysisContext,
        engine: AnalysisEngine,
    ) -> list[FindingBase]:
        """Run this category's analysis and return validated findings.

        A scanner result flagged as errored carries no usable evidence, so the
        chain short-circuits to an empty list rather than prompting Claude with
        an error blob.
        """
        if scan_result.error:
            return []
        return await engine.analyze(
            system=self.system_prompt,
            evidence_label=self.evidence_label,
            evidence=self.build_evidence(scan_result),
            context=context,
        )


__all__ = ["BaseChain"]
