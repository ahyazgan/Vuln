"""Security-header analysis chain (consumes ``HttpHeaderScanner`` output)."""

from __future__ import annotations

from vulnscan.ai.chains.base import BaseChain
from vulnscan.ai.prompts import HEADER_ANALYSIS_SYSTEM


class HeaderAnalysisChain(BaseChain):
    category = "headers"
    system_prompt = HEADER_ANALYSIS_SYSTEM


__all__ = ["HeaderAnalysisChain"]
