"""Injection (XSS / SQLi) analysis chain (consumes ``FormFuzzerScanner`` output)."""

from __future__ import annotations

from vulnscan.ai.chains.base import BaseChain
from vulnscan.ai.prompts import XSS_ANALYSIS_SYSTEM


class XssAnalysisChain(BaseChain):
    category = "xss"
    system_prompt = XSS_ANALYSIS_SYSTEM

    @property
    def evidence_label(self) -> str:
        return "Raw form-fuzzing probe results (XSS reflection / SQLi error signals)"


__all__ = ["XssAnalysisChain"]
