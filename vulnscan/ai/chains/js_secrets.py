"""JS-secret analysis chain (consumes ``JsSecretScanner`` output).

The scanner already redacts secret values; this chain forwards only that
redacted evidence, so no real credential ever reaches Claude (CLAUDE.md §2.5).
"""

from __future__ import annotations

from vulnscan.ai.chains.base import BaseChain
from vulnscan.ai.prompts import JS_SECRET_ANALYSIS_SYSTEM


class JsSecretAnalysisChain(BaseChain):
    category = "js_secrets"
    system_prompt = JS_SECRET_ANALYSIS_SYSTEM


__all__ = ["JsSecretAnalysisChain"]
