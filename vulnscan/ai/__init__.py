"""AI analysis engine for VulnScan (CLAUDE.md §5).

All Claude access is funnelled through :class:`~vulnscan.ai.engine.AnalysisEngine`
— the single entry point (CLAUDE.md §6). Analysis chains (``ai.chains``) turn
raw scanner evidence into CVSS-scored, Pydantic-validated findings; system
prompts live as constants in :mod:`vulnscan.ai.prompts` (CLAUDE.md §5.5).
"""

from vulnscan.ai.engine import (
    MODEL,
    AnalysisContext,
    AnalysisEngine,
)

__all__ = [
    "MODEL",
    "AnalysisContext",
    "AnalysisEngine",
]
