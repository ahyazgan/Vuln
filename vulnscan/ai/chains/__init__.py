"""Analysis chains — one file per finding category (CLAUDE.md §3 / §4.4).

Each chain turns a scanner's raw evidence into structured findings via the
shared :class:`~vulnscan.ai.engine.AnalysisEngine`. Category chains map a single
``ScanResult``; :class:`ChainAnalysisChain` combines individual findings into
multi-step attack paths (pipeline step 5).
"""

from vulnscan.ai.chains.base import BaseChain
from vulnscan.ai.chains.chain_analysis import ChainAnalysisChain, ChainedFinding
from vulnscan.ai.chains.headers import HeaderAnalysisChain
from vulnscan.ai.chains.js_secrets import JsSecretAnalysisChain
from vulnscan.ai.chains.xss import XssAnalysisChain

__all__ = [
    "BaseChain",
    "HeaderAnalysisChain",
    "JsSecretAnalysisChain",
    "XssAnalysisChain",
    "ChainAnalysisChain",
    "ChainedFinding",
]
