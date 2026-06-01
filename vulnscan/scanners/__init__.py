"""Scan modules for VulnScan AI.

Every scanner inherits :class:`~vulnscan.scanners.base.BaseScanner` and returns
a :class:`~vulnscan.scanners.base.ScanResult` of raw evidence. Severity and
CVSS scoring happen later, in the AI engine (CLAUDE.md §5) — scanners never
assign them. All network access is scope-checked, timeout-bounded, and retried
by the base class (CLAUDE.md §6 & §7).
"""

from vulnscan.scanners.base import (
    BaseScanner,
    ScanResult,
    ScopeValidator,
    ScopeViolationError,
)
from vulnscan.scanners.form_fuzzer import FormFuzzerScanner
from vulnscan.scanners.http import HttpHeaderScanner
from vulnscan.scanners.js import JsSecretScanner
from vulnscan.scanners.recon import ReconScanner

__all__ = [
    "BaseScanner",
    "ScanResult",
    "ScopeValidator",
    "ScopeViolationError",
    "ReconScanner",
    "HttpHeaderScanner",
    "JsSecretScanner",
    "FormFuzzerScanner",
]
