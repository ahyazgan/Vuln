"""Live AI test: real Claude analysis of header-scan evidence.

Reads the API key from the ANTHROPIC_API_KEY environment variable — the key is
never hard-coded here. Proves the AnalysisEngine turns raw scanner evidence into
CVSS-scored findings via the real Claude API.

Run:  $env:ANTHROPIC_API_KEY="..."; .\.venv\Scripts\python.exe scripts\smoke_ai.py
"""

import asyncio
import os

from vulnscan.ai.chains import ChainAnalysisChain, HeaderAnalysisChain
from vulnscan.ai.engine import AnalysisContext, AnalysisEngine
from vulnscan.scanners.base import ScanResult


async def main() -> None:
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY not set")

    # Realistic HttpHeaderScanner output for a site missing key controls.
    evidence = ScanResult(
        scanner="http_headers",
        target="https://example.com/",
        data={
            "status_code": 200,
            "present": [],
            "missing": [
                {
                    "header": "Content-Security-Policy",
                    "note": "No CSP; injected scripts unrestricted.",
                },
                {
                    "header": "Strict-Transport-Security",
                    "note": "HSTS not set; downgradeable to HTTP.",
                },
                {"header": "X-Frame-Options", "note": "Clickjacking protection not set."},
                {"header": "X-Content-Type-Options", "note": "MIME sniffing not disabled."},
            ],
            "weak": [],
            "information_disclosure": [{"header": "server", "value": "nginx/1.25.3"}],
        },
    )

    engine = AnalysisEngine()  # picks up ANTHROPIC_API_KEY + VULNSCAN_CLAUDE_MODEL
    ctx = AnalysisContext(target_url="https://example.com/", tech_stack=["nginx"])

    print(f"model: {engine.model}")
    print("\n== Claude header analysis (step 4) ==")
    findings = await HeaderAnalysisChain().analyze(evidence, ctx, engine)
    print(f"{len(findings)} finding(s):")
    for f in findings:
        print(f"  [{f.severity.value.upper():8}] CVSS {f.cvss_score:<4} {f.title}")
        print(f"             {f.description[:140]}")

    if len(findings) >= 2:
        print("\n== Claude chain analysis (step 5) ==")
        chained = await ChainAnalysisChain().analyze(findings, ctx, engine)
        print(f"{len(chained)} attack chain(s):")
        for c in chained:
            print(
                f"  [{c.severity.value.upper():8}] CVSS {c.cvss_score:<4} {c.title}  "
                f"(combines {c.chain_parent_ids})"
            )

    print("\nLIVE AI TEST DONE")


if __name__ == "__main__":
    asyncio.run(main())
