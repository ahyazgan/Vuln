"""Tek seferlik demo: scanner'ları gerçek bir hedefe karşı çalıştırır.

Çalıştırma:
    .\.venv\Scripts\python.exe demo_scan.py

NOT: Hedef, scope listesinde olmak ZORUNDA (CLAUDE.md §7.2). Scope dışı bir
URL ScopeViolationError fırlatır ve hiçbir istek gönderilmez.
"""

import asyncio
import json

from vulnscan.scanners import HttpHeaderScanner, ReconScanner

TARGET = "https://example.com/"
SCOPE = ["example.com"]  # sadece bu domain ve alt domainleri taranabilir


async def main() -> None:
    async with ReconScanner(TARGET, SCOPE) as recon:
        result = await recon.safe_run()
        print("=== RECON ===")
        print(json.dumps(result.data, indent=2, ensure_ascii=False)[:1500])

    async with HttpHeaderScanner(TARGET, SCOPE) as headers:
        result = await headers.safe_run()
        print("\n=== SECURITY HEADERS ===")
        print(json.dumps(result.data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
