"""Preview dashboard — a dev-only FastAPI app to eyeball scanner output.

⚠️  This is NOT the production scan API. Per CLAUDE.md §2.1 the real API runs
scans asynchronously via Celery and returns a job id immediately; this tool
runs the (passive) scanners synchronously so a human can see results in a
browser during early development. It will be replaced by the proper async API
(PROMPT 6) and Next.js frontend.

Run:
    .\\.venv\\Scripts\\python.exe -m uvicorn tools.dashboard:app --reload
    → open http://localhost:8000

Scope is still strictly enforced (CLAUDE.md §7.2): a target outside the scope
list is refused before any request is made.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from vulnscan.scanners import HttpHeaderScanner, JsSecretScanner, ReconScanner

app = FastAPI(title="VulnScan AI — Dev Preview", docs_url="/api/docs")

_STATIC = Path(__file__).parent / "static"


class ScanRequest(BaseModel):
    target: str = Field(min_length=1)
    # Comma/space/newline separated scope entries. If empty, the target host is
    # used as scope so the single most common case needs no extra typing.
    scope: str = ""


def _parse_scope(raw: str, target: str) -> list[str]:
    entries = [s.strip() for s in raw.replace("\n", ",").replace(" ", ",").split(",")]
    entries = [e for e in entries if e]
    if not entries:
        host = urlsplit(target).hostname
        if host:
            entries = [host]
    return entries


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


@app.post("/api/scan")
async def scan(req: ScanRequest) -> dict:
    """Run the passive scanners against a target and return aggregated evidence.

    Passive only: recon (read the page), security headers, and JS secret
    scanning. No active payloads are sent. Each scanner's ``safe_run`` never
    raises — failures come back as ``error`` results.
    """
    target = req.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    scope = _parse_scope(req.scope, target)

    async with ReconScanner(target, scope) as recon:
        recon_res = await recon.safe_run()
    scripts = recon_res.data.get("scripts", []) if not recon_res.error else []

    async with HttpHeaderScanner(target, scope) as http:
        http_res = await http.safe_run()

    async with JsSecretScanner(target, scope, script_urls=scripts) as js:
        js_res = await js.safe_run()

    return {
        "target": target,
        "scope": scope,
        "recon": recon_res.model_dump(mode="json"),
        "headers": http_res.model_dump(mode="json"),
        "js": js_res.model_dump(mode="json"),
    }


__all__ = ["app"]
