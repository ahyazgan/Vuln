"""FastAPI application factory (CLAUDE.md §3 / §8).

``create_app`` assembles the routers into an app. The top-level ``main.py``
entrypoint (next step) imports this and adds lifespan/startup wiring; keeping the
factory here lets tests build a fresh app and override dependencies (DB session,
scan enqueuer) without a running database or broker.
"""

from __future__ import annotations

from fastapi import FastAPI

from vulnscan.api.auth import router as auth_router
from vulnscan.api.routes.payments import router as payments_router
from vulnscan.api.routes.programs import router as programs_router
from vulnscan.api.routes.scans import router as scans_router
from vulnscan.api.routes.submissions import router as submissions_router
from vulnscan.api.routes.webhooks import router as webhooks_router

API_PREFIX = "/api/v1"


def create_app() -> FastAPI:
    app = FastAPI(
        title="VulnScan AI",
        version="0.1.0",
        summary="Authorized, AI-assisted vulnerability scanning platform.",
    )

    @app.get("/health", tags=["meta"])
    async def health() -> dict:
        return {"status": "ok"}

    for router in (
        auth_router,
        programs_router,
        scans_router,
        submissions_router,
        payments_router,
        webhooks_router,
    ):
        app.include_router(router, prefix=API_PREFIX)

    return app


__all__ = ["create_app", "API_PREFIX"]
