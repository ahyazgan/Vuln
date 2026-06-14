"""FastAPI application factory (CLAUDE.md §3 / §8).

``create_app`` assembles the routers into an app. The top-level ``main.py``
entrypoint imports this and supplies lifespan/startup wiring; keeping the factory
here lets tests build a fresh app and override dependencies (DB session, scan
enqueuer) without a running database or broker. ``main.py`` passes a ``lifespan``
that disposes the DB engine on shutdown; tests call ``create_app()`` with none.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from fastapi import FastAPI

from vulnscan.api.auth import router as auth_router
from vulnscan.api.routes.admin import router as admin_router
from vulnscan.api.routes.payments import router as payments_router
from vulnscan.api.routes.programs import router as programs_router
from vulnscan.api.routes.scans import router as scans_router
from vulnscan.api.routes.submissions import router as submissions_router
from vulnscan.api.routes.webhooks import router as webhooks_router

API_PREFIX = "/api/v1"

# A FastAPI lifespan: a callable taking the app and returning an async context
# manager. Optional so tests can build an app with no startup/shutdown wiring.
Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]


def create_app(*, lifespan: Lifespan | None = None) -> FastAPI:
    app = FastAPI(
        title="VulnScan AI",
        version="0.1.0",
        summary="Authorized, AI-assisted vulnerability scanning platform.",
        lifespan=lifespan,
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
        admin_router,
        webhooks_router,
    ):
        app.include_router(router, prefix=API_PREFIX)

    return app


__all__ = ["create_app", "API_PREFIX"]
