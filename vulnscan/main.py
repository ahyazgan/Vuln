"""Top-level ASGI entrypoint (CLAUDE.md §3).

Run with::

    uvicorn vulnscan.main:app --reload

This wires the application factory (:func:`vulnscan.api.app.create_app`) to a
lifespan that disposes the async DB engine on shutdown so connections drain
cleanly. Schema management is Alembic's job (``alembic upgrade head``), not the
app's — the lifespan never creates tables.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vulnscan.api.app import create_app
from vulnscan.db import dispose_engine

logger = logging.getLogger("vulnscan")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    logger.info('{"event": "api_startup"}')
    try:
        yield
    finally:
        await dispose_engine()
        logger.info('{"event": "api_shutdown"}')


app = create_app(lifespan=lifespan)


__all__ = ["app"]
