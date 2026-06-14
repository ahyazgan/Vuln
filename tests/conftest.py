"""Shared pytest fixtures.

Provides an isolated in-memory SQLite database per test, created from the
SQLAlchemy metadata. A ``StaticPool`` keeps the single in-memory connection
alive for the whole test so all sessions see the same schema/data.

Also provides ``mock_client`` — a factory that builds an ``httpx.AsyncClient``
backed by an ``httpx.MockTransport``, so scanner tests run fully offline with
no real network access.
"""

from collections.abc import Callable
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from vulnscan.domain.models import Base


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture
async def session(engine) -> AsyncSession:
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as s:
        yield s


@pytest.fixture
def mock_client() -> Callable[[Callable[[httpx.Request], httpx.Response]], httpx.AsyncClient]:
    """Factory: build an offline ``httpx.AsyncClient`` from a request handler.

    The handler receives an ``httpx.Request`` and returns an ``httpx.Response``
    (or raises an ``httpx`` transport error to simulate failures). Redirects are
    followed so scanner code that relies on ``resp.url`` behaves realistically.
    """

    clients: list[httpx.AsyncClient] = []

    def _make(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
        clients.append(client)
        return client

    return _make


class _FakeMessages:
    """Stand-in for ``client.messages`` that replays canned text responses.

    Each ``create`` call pops the next response from ``responses`` and returns a
    Messages-shaped object (``.content`` is a list of text blocks). Every call's
    kwargs are recorded on ``.calls`` so tests can assert on system/prompt shape.
    """

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        text = self._responses.pop(0) if self._responses else "[]"
        block = SimpleNamespace(type="text", text=text)
        return SimpleNamespace(content=[block])


class _FakeAnthropic:
    def __init__(self, responses: list[str]) -> None:
        self.messages = _FakeMessages(responses)


@pytest.fixture
def fake_anthropic() -> Callable[[list[str]], _FakeAnthropic]:
    """Factory: build a fake Anthropic client that replays ``responses`` in order."""

    def _make(responses: list[str]) -> _FakeAnthropic:
        return _FakeAnthropic(responses)

    return _make


@pytest_asyncio.fixture
async def api():
    """An httpx client wired to the FastAPI app over an in-memory DB.

    Yields ``(client, enqueued, maker)``: the ASGI client, a list that records
    every enqueued scan payload (the real Celery enqueuer is overridden), and a
    session maker so tests can seed rows directly. Everything runs in the test's
    own event loop, so the aiosqlite connection and the app share one loop.
    """
    from vulnscan.api.app import create_app
    from vulnscan.api.deps import get_db, get_enqueuer

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    app = create_app()
    enqueued: list[dict] = []

    async def _override_db():
        async with maker() as s:
            yield s

    def _override_enqueuer():
        def _enqueue(payload: dict) -> str:
            enqueued.append(payload)
            return "task-test"

        return _enqueue

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_enqueuer] = _override_enqueuer

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, enqueued, maker
    await engine.dispose()
