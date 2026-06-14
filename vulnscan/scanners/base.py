"""Foundation for every scan module.

This module provides the three things every scanner shares (see CLAUDE.md
§6 & §7):

* :class:`ScopeValidator` / :class:`ScopeViolationError` — **scope enforcement
  is a security control, not a convenience** (§7.2). Every URL is validated
  against the company whitelist *before any network request leaves the worker*.
  ``BaseScanner._request`` calls the validator first, so a scanner physically
  cannot reach an out-of-scope host.
* :class:`ScanResult` — the structured, raw-evidence envelope every scanner
  returns. Scanners produce *evidence*; CVSS scoring/severity is the AI
  engine's job (CLAUDE.md §5), never the scanner's.
* :class:`BaseScanner` — the ABC all scanners inherit. It supplies the
  scope-checked, timeout-bounded, retrying ``_request`` helper, structured
  logging, and ``safe_run`` which guarantees a scanner **never raises an
  unhandled exception** — on failure it degrades to a partial result with an
  ``error`` flag (§6).

Defaults mirror CLAUDE.md §6: 30s per-operation timeout, max 2 retries, 2s
base exponential backoff.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field

# Per-operation defaults (CLAUDE.md §6).
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_BASE = 2.0

logger = logging.getLogger("vulnscan.scanners")


# --------------------------------------------------------------------------- #
# Scope enforcement (CLAUDE.md §7.2 — NON-NEGOTIABLE)
# --------------------------------------------------------------------------- #
class ScopeViolationError(Exception):
    """Raised when a scanner is asked to reach a URL outside the program scope.

    This is a security event, not a recoverable error: it means a request was
    about to leave the worker for a target the company never authorized. It is
    raised *before* any socket is opened.
    """

    def __init__(self, url: str, host: str | None = None) -> None:
        self.url = url
        self.host = host
        super().__init__(f"Out-of-scope URL refused: {url!r} (host={host!r})")


class ScopeValidator:
    """Validates URLs against a ``BountyProgram.scope_domains`` whitelist.

    Matching rules (documented so scope semantics are never a surprise):

    * Only ``http`` / ``https`` URLs can ever be in scope. Any other scheme
      (``file:``, ``ftp:``, ``data:``, …) is always rejected.
    * A bare entry ``"example.com"`` matches the apex host **and** any
      subdomain of it (``api.example.com``, ``a.b.example.com``).
    * A wildcard entry ``"*.example.com"`` matches any subdomain
      (``api.example.com``) but **not** the apex ``example.com`` itself.
    * Host comparison is case-insensitive and ignores the port.
    * An empty scope matches nothing — deny by default.
    """

    def __init__(self, scope_domains: Iterable[str]) -> None:
        self._exact: set[str] = set()
        self._suffixes: set[str] = set()
        for raw in scope_domains:
            self._add_pattern(raw)

    def _add_pattern(self, raw: str) -> None:
        pattern = (raw or "").strip().lower()
        if not pattern:
            return
        # Tolerate entries written as full URLs or with a path/port.
        if "://" in pattern:
            pattern = urlsplit(pattern).netloc or pattern
        pattern = pattern.split("/", 1)[0].split(":", 1)[0]
        if pattern.startswith("*."):
            # Subdomain wildcard: matches any host ending in ".<suffix>".
            self._suffixes.add(pattern[2:])
        else:
            # Bare domain: matches the apex and any subdomain.
            self._exact.add(pattern)
            self._suffixes.add(pattern)

    def is_in_scope(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        if not host:
            return False
        if host in self._exact:
            return True
        return any(host.endswith("." + suffix) for suffix in self._suffixes)

    def assert_in_scope(self, url: str) -> None:
        """Raise :class:`ScopeViolationError` unless ``url`` is in scope."""
        if not self.is_in_scope(url):
            host = urlsplit(url).hostname
            raise ScopeViolationError(url, host)


# --------------------------------------------------------------------------- #
# Result envelope
# --------------------------------------------------------------------------- #
class ScanResult(BaseModel):
    """Raw, structured output of a single scanner run.

    ``data`` carries the scanner-specific evidence (headers, forms, secret
    matches, probe reflections, …) that is later fed verbatim to the Claude
    analysis chains. A scanner that fails sets ``error=True`` and
    ``error_message`` and returns whatever partial ``data`` it gathered, so
    the pipeline degrades gracefully instead of aborting (CLAUDE.md §6).
    """

    scanner: str
    target: str
    success: bool = True
    error: bool = False
    error_message: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: float | None = None

    def summary(self) -> str:
        """Short ``result_summary`` string for structured logs."""
        if self.error:
            return f"error: {self.error_message}"
        keys = ", ".join(sorted(self.data)) or "no data"
        return f"ok ({keys})"


# --------------------------------------------------------------------------- #
# Base scanner
# --------------------------------------------------------------------------- #
class BaseScanner(ABC):
    """Abstract base for all scan modules.

    Subclasses implement :meth:`run`, doing their scanner-specific work and
    returning a :class:`ScanResult`. They must reach the network only through
    :meth:`_request`, which scope-checks every URL before the request leaves
    the process and applies the timeout + retry policy.

    Callers (the worker pipeline) should invoke :meth:`safe_run`, which wraps
    :meth:`run` so a scanner never propagates an unhandled exception.

    The scanner can be used as an async context manager to own its HTTP
    client::

        async with ReconScanner(url, scope) as s:
            result = await s.safe_run()
    """

    #: Stable identifier used in ``ScanResult.scanner`` and log records.
    name: str = "base"

    def __init__(
        self,
        target_url: str,
        scope: ScopeValidator | Iterable[str],
        *,
        scan_id: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ) -> None:
        self.target_url = target_url
        self.scope = scope if isinstance(scope, ScopeValidator) else ScopeValidator(scope)
        self.scan_id = scan_id
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        # An injected client is owned by the caller (used in tests); a client we
        # create ourselves is closed on __aexit__.
        self._client = client
        self._owns_client = client is None

    # -- lifecycle --------------------------------------------------------- #
    async def __aenter__(self) -> BaseScanner:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
                headers={"User-Agent": "VulnScanAI/0.1 (+authorized-scan)"},
            )
        return self._client

    # -- networking -------------------------------------------------------- #
    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Scope-checked, timeout-bounded HTTP request with retry/backoff.

        Scope is validated **first**, before any client is touched, so an
        out-of-scope URL never opens a socket (CLAUDE.md §7.2). Transient
        network errors (timeouts, transport errors) are retried up to
        ``max_retries`` times with exponential backoff; a
        :class:`ScopeViolationError` is never retried — it propagates
        immediately.
        """
        self.scope.assert_in_scope(url)
        client = self._get_client()
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return await client.request(method, url, timeout=self.timeout, **kwargs)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                self._log(
                    "request_retry",
                    url=url,
                    attempt=attempt,
                    error=str(exc),
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(self.backoff_base * (2**attempt))
                    continue
                raise
        # Unreachable: the loop either returns or raises. Guard for type-checkers.
        raise last_exc  # type: ignore[misc]

    async def _get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    # -- logging ----------------------------------------------------------- #
    def _log(self, step: str, *, level: int = logging.INFO, **fields: Any) -> None:
        """Emit one structured (JSON) log record for a scan step (CLAUDE.md §6).

        Minimum fields always present: ``scan_id``, ``scanner``, ``step``,
        ``target``, ``timestamp``.
        """
        record = {
            "scan_id": self.scan_id,
            "scanner": self.name,
            "step": step,
            "target": self.target_url,
            "timestamp": datetime.now(UTC).isoformat(),
            **fields,
        }
        logger.log(level, json.dumps(record, default=str))

    # -- execution --------------------------------------------------------- #
    @abstractmethod
    async def run(self) -> ScanResult:
        """Perform the scan and return raw evidence. Implemented by subclasses."""
        raise NotImplementedError

    async def safe_run(self) -> ScanResult:
        """Run the scanner, never raising — failures become partial results.

        Wraps :meth:`run` so the pipeline degrades gracefully (CLAUDE.md §6).
        A :class:`ScopeViolationError` is logged at WARNING (it is a security
        event) and returned as an errored result; any other exception is
        logged at ERROR and likewise returned as an errored result.
        """
        started = datetime.now(UTC)
        self._log("start")
        try:
            result = await self.run()
        except ScopeViolationError as exc:
            self._log("scope_violation", level=logging.WARNING, url=exc.url, host=exc.host)
            result = self._error_result(started, f"scope violation: {exc}")
        except Exception as exc:  # noqa: BLE001 - scanners must never leak exceptions
            self._log("error", level=logging.ERROR, error=str(exc))
            result = self._error_result(started, str(exc))
        else:
            # Stamp timing if the subclass did not.
            if result.started_at is None:
                result.started_at = started
            if result.finished_at is None:
                result.finished_at = datetime.now(UTC)
            if result.duration_ms is None:
                result.duration_ms = (
                    result.finished_at - result.started_at
                ).total_seconds() * 1000.0
        self._log("done", result_summary=result.summary())
        return result

    def _error_result(self, started: datetime, message: str) -> ScanResult:
        finished = datetime.now(UTC)
        return ScanResult(
            scanner=self.name,
            target=self.target_url,
            success=False,
            error=True,
            error_message=message,
            started_at=started,
            finished_at=finished,
            duration_ms=(finished - started).total_seconds() * 1000.0,
        )


__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_BACKOFF_BASE",
    "ScopeViolationError",
    "ScopeValidator",
    "ScanResult",
    "BaseScanner",
]
