"""Tests for the scanner foundation: scope enforcement, retry, safe_run."""

import httpx
import pytest

from vulnscan.scanners.base import (
    BaseScanner,
    ScanResult,
    ScopeValidator,
    ScopeViolationError,
)


class _ProbeScanner(BaseScanner):
    """Minimal concrete scanner that GETs the target and echoes the status."""

    name = "probe"

    async def run(self) -> ScanResult:
        resp = await self._get(self.target_url)
        return ScanResult(
            scanner=self.name,
            target=self.target_url,
            data={"status": resp.status_code},
        )


# --------------------------------------------------------------------------- #
# ScopeValidator
# --------------------------------------------------------------------------- #
class TestScopeValidator:
    def test_bare_domain_matches_apex_and_subdomains(self):
        v = ScopeValidator(["example.com"])
        assert v.is_in_scope("https://example.com/")
        assert v.is_in_scope("https://api.example.com/x")
        assert v.is_in_scope("http://a.b.example.com")

    def test_wildcard_matches_subdomains_but_not_apex(self):
        v = ScopeValidator(["*.example.com"])
        assert v.is_in_scope("https://api.example.com/")
        assert not v.is_in_scope("https://example.com/")

    def test_unrelated_domain_out_of_scope(self):
        v = ScopeValidator(["example.com"])
        assert not v.is_in_scope("https://evil.com/")
        # Substring trickery must not pass.
        assert not v.is_in_scope("https://example.com.evil.com/")
        assert not v.is_in_scope("https://notexample.com/")

    def test_non_http_schemes_never_in_scope(self):
        v = ScopeValidator(["example.com"])
        assert not v.is_in_scope("file:///etc/passwd")
        assert not v.is_in_scope("ftp://example.com/")

    def test_empty_scope_denies_all(self):
        v = ScopeValidator([])
        assert not v.is_in_scope("https://example.com/")

    def test_entries_tolerate_urls_and_ports(self):
        v = ScopeValidator(["https://example.com:8443/path", "  API.Example.org  "])
        assert v.is_in_scope("https://example.com/")
        assert v.is_in_scope("https://api.example.org/")

    def test_assert_in_scope_raises_with_host(self):
        v = ScopeValidator(["example.com"])
        with pytest.raises(ScopeViolationError) as ei:
            v.assert_in_scope("https://evil.com/x")
        assert ei.value.host == "evil.com"


# --------------------------------------------------------------------------- #
# BaseScanner networking
# --------------------------------------------------------------------------- #
class TestBaseScannerRequest:
    async def test_request_blocks_out_of_scope_before_network(self, mock_client):
        called = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            called["n"] += 1
            return httpx.Response(200, text="should not happen")

        scanner = _ProbeScanner(
            "https://evil.com/", ["example.com"], client=mock_client(handler)
        )
        with pytest.raises(ScopeViolationError):
            await scanner._get("https://evil.com/")
        assert called["n"] == 0  # no socket opened for an out-of-scope URL

    async def test_request_retries_transient_then_succeeds(self, mock_client):
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise httpx.ConnectError("boom", request=request)
            return httpx.Response(200, text="ok")

        scanner = _ProbeScanner(
            "https://example.com/",
            ["example.com"],
            client=mock_client(handler),
            backoff_base=0,  # no real sleeping in tests
            max_retries=2,
        )
        resp = await scanner._get("https://example.com/")
        assert resp.status_code == 200
        assert attempts["n"] == 3

    async def test_request_exhausts_retries_and_raises(self, mock_client):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("always down", request=request)

        scanner = _ProbeScanner(
            "https://example.com/",
            ["example.com"],
            client=mock_client(handler),
            backoff_base=0,
            max_retries=1,
        )
        with pytest.raises(httpx.ConnectError):
            await scanner._get("https://example.com/")


# --------------------------------------------------------------------------- #
# safe_run
# --------------------------------------------------------------------------- #
class TestSafeRun:
    async def test_success_stamps_timing(self, mock_client):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="hi")

        scanner = _ProbeScanner(
            "https://example.com/", ["example.com"], client=mock_client(handler)
        )
        result = await scanner.safe_run()
        assert result.success and not result.error
        assert result.data["status"] == 200
        assert result.started_at is not None and result.finished_at is not None
        assert result.duration_ms is not None and result.duration_ms >= 0

    async def test_scope_violation_becomes_error_result(self, mock_client):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)

        # Target is out of scope -> run() raises ScopeViolationError -> caught.
        scanner = _ProbeScanner(
            "https://evil.com/", ["example.com"], client=mock_client(handler)
        )
        result = await scanner.safe_run()
        assert result.error and not result.success
        assert "scope violation" in result.error_message

    async def test_unexpected_exception_becomes_error_result(self, mock_client):
        def handler(request: httpx.Request) -> httpx.Response:
            raise RuntimeError("kaboom")

        # RuntimeError is not a transport error, so it is not retried; safe_run
        # must still catch it and return a degraded result, never raise.
        scanner = _ProbeScanner(
            "https://example.com/", ["example.com"], client=mock_client(handler)
        )
        result = await scanner.safe_run()
        assert result.error
        assert "kaboom" in result.error_message
