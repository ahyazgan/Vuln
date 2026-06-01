"""Tests for the HTTP security-header scanner."""

import httpx

from vulnscan.scanners.http import HttpHeaderScanner


def _names(items):
    return {i["header"].lower() for i in items}


async def test_missing_headers_are_reported(mock_client):
    def handler(request: httpx.Request) -> httpx.Response:
        # A bare response: no security headers, leaks Server + X-Powered-By.
        return httpx.Response(200, headers={"server": "Apache/2.4", "x-powered-by": "PHP/8.2"})

    scanner = HttpHeaderScanner(
        "https://example.com/", ["example.com"], client=mock_client(handler)
    )
    data = (await scanner.run()).data

    missing = _names(data["missing"])
    assert "strict-transport-security" in missing
    assert "content-security-policy" in missing
    assert "x-frame-options" in missing
    assert "x-content-type-options" in missing
    assert {d["header"] for d in data["information_disclosure"]} == {"server", "x-powered-by"}


async def test_present_headers_are_recognized(mock_client):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
        )

    scanner = HttpHeaderScanner(
        "https://example.com/", ["example.com"], client=mock_client(handler)
    )
    data = (await scanner.run()).data

    present = _names(data["present"])
    assert "strict-transport-security" in present
    assert "content-security-policy" in present
    assert "x-content-type-options" in present
    assert data["missing"] == []
    assert data["weak"] == []


async def test_weak_hsts_and_bad_nosniff_flagged(mock_client):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=100",  # far below 6 months
                "x-content-type-options": "sniff",            # not 'nosniff'
            },
        )

    scanner = HttpHeaderScanner(
        "https://example.com/", ["example.com"], client=mock_client(handler)
    )
    data = (await scanner.run()).data

    weak = _names(data["weak"])
    assert "strict-transport-security" in weak
    assert "x-content-type-options" in weak
