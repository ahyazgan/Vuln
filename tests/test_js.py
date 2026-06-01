"""Tests for the JS secret scanner (detection + mandatory redaction)."""

import httpx

from vulnscan.scanners.js import JsSecretScanner

# A fake-but-format-valid AWS key and a generic assigned secret.
_FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
_FAKE_API_SECRET = "s3cr3tValue1234567890abcd"
_JS_WITH_SECRETS = f"""
const cfg = {{
  awsKey: "{_FAKE_AWS_KEY}",
  api_key: "{_FAKE_API_SECRET}",
}};
console.log("hello");
"""

_JS_CLEAN = "export const add = (a, b) => a + b;\n"


def _make_handler():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/secrets.js":
            return httpx.Response(200, text=_JS_WITH_SECRETS)
        if path == "/clean.js":
            return httpx.Response(200, text=_JS_CLEAN)
        if path == "/missing.js":
            return httpx.Response(404, text="not found")
        return httpx.Response(200, text="")

    return handler


async def test_detects_secrets_and_redacts(mock_client):
    scanner = JsSecretScanner(
        "https://example.com/",
        ["example.com"],
        client=mock_client(_make_handler()),
        script_urls=["https://example.com/secrets.js", "https://example.com/clean.js"],
    )
    data = (await scanner.run()).data

    patterns = {m["pattern"] for m in data["matches"]}
    assert "aws_access_key_id" in patterns
    assert "generic_assigned_secret" in patterns
    assert set(data["scripts_scanned"]) == {
        "https://example.com/secrets.js",
        "https://example.com/clean.js",
    }

    # NON-NEGOTIABLE (CLAUDE.md §2.5/§7.3): the raw secret never appears anywhere
    # in the returned evidence — only a redacted preview.
    blob = str(data)
    assert _FAKE_AWS_KEY not in blob
    assert _FAKE_API_SECRET not in blob
    for m in data["matches"]:
        assert "[redacted" in m["redacted"]
        assert m["line"] >= 1


async def test_out_of_scope_scripts_skipped(mock_client):
    scanner = JsSecretScanner(
        "https://example.com/",
        ["example.com"],
        client=mock_client(_make_handler()),
        script_urls=[
            "https://example.com/secrets.js",
            "https://evil.com/secrets.js",  # out of scope: never fetched
        ],
    )
    data = (await scanner.run()).data

    assert "https://evil.com/secrets.js" in data["skipped_out_of_scope"]
    assert data["scripts_scanned"] == ["https://example.com/secrets.js"]


async def test_fetch_error_recorded_not_raised(mock_client):
    scanner = JsSecretScanner(
        "https://example.com/",
        ["example.com"],
        client=mock_client(_make_handler()),
        script_urls=["https://example.com/missing.js"],
    )
    # 404 is a normal response (no error), so the file is scanned with no matches.
    data = (await scanner.run()).data
    assert data["scripts_scanned"] == ["https://example.com/missing.js"]
    assert data["matches"] == []
