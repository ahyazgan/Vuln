"""Tests for the form fuzzer (XSS reflection + SQLi error signatures)."""

import httpx

from vulnscan.scanners.form_fuzzer import FormFuzzerScanner


def _reflecting_handler(request: httpx.Request) -> httpx.Response:
    """Echoes submitted values back (reflective) and fakes a SQL error.

    The ``q`` parameter is reflected verbatim (XSS signal); any request whose
    body/query contains a single quote returns a MySQL-style error (SQLi signal).
    """
    if request.method == "GET":
        submitted = dict(request.url.params)
    else:
        from urllib.parse import parse_qs

        submitted = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}

    payload = submitted.get("q", "")
    body = f"<html>You searched for: {payload}</html>"
    if "'" in "".join(submitted.values()):
        body += "<br>You have an error in your SQL syntax near ''1'='1'"
    return httpx.Response(200, text=body, headers={"content-type": "text/html"})


_FORM = {
    "action": "https://example.com/search",
    "method": "get",
    "inputs": [
        {"name": "q", "type": "text"},
        {"name": "submit", "type": "submit"},  # skipped (not fuzzable)
    ],
}


async def test_detects_reflected_xss_and_sql_error(mock_client):
    scanner = FormFuzzerScanner(
        "https://example.com/",
        ["example.com"],
        client=mock_client(_reflecting_handler),
        forms=[_FORM],
        request_delay=0,  # no rate-limit sleep in tests
    )
    data = (await scanner.run()).data

    # 'q' is fuzzed for both XSS and SQLi; 'submit' is skipped.
    kinds = {(p["param"], p["kind"]) for p in data["probes"]}
    assert ("q", "xss") in kinds
    assert ("q", "sqli") in kinds
    assert ("submit", "xss") not in kinds

    assert data["reflected_count"] >= 1
    assert data["sql_error_count"] >= 1
    xss = next(p for p in data["probes"] if p["kind"] == "xss")
    assert xss["reflected"] is True


async def test_out_of_scope_form_skipped(mock_client):
    out_of_scope_form = {**_FORM, "action": "https://evil.com/search"}
    scanner = FormFuzzerScanner(
        "https://example.com/",
        ["example.com"],
        client=mock_client(_reflecting_handler),
        forms=[out_of_scope_form],
        request_delay=0,
    )
    data = (await scanner.run()).data

    assert "https://evil.com/search" in data["skipped_out_of_scope"]
    assert data["probes"] == []


async def test_post_form_is_fuzzed(mock_client):
    post_form = {**_FORM, "method": "post"}
    scanner = FormFuzzerScanner(
        "https://example.com/",
        ["example.com"],
        client=mock_client(_reflecting_handler),
        forms=[post_form],
        request_delay=0,
    )
    data = (await scanner.run()).data
    assert all(p["method"] == "post" for p in data["probes"])
    assert data["sql_error_count"] >= 1
