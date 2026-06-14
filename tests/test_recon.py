"""Tests for the recon scanner (surface mapping + tech fingerprint)."""

import httpx

from vulnscan.scanners.recon import ReconScanner

_HTML = """
<!doctype html>
<html>
  <head>
    <title>Example Shop</title>
    <meta name="generator" content="WordPress 6.4">
    <script src="/static/app.js"></script>
    <script src="https://cdn.example.com/jquery.min.js"></script>
  </head>
  <body>
    <a href="/about">About</a>
    <a href="https://example.com/contact">Contact</a>
    <a href="https://twitter.com/example">Twitter</a>
    <a href="#section">Anchor</a>
    <a href="mailto:hi@example.com">Mail</a>
    <form action="/search" method="get">
      <input name="q" type="text">
      <input name="go" type="submit">
    </form>
    <form action="https://example.com/login" method="post">
      <input name="user" type="text">
      <input name="pass" type="password">
    </form>
  </body>
</html>
"""


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        text=_HTML,
        headers={"content-type": "text/html", "server": "nginx/1.25", "x-powered-by": "PHP/8.2"},
    )


async def test_recon_extracts_surface(mock_client):
    scanner = ReconScanner("https://example.com/", ["example.com"], client=mock_client(_handler))
    result = await scanner.run()
    data = result.data

    assert data["status_code"] == 200
    assert data["title"] == "Example Shop"

    # Links: internal resolved + external split, junk (#, mailto) dropped.
    assert "https://example.com/about" in data["links"]["internal"]
    assert "https://example.com/contact" in data["links"]["internal"]
    assert "https://twitter.com/example" in data["links"]["external"]
    flat = data["links"]["internal"] + data["links"]["external"]
    assert not any("mailto" in u or "#" in u for u in flat)


async def test_recon_parses_forms(mock_client):
    scanner = ReconScanner("https://example.com/", ["example.com"], client=mock_client(_handler))
    result = await scanner.run()
    forms = result.data["forms"]

    assert len(forms) == 2
    search = next(f for f in forms if f["action"].endswith("/search"))
    assert search["method"] == "get"
    assert {i["name"] for i in search["inputs"]} == {"q", "go"}

    login = next(f for f in forms if f["action"].endswith("/login"))
    assert login["method"] == "post"
    assert login["action"] == "https://example.com/login"


async def test_recon_detects_tech_and_scripts(mock_client):
    scanner = ReconScanner("https://example.com/", ["example.com"], client=mock_client(_handler))
    result = await scanner.run()
    data = result.data

    assert "WordPress" in data["tech_stack"]  # from <meta generator> markup
    assert "nginx" in data["tech_stack"]  # from Server header
    assert "PHP" in data["tech_stack"]  # from X-Powered-By
    assert "jQuery" in data["tech_stack"]  # from script src
    # Scripts resolved to absolute URLs.
    assert "https://example.com/static/app.js" in data["scripts"]
    assert "https://cdn.example.com/jquery.min.js" in data["scripts"]
