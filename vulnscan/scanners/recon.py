"""Recon scanner — pipeline step 1 (CLAUDE.md §4.1).

Loads the target, parses the returned HTML, and discovers the attack surface:
links, forms (with their inputs), external JavaScript, ``<meta>`` tags, and a
best-effort technology-stack fingerprint derived from response headers and
markup. The output is raw evidence consumed by later steps (surface mapping,
form fuzzing) and by the Claude analysis chains — recon itself assigns no
severity.

HTML is parsed with the standard library's ``html.parser`` (no third-party
parser dependency, works fully offline in tests).
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from vulnscan.scanners.base import BaseScanner, ScanResult

# Header / markup signatures -> technology label. Intentionally small and
# conservative; this is a fingerprint hint for Claude, not a definitive claim.
_HEADER_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "server": [
        ("nginx", "nginx"),
        ("apache", "Apache"),
        ("cloudflare", "Cloudflare"),
        ("gunicorn", "Gunicorn"),
        ("envoy", "Envoy"),
    ],
    "x-powered-by": [
        ("php", "PHP"),
        ("express", "Express"),
        ("asp.net", "ASP.NET"),
        ("next.js", "Next.js"),
    ],
}

_MARKUP_SIGNATURES: list[tuple[str, str]] = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("wordpress", "WordPress"),  # e.g. <meta name="generator" content="WordPress ...">
    ("drupal", "Drupal"),
    ("/drupal", "Drupal"),
    ("cdn.shopify.com", "Shopify"),
    ("react", "React"),
    ("vue", "Vue.js"),
    ("angular", "Angular"),
    ("jquery", "jQuery"),
]


class _SurfaceParser(HTMLParser):
    """Collects links, forms, scripts and meta tags from an HTML document.

    Forms are accumulated statefully: inputs encountered between ``<form>`` and
    ``</form>`` are attached to the currently open form.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.metas: list[dict[str, str]] = []
        self.forms: list[dict] = []
        self.title: str | None = None
        self._open_form: dict | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and "href" in a:
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "meta" and ("name" in a or "http-equiv" in a):
            self.metas.append(
                {
                    "name": a.get("name", a.get("http-equiv", "")),
                    "content": a.get("content", ""),
                }
            )
        elif tag == "form":
            self._open_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._open_form is not None:
            self._open_form["inputs"].append(
                {
                    "name": a.get("name", ""),
                    "type": a.get("type", "text" if tag == "input" else tag),
                }
            )
        elif tag == "title":
            self._in_title = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Self-closing tags (<input .../>, <meta .../>) still carry surface data.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._open_form is not None:
            self.forms.append(self._open_form)
            self._open_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and data.strip():
            self.title = (self.title or "") + data.strip()


def _detect_tech(headers: dict[str, str], html: str, scripts: list[str]) -> list[str]:
    """Best-effort technology fingerprint from headers + markup."""
    found: set[str] = set()
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    for header, sigs in _HEADER_SIGNATURES.items():
        value = lower_headers.get(header, "")
        for needle, label in sigs:
            if needle in value:
                found.add(label)
    haystack = html.lower() + " " + " ".join(scripts).lower()
    for needle, label in _MARKUP_SIGNATURES:
        if needle in haystack:
            found.add(label)
    return sorted(found)


class ReconScanner(BaseScanner):
    """Fetch the target and map its attack surface (CLAUDE.md §4.1)."""

    name = "recon"

    async def run(self) -> ScanResult:
        resp = await self._get(self.target_url)
        final_url = str(resp.url)
        headers = dict(resp.headers)
        body = resp.text if "text/html" in headers.get("content-type", "") else resp.text

        parser = _SurfaceParser()
        try:
            parser.feed(body)
        except Exception as exc:  # malformed HTML must not abort recon
            self._log("html_parse_warning", error=str(exc))

        # Resolve links/scripts to absolute URLs and drop fragments/dupes.
        links = self._normalize_urls(parser.links, final_url)
        scripts = self._normalize_urls(parser.scripts, final_url)

        # Split discovered links into same-origin (worth crawling) vs external.
        origin = urlsplit(final_url)
        internal = [u for u in links if urlsplit(u).hostname == origin.hostname]
        external = [u for u in links if urlsplit(u).hostname != origin.hostname]

        forms = self._normalize_forms(parser.forms, final_url)
        tech = _detect_tech(headers, body, scripts)

        data = {
            "status_code": resp.status_code,
            "final_url": final_url,
            "title": parser.title,
            "headers": headers,
            "tech_stack": tech,
            "links": {"internal": internal, "external": external},
            "forms": forms,
            "scripts": scripts,
            "meta": parser.metas,
        }
        self._log(
            "recon_complete",
            result_summary=(
                f"{len(internal)} internal links, {len(forms)} forms, "
                f"{len(scripts)} scripts, tech={tech}"
            ),
        )
        return ScanResult(scanner=self.name, target=self.target_url, data=data)

    @staticmethod
    def _normalize_urls(raw: list[str], base: str) -> list[str]:
        seen: dict[str, None] = {}
        for href in raw:
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            absolute, _ = urldefrag(urljoin(base, href))
            if absolute.startswith(("http://", "https://")):
                seen.setdefault(absolute, None)
        return list(seen)

    @staticmethod
    def _normalize_forms(forms: list[dict], base: str) -> list[dict]:
        out: list[dict] = []
        for form in forms:
            action_abs, _ = urldefrag(urljoin(base, form["action"] or base))
            out.append(
                {
                    "action": action_abs,
                    "method": form["method"],
                    "inputs": form["inputs"],
                }
            )
        return out


__all__ = ["ReconScanner"]
