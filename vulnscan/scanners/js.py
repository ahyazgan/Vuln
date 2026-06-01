"""JavaScript secret scanner — part of Claude-fed evidence collection.

Fetches the in-scope external JavaScript discovered during recon and scans the
source for hard-coded secrets (API keys, tokens, private keys). Each match is
reported as **metadata only**: the pattern name, the file, a line number, and a
*redacted* preview. The raw secret value is never stored or returned in full —
persisting credentials lifted from a target is forbidden (CLAUDE.md §2.5 / §7.3).

Out-of-scope script URLs are skipped (scope is enforced by ``_request``); any
script that fails to fetch is recorded with an ``error`` flag and the scan
continues (CLAUDE.md §6).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from vulnscan.scanners.base import BaseScanner, ScanResult, ScopeViolationError

# (name, compiled pattern). Patterns are intentionally specific to limit false
# positives — Claude makes the final call, but noisy regex wastes its budget.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("stripe_secret_key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{24,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "generic_assigned_secret",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|secret|token|passwd|password|access[_-]?token)\b
            \s*[:=]\s*
            ['"]([0-9A-Za-z\-_./+]{16,})['"]
            """
        ),
    ),
]

# Cap per-file download size so a hostile/huge bundle can't exhaust the worker.
_MAX_JS_BYTES = 2_000_000


def _redact(secret: str) -> str:
    """Return a non-recoverable preview: first 4 chars + length, value dropped."""
    secret = secret.strip()
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{secret[:4]}…[redacted, len={len(secret)}]"


class JsSecretScanner(BaseScanner):
    """Scan external JS for hard-coded secrets (metadata + redacted preview)."""

    name = "js_secrets"

    def __init__(self, *args, script_urls: Iterable[str] | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Optional pre-discovered scripts (from recon). If omitted, the scanner
        # fetches the target and extracts <script src> itself.
        self._script_urls = list(script_urls) if script_urls is not None else None

    async def run(self) -> ScanResult:
        script_urls = self._script_urls
        if script_urls is None:
            script_urls = await self._discover_scripts()

        scanned: list[str] = []
        skipped_out_of_scope: list[str] = []
        errors: list[dict] = []
        matches: list[dict] = []

        for url in script_urls:
            if not self.scope.is_in_scope(url):
                skipped_out_of_scope.append(url)
                continue
            try:
                resp = await self._get(url)
            except ScopeViolationError:
                skipped_out_of_scope.append(url)
                continue
            except Exception as exc:  # one bad script must not abort the scan
                errors.append({"url": url, "error": str(exc)})
                self._log("script_fetch_error", url=url, error=str(exc))
                continue

            scanned.append(url)
            matches.extend(self._scan_source(url, resp.text[:_MAX_JS_BYTES]))

        data = {
            "scripts_scanned": scanned,
            "skipped_out_of_scope": skipped_out_of_scope,
            "fetch_errors": errors,
            "matches": matches,
        }
        self._log(
            "js_scan_complete",
            result_summary=(
                f"{len(scanned)} scripts, {len(matches)} secret matches, "
                f"{len(skipped_out_of_scope)} out-of-scope skipped"
            ),
        )
        return ScanResult(scanner=self.name, target=self.target_url, data=data)

    def _scan_source(self, url: str, source: str) -> list[dict]:
        out: list[dict] = []
        for name, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(source):
                # Group 1 holds the secret value for capturing patterns;
                # otherwise the whole match is the indicator.
                raw = m.group(1) if m.groups() else m.group(0)
                out.append(
                    {
                        "pattern": name,
                        "url": url,
                        "line": source.count("\n", 0, m.start()) + 1,
                        "redacted": _redact(raw),
                    }
                )
        return out

    async def _discover_scripts(self) -> list[str]:
        """Fetch the target and pull absolute <script src> URLs (recon-lite)."""
        from vulnscan.scanners.recon import _SurfaceParser  # local import avoids cycle
        from urllib.parse import urldefrag, urljoin

        resp = await self._get(self.target_url)
        parser = _SurfaceParser()
        try:
            parser.feed(resp.text)
        except Exception as exc:
            self._log("html_parse_warning", error=str(exc))
            return []
        base = str(resp.url)
        seen: dict[str, None] = {}
        for src in parser.scripts:
            absolute, _ = urldefrag(urljoin(base, src))
            if absolute.startswith(("http://", "https://")):
                seen.setdefault(absolute, None)
        return list(seen)


__all__ = ["JsSecretScanner"]
