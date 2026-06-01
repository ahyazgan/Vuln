"""HTTP security-header scanner — part of active testing (CLAUDE.md §4.3).

Fetches the target and inspects its response headers for the presence,
absence, and weakness of standard security headers (HSTS, CSP, X-Frame-Options,
…), plus information-disclosure headers (``Server``, ``X-Powered-By``).

The scanner emits **observations only** — ``present`` / ``missing`` / ``weak``
lists with human-readable notes. It deliberately does not assign severity or a
CVSS score; that is the Claude analysis engine's responsibility (CLAUDE.md §5).
"""

from __future__ import annotations

from vulnscan.scanners.base import BaseScanner, ScanResult

# Recommended minimum HSTS max-age (~6 months) before we flag it as weak.
_MIN_HSTS_MAX_AGE = 15_552_000


class HttpHeaderScanner(BaseScanner):
    """Analyze HTTP response security headers (CLAUDE.md §4.3)."""

    name = "http_headers"

    async def run(self) -> ScanResult:
        resp = await self._get(self.target_url)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        present: list[dict] = []
        missing: list[dict] = []
        weak: list[dict] = []

        self._check_hsts(headers, present, missing, weak)
        self._check_csp(headers, present, missing)
        self._check_simple(
            headers,
            present,
            missing,
            "x-frame-options",
            "Clickjacking protection (X-Frame-Options) is not set.",
        )
        self._check_content_type_options(headers, present, missing, weak)
        self._check_simple(
            headers,
            present,
            missing,
            "referrer-policy",
            "Referrer-Policy is not set; referrer data may leak to third parties.",
        )
        self._check_simple(
            headers,
            present,
            missing,
            "permissions-policy",
            "Permissions-Policy is not set; browser features are not restricted.",
        )

        # Information-disclosure headers (their *presence* is the observation).
        disclosure = [
            {"header": h, "value": headers[h]}
            for h in ("server", "x-powered-by", "x-aspnet-version")
            if h in headers
        ]

        data = {
            "status_code": resp.status_code,
            "scheme": str(resp.url.scheme),
            "present": present,
            "missing": missing,
            "weak": weak,
            "information_disclosure": disclosure,
        }
        self._log(
            "header_analysis_complete",
            result_summary=(
                f"{len(present)} present, {len(missing)} missing, "
                f"{len(weak)} weak, {len(disclosure)} disclosure"
            ),
        )
        return ScanResult(scanner=self.name, target=self.target_url, data=data)

    # -- individual checks ------------------------------------------------- #
    def _check_hsts(self, headers, present, missing, weak) -> None:
        value = headers.get("strict-transport-security")
        if value is None:
            missing.append(
                {
                    "header": "Strict-Transport-Security",
                    "note": "HSTS not set; connection may be downgraded to HTTP.",
                }
            )
            return
        present.append({"header": "Strict-Transport-Security", "value": value})
        max_age = self._parse_max_age(value)
        if max_age is not None and max_age < _MIN_HSTS_MAX_AGE:
            weak.append(
                {
                    "header": "Strict-Transport-Security",
                    "value": value,
                    "note": f"max-age={max_age} is below the recommended "
                    f"{_MIN_HSTS_MAX_AGE} (~6 months).",
                }
            )

    def _check_csp(self, headers, present, missing) -> None:
        value = headers.get("content-security-policy")
        if value is None:
            missing.append(
                {
                    "header": "Content-Security-Policy",
                    "note": "No CSP; injected scripts are unrestricted.",
                }
            )
        else:
            present.append({"header": "Content-Security-Policy", "value": value})

    def _check_content_type_options(self, headers, present, missing, weak) -> None:
        value = headers.get("x-content-type-options")
        if value is None:
            missing.append(
                {
                    "header": "X-Content-Type-Options",
                    "note": "MIME sniffing is not disabled (expected 'nosniff').",
                }
            )
        elif value.strip().lower() != "nosniff":
            weak.append(
                {
                    "header": "X-Content-Type-Options",
                    "value": value,
                    "note": "Expected 'nosniff'.",
                }
            )
        else:
            present.append({"header": "X-Content-Type-Options", "value": value})

    @staticmethod
    def _check_simple(headers, present, missing, header: str, note: str) -> None:
        value = headers.get(header)
        if value is None:
            missing.append({"header": header.title(), "note": note})
        else:
            present.append({"header": header.title(), "value": value})

    @staticmethod
    def _parse_max_age(value: str) -> int | None:
        for part in value.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age"):
                _, _, num = part.partition("=")
                try:
                    return int(num.strip())
                except ValueError:
                    return None
        return None


__all__ = ["HttpHeaderScanner"]
