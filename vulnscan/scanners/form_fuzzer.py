"""Form fuzzer — active testing (CLAUDE.md §4.3).

For each discovered form, submits benign, uniquely-marked XSS and SQLi probe
payloads into its text-like inputs and records observable signals: whether the
payload is **reflected** verbatim in the response, and whether the response
contains a recognizable **SQL error signature**. These are raw indicators only
— confirmation, severity, and CVSS scoring are the Claude engine's job
(CLAUDE.md §5).

Safety properties:
* **Strictly scope-checked.** Every form action is resolved to an absolute URL
  and validated against scope by ``_request`` before any payload is sent
  (CLAUDE.md §7.2). Out-of-scope forms are skipped.
* **Rate-limited.** A configurable delay is awaited between probe requests so
  the scanner does not hammer the target.
* **Non-destructive.** Payloads are detection markers (a unique XSS token, a
  classic boolean SQLi string), never exploitation primitives.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable

from vulnscan.scanners.base import BaseScanner, ScanResult, ScopeViolationError

# Unique, greppable marker so a reflection is unambiguously *our* payload.
_XSS_MARKER = "vulnscan9xss"
_XSS_PAYLOAD = f"<{_XSS_MARKER}>\"'"
_SQLI_PAYLOAD = "' OR '1'='1"

# Input types we do not fuzz (no attacker-controlled free text of interest).
_SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "hidden", "checkbox", "radio"}

# Common SQL error fragments leaked by misconfigured backends.
_SQL_ERROR_SIGNATURES = re.compile(
    r"(?i)(sql syntax|mysql_fetch|ora-\d{5}|psql:|pg_query|"
    r"sqlite3?\.|unclosed quotation mark|odbc sql server driver|"
    r"syntax error at or near|quoted string not properly terminated)"
)


class FormFuzzerScanner(BaseScanner):
    """Probe forms for XSS reflection and SQLi error signatures (CLAUDE.md §4.3)."""

    name = "form_fuzzer"

    def __init__(
        self,
        *args,
        forms: Iterable[dict] | None = None,
        request_delay: float = 0.5,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        # Forms from recon ({action, method, inputs:[{name,type}]}); if omitted
        # the fuzzer discovers them by fetching and parsing the target.
        self._forms = list(forms) if forms is not None else None
        self.request_delay = request_delay

    async def run(self) -> ScanResult:
        forms = self._forms
        if forms is None:
            forms = await self._discover_forms()

        results: list[dict] = []
        skipped_out_of_scope: list[str] = []
        first_probe = True

        for form in forms:
            action = form.get("action") or self.target_url
            if not self.scope.is_in_scope(action):
                skipped_out_of_scope.append(action)
                continue

            params = [
                i["name"]
                for i in form.get("inputs", [])
                if i.get("name") and i.get("type", "text").lower() not in _SKIP_INPUT_TYPES
            ]
            if not params:
                continue

            method = (form.get("method") or "get").lower()
            for param in params:
                for kind, payload in (("xss", _XSS_PAYLOAD), ("sqli", _SQLI_PAYLOAD)):
                    if not first_probe and self.request_delay:
                        await asyncio.sleep(self.request_delay)  # rate limit
                    first_probe = False
                    probe = await self._probe(action, method, params, param, payload, kind)
                    if probe is not None:
                        results.append(probe)

        data = {
            "forms_tested": [f.get("action") for f in forms if f.get("action")],
            "skipped_out_of_scope": skipped_out_of_scope,
            "probes": results,
            "reflected_count": sum(1 for r in results if r.get("reflected")),
            "sql_error_count": sum(1 for r in results if r.get("sql_error")),
        }
        self._log(
            "fuzz_complete",
            result_summary=(
                f"{len(results)} probes, {data['reflected_count']} reflected, "
                f"{data['sql_error_count']} sql-error signatures"
            ),
        )
        return ScanResult(scanner=self.name, target=self.target_url, data=data)

    async def _probe(
        self,
        action: str,
        method: str,
        params: list[str],
        target_param: str,
        payload: str,
        kind: str,
    ) -> dict | None:
        # Fill every field; only the target param carries the payload.
        fields = {p: ("test" if p != target_param else payload) for p in params}
        try:
            if method == "post":
                resp = await self._request("POST", action, data=fields)
            else:
                resp = await self._request("GET", action, params=fields)
        except ScopeViolationError:
            return None
        except Exception as exc:  # a failed probe is logged, not fatal (§6)
            self._log("probe_error", url=action, param=target_param, error=str(exc))
            return {
                "param": target_param,
                "kind": kind,
                "action": action,
                "method": method,
                "error": str(exc),
            }

        body = resp.text
        reflected = _XSS_MARKER in body if kind == "xss" else payload in body
        sql_error = bool(_SQL_ERROR_SIGNATURES.search(body)) if kind == "sqli" else False
        return {
            "param": target_param,
            "kind": kind,
            "action": action,
            "method": method,
            "status_code": resp.status_code,
            "reflected": reflected,
            "sql_error": sql_error,
        }

    async def _discover_forms(self) -> list[dict]:
        from vulnscan.scanners.recon import ReconScanner

        recon = ReconScanner(
            self.target_url,
            self.scope,
            scan_id=self.scan_id,
            client=self._get_client(),
            timeout=self.timeout,
            max_retries=self.max_retries,
            backoff_base=self.backoff_base,
        )
        result = await recon.run()
        return result.data.get("forms", [])


__all__ = ["FormFuzzerScanner"]
