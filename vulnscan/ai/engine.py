"""The single entry point for every Claude call (CLAUDE.md §6).

Routes, workers, and analysis chains never instantiate ``anthropic.AsyncAnthropic``
directly — they go through :class:`AnalysisEngine`. The engine:

* Pins the model id in ONE place (``MODEL``, CLAUDE.md §5.6) and configures
  timeout + automatic rate-limit/5xx retry with exponential backoff (the SDK's
  built-in ``max_retries``; CLAUDE.md §6).
* Always sends structured context, never a bare blob: every call includes the
  target URL, detected tech stack, raw scan evidence, and any previous findings
  for the same target (CLAUDE.md §2.2), assembled by :meth:`_build_user_message`.
* Caches the stable base system prompt and appends a volatile per-category
  prompt after it (CLAUDE.md §5.5 + prompt-caching prefix rules).
* Never trusts raw model text: it parses the JSON array, validates each item
  with Pydantic, and on a parse failure retries once with a repair prompt, then
  drops the result rather than shipping garbage (CLAUDE.md §5.2).

The Anthropic client is created lazily so importing this module never requires
``ANTHROPIC_API_KEY`` (safe for tests/CLI); tests inject a fake client.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, TypeVar

from pydantic import BaseModel, Field, ValidationError

from vulnscan.ai.prompts import BASE_SYSTEM_PROMPT, REPAIR_PROMPT
from vulnscan.domain.schemas import FindingBase

logger = logging.getLogger("vulnscan.ai")

# Pinned in ONE place (CLAUDE.md §5.6). NOTE: claude-sonnet-4-20250514 is the
# constitution-locked analysis model; change it here and nowhere else.
MODEL = os.getenv("VULNSCAN_CLAUDE_MODEL", "claude-sonnet-4-20250514")

DEFAULT_MAX_TOKENS = 4096
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_RETRIES = 4  # SDK retries 429/5xx with exponential backoff

T = TypeVar("T", bound=BaseModel)


class AnalysisContext(BaseModel):
    """Structured context attached to every analysis call (CLAUDE.md §2.2).

    The engine refuses to send a bare evidence blob — these fields are folded
    into every prompt so Claude always sees the target, its stack, and the
    findings already known for it.
    """

    target_url: str
    tech_stack: list[str] = Field(default_factory=list)
    # Compact dicts (e.g. {"title","severity","cvss_score"}) of prior findings
    # for this same target, so analysis is incremental rather than blind.
    previous_findings: list[dict] = Field(default_factory=list)


class AnalysisEngine:
    """Wraps the Anthropic client and turns raw evidence into validated findings."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        model: str = MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._client = client
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max_retries

    # -- client lifecycle -------------------------------------------------- #
    def _ensure_client(self) -> Any:
        if self._client is None:
            # Lazy import + construct: no network or API key needed at import.
            import anthropic

            self._client = anthropic.AsyncAnthropic(
                timeout=self.timeout, max_retries=self.max_retries
            )
        return self._client

    # -- public API -------------------------------------------------------- #
    async def analyze(
        self,
        *,
        system: str,
        evidence_label: str,
        evidence: Any,
        context: AnalysisContext,
        schema: type[T] = FindingBase,  # type: ignore[assignment]
    ) -> list[T]:
        """Run one analysis call and return validated findings.

        ``system`` is the per-category focus prompt (the base persona/contract is
        prepended and cached automatically). ``evidence`` is the raw scanner
        output for this category; ``schema`` is the Pydantic model each returned
        object is validated against (defaults to :class:`FindingBase`; chain
        analysis passes an extended schema).

        Never raises on bad model output: a non-JSON response is repaired once,
        then dropped to ``[]`` (CLAUDE.md §5.2). Individual items that fail
        schema validation are skipped, not fatal.
        """
        user = self._build_user_message(evidence_label, evidence, context)

        text = await self._complete(system, user)
        items = _parse_json_array(text)
        if items is None:
            # One repair attempt, then drop rather than ship garbage (§5.2).
            logger.warning(json.dumps({"engine": "analyze", "event": "json_parse_failed_retrying"}))
            repaired = await self._complete(system, REPAIR_PROMPT + text)
            items = _parse_json_array(repaired)
            if items is None:
                logger.error(
                    json.dumps({"engine": "analyze", "event": "json_unrecoverable_dropped"})
                )
                return []

        return self._validate(items, schema)

    # -- internals --------------------------------------------------------- #
    async def _complete(self, system: str, user_text: str) -> str:
        """One Anthropic call. Base prompt cached; category prompt appended."""
        system_blocks: list[dict] = [
            {
                "type": "text",
                "text": BASE_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},  # stable, reused → cache (§5.5)
            }
        ]
        if system:
            system_blocks.append({"type": "text", "text": system})

        resp = await self._ensure_client().messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_blocks,
            messages=[{"role": "user", "content": user_text}],
        )
        return _text_of(resp)

    @staticmethod
    def _build_user_message(evidence_label: str, evidence: Any, context: AnalysisContext) -> str:
        """Fold the §2.2 mandatory context around the raw evidence."""
        tech = ", ".join(context.tech_stack) if context.tech_stack else "unknown"
        prev = (
            json.dumps(context.previous_findings, default=str, indent=2)
            if context.previous_findings
            else "None."
        )
        evidence_json = json.dumps(evidence, default=str, indent=2)
        return (
            f"Target URL: {context.target_url}\n"
            f"Detected technology stack: {tech}\n\n"
            f"Previous findings for this target:\n{prev}\n\n"
            f"{evidence_label}:\n```json\n{evidence_json}\n```\n"
        )

    @staticmethod
    def _validate(items: list, schema: type[T]) -> list[T]:
        out: list[T] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                out.append(schema.model_validate(item))
            except ValidationError as exc:
                logger.warning(
                    json.dumps(
                        {"engine": "analyze", "event": "finding_dropped", "error": str(exc)},
                        default=str,
                    )
                )
        return out


# --------------------------------------------------------------------------- #
# Response helpers
# --------------------------------------------------------------------------- #
def _text_of(response: Any) -> str:
    """Concatenate the text content blocks of a Messages response."""
    parts: list[str] = []
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text" or hasattr(block, "text"):
            parts.append(getattr(block, "text", ""))
    return "".join(parts)


def _parse_json_array(text: str) -> list | None:
    """Best-effort parse of a JSON array from model text.

    Tolerates surrounding prose or markdown fences by slicing from the first
    ``[`` to the last ``]``. Returns the list on success, or ``None`` if no
    valid JSON array could be parsed (the caller then repairs or drops).
    """
    if not text:
        return None
    stripped = text.strip()
    # Strip a ```json ... ``` or ``` ... ``` fence if present.
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1]
        if stripped.rstrip().endswith("```"):
            stripped = stripped.rstrip()[:-3]
    start = stripped.find("[")
    end = stripped.rfind("]")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        parsed = json.loads(stripped[start : end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, list) else None


__all__ = [
    "MODEL",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_TIMEOUT",
    "DEFAULT_MAX_RETRIES",
    "AnalysisContext",
    "AnalysisEngine",
]
