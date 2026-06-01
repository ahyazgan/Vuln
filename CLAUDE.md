# CLAUDE.md — VulnScan AI

> **This file is the project constitution.** Architecture decisions and security
> constraints marked **LOCKED** must not be changed without explicit human
> discussion. When writing code, treat the rules here as binding contracts, not
> suggestions. If a request conflicts with a LOCKED rule, surface the conflict
> before proceeding.

---

## 1. Project Overview

**VulnScan AI** is an autonomous, AI-powered security vulnerability scanner
platform. It accepts a **target URL + scope** from an authenticated user, runs
**multi-layer security scans** in background workers, sends the **raw scan data
to Claude** for analysis, and returns **prioritized, CVSS-scored vulnerability
reports**.

The platform is a bug-bounty marketplace: companies define programs and scope,
hackers run AI-assisted scans against in-scope targets, and the platform brokers
findings, reports, and payouts.

### User types

| Role        | Capabilities |
|-------------|--------------|
| **Hacker**  | Submits targets within an authorized program scope, runs scans, receives AI-assisted findings, submits findings for bounty review. |
| **Company** | Defines a bounty program (scope + reward table), receives reports, reviews and accepts/rejects submissions, pays rewards. |
| **Admin**   | Manages the platform: tenants, users, plans, abuse, global config. |

### Authorization & ethics (read first)

This is a **defensive / authorized-testing** platform. Every scan is gated by an
explicit, company-defined scope whitelist. The system **must never** be capable
of scanning targets that are not explicitly authorized by a `BountyProgram`.
Scope enforcement is a security control, not a convenience — see §7.

---

## 2. Architecture Decisions — **LOCKED**

These are fixed. Do not change without discussion.

1. **All scan jobs run async via Celery.** The API never blocks on a scan. A
   `POST /scans` returns immediately with a job id; work happens in workers.
2. **Claude analysis always receives structured context**, never bare blobs.
   Every analysis call includes: target URL, detected technology stack, raw
   scan output, and previous findings for the same target if any exist.
3. **Severity is always one of:** `Critical / High / Medium / Low / Info`, and
   every finding **always carries a CVSS 3.1 score**. No finding ships without
   both a severity label and a numeric CVSS score.
4. **Scans are strictly scope-limited.** Only domains/paths explicitly
   whitelisted by the Company's `BountyProgram` may be requested. Every URL is
   validated against scope *before* any network request leaves the worker.
5. **Never store actual user data from target systems.** Persist only
   vulnerability *metadata* (what was found, where, how). Never persist scraped
   PII, response bodies containing user data, credentials, or session contents
   from the target.
6. **Multi-tenant isolation:** every DB query **must** filter by `tenant_id`.
   There are no cross-tenant reads. This is enforced at the repository/query
   layer, not left to callers to remember.

---

## 3. Folder Structure

```
vulnscan/
  api/            # FastAPI routes, auth, dependencies
    routes/       #   scans.py, programs.py, submissions.py, webhooks.py
    auth.py
  workers/        # Celery app + scan pipeline tasks
  scanners/       # Individual scan modules (base, recon, http, js, form_fuzzer)
  ai/             # Claude analysis engine + prompt chains
    chains/       #   one file per analysis chain
    engine.py     #   single entry point for ALL Claude calls
    prompts.py    #   all system prompts as constants
  domain/         # Models, Pydantic schemas, enums
  db.py           # async SQLAlchemy engine + get_db dependency
  main.py         # FastAPI app entrypoint
  tests/          # pytest — one test file per module
  frontend/       # Next.js 14 (App Router)
```

Mirror this layout. New scan logic goes in `scanners/`, new AI logic in `ai/`,
new HTTP surface in `api/routes/`. Cross-cutting domain types live in `domain/`.

---

## 4. Scan Pipeline — exact order

Scans run as an ordered Celery chain. Each step persists intermediate results to
Redis keyed by `scan_id`; the final step writes findings to PostgreSQL.

1. **Recon** — load target, build sitemap, detect tech stack, discover endpoints
   (links, forms, external JS, headers, meta).
2. **Surface mapping** — prioritize risky endpoints (auth flows, forms, admin
   paths, file uploads) for active testing.
3. **Active testing** — form fuzzing (XSS/SQLi probes), security header
   analysis, auth-flow inspection. Rate-limited and strictly scope-checked.
4. **Claude analysis** — structured prompt chain per finding category
   (headers, JS secrets, XSS, etc.). Raw evidence in, structured findings out.
5. **Chain analysis** — combine individual (often Low) findings into multi-step
   attack paths with a combined, usually higher, severity.
6. **Report generation** — produce CVSS-scored findings with PoC steps and fix
   recommendations; assemble executive + technical report; emit webhook.

`scan_level` (1–6) on a `ScanJob` selects how far down this pipeline to run.

---

## 5. Claude Prompt Rules — **LOCKED**

1. **Base system prompt** (used for the primary analysis persona):
   > "You are a senior penetration tester and security researcher. Analyze the
   > following data and identify security vulnerabilities. Be precise, avoid
   > false positives, assign CVSS 3.1 scores."
2. **Always output structured JSON.** Every finding conforms to:
   ```json
   {
     "severity": "critical|high|medium|low|info",
     "title": "string",
     "description": "string",
     "cvss_score": 0.0,
     "proof_of_concept": "string",
     "recommendation": "string",
     "references": ["string"]
   }
   ```
   Parse with Pydantic. **Never trust raw model text** — if JSON parsing fails,
   retry with a repair prompt, then drop the result rather than ship garbage.
3. **Never hallucinate vulnerabilities.** Report only what the supplied evidence
   supports. When evidence is ambiguous, prefer Info/Low or omit.
4. **Chain-analysis prompt must explicitly list every individual finding** (with
   ids) and ask Claude to identify multi-step attack paths that combine them.
5. **All system prompts live in `ai/prompts.py`** as named constants — never
   inline a system prompt inside a chain file.
6. **Model:** the AI engine uses Claude Sonnet (`claude-sonnet-4-20250514`) for
   analysis chains. The model id is configured in one place (`ai/engine.py` /
   settings), never scattered.

---

## 6. Coding Standards

- **All scan modules inherit from `BaseScanner(ABC)`** in
  `scanners/base.py` and implement `async def run() -> ScanResult`.
- **All Claude calls go through `ai/engine.py`.** Routes, workers, and chains
  never instantiate `anthropic.AsyncAnthropic` directly.
- **Every external call** (Playwright, httpx, Anthropic) has a **timeout** and a
  **retry with exponential backoff**. Defaults: 30s per-operation timeout,
  max 2 retries with 2s base backoff for scanners; engine retries on rate limit.
- **Structured logging on every scan step**, minimum fields:
  `{scan_id, step, target, timestamp, result_summary}`. Use structured (JSON)
  log records, not f-string prose.
- **Scanners never raise unhandled exceptions.** Catch, log, and return partial
  results with an `error` flag so the pipeline degrades gracefully.
- **Async everywhere** in the request/scan path (FastAPI async routes, async
  SQLAlchemy, async httpx, async Playwright).
- **Type hints required** on all public functions; Pydantic v2 for all schemas.
- **Tests required** for every scanner module and every AI chain. One test file
  per module under `tests/`.

---

## 7. Security Constraints — **NON-NEGOTIABLE / LOCKED**

1. **Rate limit: max 1 concurrent scan per tenant.** `run_scan` checks for an
   already-running scan for the same `tenant_id` and queues rather than runs a
   second one concurrently.
2. **Scope enforcement:** validate **every** URL against the company whitelist
   (`BountyProgram.scope_domains`) **before any request is made**. An
   out-of-scope URL raises `ScopeViolationError` and is never requested.
3. **No credentials stored in the scanner.** Use short-lived tokens only; never
   persist long-lived secrets in scanner code, config, or scan state.
4. **All scan results encrypted at rest.** Findings and any sensitive scan
   metadata are encrypted in the database / storage layer.
5. **Audit-log every scan:** who (user/tenant), what target, when, and what was
   found. Audit records are append-only.
6. **No target user data persisted** (restates §2.5): only vulnerability
   metadata is stored, never the target's actual user/session/PII data.

---

## 8. Tech Stack Reference

| Concern              | Choice |
|----------------------|--------|
| Backend API          | FastAPI (async) |
| Task queue           | Celery + Redis (broker & result backend) |
| Database             | PostgreSQL + SQLAlchemy (async) + Alembic |
| Browser automation   | Playwright (async) |
| HTTP client          | httpx (async) |
| AI engine            | Anthropic Claude API (`claude-sonnet-4-20250514`) |
| Frontend             | Next.js 14 (App Router) |
| Auth                 | JWT, multi-tenant (access + refresh tokens) |
| Payments             | Stripe |
| Tests                | pytest + pytest-asyncio |

---

## 9. Definition of Done (per change)

- Conforms to all **LOCKED** rules in §2, §5, §7.
- Every DB query filters by `tenant_id`.
- Every external call has timeout + retry.
- New scanner/chain has a matching test file.
- Structured logging present on new scan steps.
- No secrets, no target PII, persisted.
