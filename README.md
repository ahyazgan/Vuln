# VulnScan AI

Autonomous, AI-powered security vulnerability scanner platform.

VulnScan AI accepts a **target URL + scope** from an authenticated user, runs
**multi-layer security scans** in background workers, sends the **raw scan data
to Claude** for analysis, and returns **prioritized, CVSS 3.1-scored
vulnerability reports**. It operates as a bug-bounty marketplace: companies
define programs and scope, hackers run AI-assisted scans against in-scope
targets, and the platform brokers findings, reports, and payouts.

> ⚠️ **Authorized testing only.** Every scan is gated by an explicit,
> company-defined scope whitelist. The platform must never scan targets that are
> not explicitly authorized by a bounty program.

## Architecture

| Concern            | Technology |
|--------------------|------------|
| Backend API        | FastAPI (async) |
| Task queue         | Celery + Redis |
| Database           | PostgreSQL + SQLAlchemy (async) + Alembic |
| Browser automation | Playwright (async) |
| HTTP client        | httpx (async) |
| AI engine          | Anthropic Claude API |
| Frontend           | Next.js 14 (App Router) |
| Auth               | JWT, multi-tenant |
| Payments           | Stripe |

## Scan pipeline

1. **Recon** — sitemap, tech-stack detection, endpoint discovery
2. **Surface mapping** — prioritize risky endpoints
3. **Active testing** — form fuzzing, header analysis, auth-flow inspection
4. **Claude analysis** — structured prompt chain per finding category
5. **Chain analysis** — combine findings into multi-step attack paths
6. **Report generation** — CVSS score, PoC steps, fix recommendations

## Project layout

See [CLAUDE.md](CLAUDE.md) — the project constitution — for the full folder
structure, locked architecture decisions, and non-negotiable security
constraints.

## Status

The backend is feature-complete and tested: domain layer, scanners, AI engine,
the six-step Celery worker pipeline, the HTTP API (auth, programs, scans,
submissions, append-only audit log), and Stripe-backed bounty **payments**. A
Next.js 14 **frontend** (`vulnscan/frontend/`) covers auth, scans, programs,
submissions, and payments.

### Developing

```bash
pip install -e ".[dev]"   # runtime + test + lint tooling
pytest -q                 # backend tests
ruff check . && ruff format --check .

cd vulnscan/frontend && npm install && npm run dev   # frontend
```

CI (`.github/workflows/ci.yml`) runs the backend lint+tests and the frontend
lint+build on every push.
