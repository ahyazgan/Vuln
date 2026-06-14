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

### Running the stack locally

```bash
# 1. Postgres + Redis (any local install or container), then migrate the schema:
export DATABASE_URL=postgresql+asyncpg://vulnscan:vulnscan@127.0.0.1:5432/vulnscan
alembic upgrade head

# 2. API (returns immediately on POST /scans; the scan runs in the worker):
uvicorn vulnscan.main:app --reload

# 3. Worker (use --pool=solo locally; each task runs in its own event loop):
celery -A vulnscan.workers.app:celery_app worker --pool=solo -l info
```

Config is read from the environment — see `.env.example` for every variable
(database, Redis/Celery, JWT, webhook, Anthropic, Stripe).

### Live verification

Two manual harnesses exercise the real wiring (beyond the unit suite):

| Script | What it proves |
|--------|----------------|
| `scripts/smoke_live.py`     | API/auth/scope/audit over the production app (SQLite, no services needed). |
| `scripts/live_pipeline.py`  | The **full level-6 pipeline** against real Postgres + Redis: scanners → AI chains (fake Claude client, no key needed) → findings + chained findings persisted, six steps in Redis. |

```bash
# live_pipeline.py needs Postgres + Redis up and an in-scope HTTP target:
python -m http.server 8099 --bind 127.0.0.1 &      # a throwaway in-scope target
DATABASE_URL=postgresql+asyncpg://vulnscan:vulnscan@127.0.0.1:5432/vulnscan \
REDIS_URL=redis://localhost:6379/0 TARGET_URL=http://127.0.0.1:8099/ \
PYTHONPATH=. python scripts/live_pipeline.py
```

> **Worker note:** every Celery task runs in a fresh event loop (`asyncio.run`),
> so the worker uses a dedicated `NullPool` engine and a single-loop
> acquire→run→release lock cycle — pooled DB/Redis clients must never be reused
> across loops.
