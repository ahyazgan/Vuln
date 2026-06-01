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

🚧 Early development. The domain layer, scanners, AI engine, worker pipeline,
and API are being implemented per the roadmap in `CLAUDE.md`.
