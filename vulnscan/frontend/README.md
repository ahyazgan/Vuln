# VulnScan AI — Frontend

Next.js 14 (App Router) frontend for the VulnScan AI platform. It talks to the
FastAPI backend over the JSON API at `/api/v1`.

## Setup

```bash
cp .env.example .env.local   # point NEXT_PUBLIC_API_BASE_URL at the backend
npm install
npm run dev                  # http://localhost:3000
```

The backend must be running (default `http://localhost:8000`):

```bash
# from the repo root
uvicorn vulnscan.main:app --reload
```

## Scripts

| Script          | Purpose                          |
|-----------------|----------------------------------|
| `npm run dev`   | Dev server with hot reload       |
| `npm run build` | Production build                 |
| `npm run start` | Serve the production build       |
| `npm run lint`  | ESLint (`next/core-web-vitals`)  |

## Layout

```
app/
  login, register/        # auth screens
  dashboard/              # role-aware overview
  scans/                  # list, new, [id] detail + findings
  programs/               # company: list, new
  submissions/            # hacker submits; company reviews + pays
  payments/               # company: payment history
lib/
  api.ts                  # typed fetch client
  auth.tsx                # AuthProvider (JWT in localStorage, silent refresh)
  useApi.ts               # data-fetching hook
  types.ts                # mirrors backend schemas
components/               # shell (nav + auth guard), shared UI
```

Auth uses the backend's JWT access/refresh pair; tokens are kept in
`localStorage` and the access token is refreshed transparently on a 401.
