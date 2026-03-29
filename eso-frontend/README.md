# ESO Frontend

Next.js 14 dashboard for Enterprise Security Orchestrator.

## Setup

```bash
npm install
npm run dev
```

Opens at `http://localhost:3000`. Proxies API calls to `http://localhost:8000`.

## Prerequisites

- Node.js 18+
- ESO backend running on port 8000

## Pages

| Route | Description |
|-------|-------------|
| `/login` | Login / Register |
| `/dashboard` | Stats, recent scans, system health |
| `/scan/new` | Launch a new scan |
| `/scan/[id]` | Live scan progress, workflow, approvals, report |
| `/history` | Scan history table |
| `/settings` | API keys, profile |

## Tech

- Next.js 14 (App Router)
- TypeScript
- Tailwind CSS (glassmorphism design)
- No external UI library — pure Tailwind
