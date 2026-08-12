# CSAO — Cloud Security Assessment Orchestrator

CSAO is a read-only AWS security assessment platform. It runs a set of
collector tools against an AWS account (inventory, misconfiguration checks,
IAM risk analysis, resource-relationship mapping), turns the results into
findings, threats, and attack paths, and presents all of it through a
browser console — without ever making a write/mutating call against the
target AWS account.

## Architecture

```
┌─────────────────────────┐        ┌──────────────────────────────┐
│   React SPA (built)     │        │      FastAPI (workbench)     │
│   served at  /app        ├───────►│  serves API + SPA + old UI    │
└─────────────────────────┘        │  http://localhost:2909        │
                                    └───────────┬───────────────────┘
                                                │
                        ┌───────────────────────┼───────────────────────┐
                        ▼                       ▼                       ▼
                ┌──────────────┐       ┌──────────────┐        ┌──────────────┐
                │  PostgreSQL   │       │    Redis      │        │    Neo4j      │
                │  app state    │       │  job queue    │        │  Cartography  │
                └──────────────┘       └──────┬───────┘        │  graph data   │
                                               │                 └──────────────┘
                                               ▼
                                    ┌──────────────────────┐
                                    │  worker (Docker)      │
                                    │  ARQ job consumer      │
                                    │  runs the actual scans │
                                    │  (Prowler, Steampipe,   │
                                    │  Cloudsplaining,        │
                                    │  Cartography, AWS CLI) │
                                    └──────────────────────┘
```

- **Backend**: FastAPI + SQLAlchemy, PostgreSQL for all persistent state
  (accounts, users, sessions, assessments, findings, tool status).
- **Job queue**: ARQ (async Redis-backed queue). Both the CLI path
  (`main.py`) and the web-triggered path submit through the same
  orchestrator, so a scan behaves identically either way.
- **Worker**: a separate Docker container (`worker` service) that consumes
  ARQ jobs and actually invokes the collector tools. This is the only
  process that needs Prowler/Steampipe/Cloudsplaining/Cartography/AWS CLI
  installed — see [Collector tools](#collector-tools) below.
- **Frontend**: a React + TypeScript SPA (Vite, shadcn/ui, Tailwind,
  TanStack Query). It is **not** a separate running service — it's built
  once (`npm run build`, or automatically inside the `web` Docker image)
  into static files that the FastAPI backend serves directly at `/app`.
  There is no separate frontend port.
- **`web`**: an optional Docker service running the exact same FastAPI app
  as native `workbench.serve`, with the frontend pre-built into the image
  — see [Getting started](#getting-started). Native `workbench.serve` and
  the `web` container are two ways to run the same code, not two
  different things; use whichever fits (native for fast edit-and-reload
  iteration, `web` for a from-scratch clone with nothing installed).
- **Graph store**: Neo4j, used by Cartography to store AWS resource
  relationships (who-can-reach-what style analysis).

## Ports

| What | Where |
|---|---|
| **Backend + API + frontend SPA** | `http://localhost:2909` (override with `CSAO_PORT`) |
| React SPA | `http://localhost:2909/app` — same port, served as static files by the backend |
| Legacy server-rendered UI | `http://localhost:2909/` |
| PostgreSQL | `localhost:5432` |
| Redis | `localhost:6379` |
| Neo4j browser | `http://localhost:7474`, Bolt on `7687` |
| Adminer (DB browser) | `http://localhost:8081` |

The web app (`workbench.serve`) picks a working port automatically if
`2909` is taken and prints which port it actually bound to — it will not
kill or fight anything already listening.

## Getting started

### Option A: one command (recommended for a fresh clone)

Requires only Docker + Docker Compose installed — nothing else. Builds and
starts everything: Postgres, Redis, Neo4j, the worker (with every
collector tool baked in), and the web app itself (with the React SPA
pre-built into the image).

```bash
./install.sh
```

Open **http://localhost:2909/app** — the first visit walks you through
creating the admin account. No native Python/Node setup, no manual tool
installation, no separate build step.

### Option B: native web app + Docker infra (for active development)

Faster iteration on backend/frontend code (edit and refresh, no image
rebuild), at the cost of needing Python/Node installed on the host.

```bash
docker compose up -d postgres redis neo4j worker

python3 -m venv venv
venv/bin/python -m pip install -r requirements-dev.txt
venv/bin/python -m alembic upgrade head

cd frontend && npm install && npm run build && cd ..

venv/bin/python -m workbench.serve
```

Open **http://localhost:2909/app**.

### CLI path (no browser needed, either option)

```bash
venv/bin/python main.py
```

Goes through the same assessment orchestrator as a web-triggered scan.

## Collector tools

| Tool | Purpose | Where it runs |
|---|---|---|
| AWS CLI | account/session validation | worker (Docker) |
| Prowler | AWS security/compliance checks | worker (Docker) |
| Steampipe (`aws` plugin) | SQL-queryable AWS resource inventory | worker (Docker) |
| Cloudsplaining | IAM policy risk analysis | worker (Docker) |
| Cartography | AWS resource relationship graph → Neo4j | worker (Docker) |
| IAM Access Analyzer | AWS-native, no install needed | AWS API |

All five installable tools are baked into the `worker` Docker image — you
do not install anything by hand. Anyone who runs `docker compose up -d
worker` gets a fully capable scanner. Tool availability is checked once
per worker startup and shown live in the console under **Admin → Trust
Center**, along with the exact IAM permission matrix each tool uses and
CSAO's read-only guarantee.

Steampipe specifically refuses to run as root; the image handles this with
a dedicated unprivileged user and a wrapper so no application code needs
to know about it — see `MIGRATION_LEDGER.md` for the detail.

## Project structure

- `workbench/` — FastAPI app: HTTP routes, JSON API, auth, ARQ worker entry point
- `core/` — assessment engine, schemas, reporting
- `modules/` — collector runners (Prowler, Steampipe, Cloudsplaining, Cartography, AWS CLI)
- `frontend/` — React/TypeScript SPA source (built into `frontend/dist`, served at `/app`)
- `queries/` — Steampipe SQL queries
- `config/` — runtime and tool configuration (`config/config.yaml`)
- `docker-compose.yml` / `Dockerfile` — Postgres, Redis, Neo4j, Adminer, and the worker image
- `MIGRATION_LEDGER.md` — dated log of the architecture history and every bug found/fixed along the way

## Security model

- Every collector is restricted to read-only AWS API calls (`List*`,
  `Get*`, `Describe*`), plus `sts:GetCallerIdentity` / `sts:AssumeRole`
  where cross-account access is used.
- CSAO never creates, modifies, or deletes AWS resources, IAM policies, or
  infrastructure of any kind during an assessment.
- Startup validation blocks any collector configuration that would need
  write access.
- The full permission matrix (which IAM action each collector needs and
  why) is visible in-app at **Admin → Trust Center**.

## Configuration

Copy `.env.example` (or set directly) — required for local runs:

```
DATABASE_URL=postgresql+asyncpg://csao:<password>@localhost:5432/csao
DATABASE_URL_SYNC=postgresql+psycopg://csao:<password>@localhost:5432/csao
REDIS_URL=redis://localhost:6379/0
CSAO_DB_PASSWORD=<password>
```

Tool and module configuration (which collectors are enabled, AWS regions,
thread count, Neo4j connection) lives in `config/config.yaml`.
