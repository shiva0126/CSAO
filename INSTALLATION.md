# Installation Guide

For a fresh clone with nothing installed, run `./install.sh` from the repo
root instead of anything below — it builds and starts everything (Postgres,
Redis, Neo4j, the worker with every collector tool, and the web app) via
Docker Compose alone. See `README.md`.

The steps below are for native development instead (faster edit-and-reload
iteration, at the cost of needing Python/Node installed on the host).

## Requirements

- Python 3.12
- Docker + Docker Compose (for Postgres/Redis/Neo4j/the worker)
- A writable local workspace
- Optional external tools for full evidence collection: `aws`, `prowler`, `cloudsplaining`, `steampipe`, `cartography` — installed automatically inside the `worker` Docker image, not needed on the host

## Setup

```bash
docker compose up -d postgres redis neo4j worker

python3 -m venv venv
venv/bin/python -m pip install -r requirements-dev.txt
venv/bin/python -m alembic upgrade head
```

## Launch

Workbench:

```bash
venv/bin/python -m workbench.serve
```

CLI pipeline:

```bash
venv/bin/python main.py
```

## Notes

- The project virtual environment is the supported runtime.
- The CLI can run in degraded mode when AWS credentials or optional collector binaries are not available.
- Cloud account credentials are stored encrypted in PostgreSQL; the encryption key itself lives locally at `output/workbench/.secret.key` (`output/workbench/.secret.keys.json` after a key rotation).
