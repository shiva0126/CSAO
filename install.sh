#!/bin/bash
###############################################################################
# CSAO -- one-command deploy.
#
# Requires only Docker + Docker Compose on the host. Everything else --
# Postgres, Redis, Neo4j, the web app, the React SPA build, and every
# collector tool (AWS CLI, Prowler, Steampipe, Cloudsplaining, Cartography)
# -- is built and started by `docker compose`. Nothing installs onto the
# host machine itself.
#
# Superseded install.sh from before the Docker migration: that version
# apt-installed tools directly onto the host (Ubuntu/apt-only, and doesn't
# match the current architecture where collector tools live inside the
# `worker` container, not on the host). See MIGRATION_LEDGER.md.
###############################################################################

set -euo pipefail

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

success() { echo -e "${GREEN}[OK]${NC} $1"; }
info()    { echo -e "${YELLOW}[..]${NC} $1"; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

command -v docker >/dev/null 2>&1 || fail "Docker is required. Install it from https://docs.docker.com/get-docker/ and re-run this script."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required (bundled with current Docker Desktop/Engine)."
success "Docker and Docker Compose found."

if [ ! -f .env ]; then
    info "No .env found -- generating one with a fresh database password."
    DB_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))' 2>/dev/null || openssl rand -base64 24 | tr -d '/+=' )"
    cat > .env <<EOF
DATABASE_URL_SYNC=postgresql+psycopg://csao:${DB_PASSWORD}@localhost:5432/csao
REDIS_URL=redis://localhost:6379/0
CSAO_DB_PASSWORD=${DB_PASSWORD}
EOF
    success ".env created."
else
    success ".env already exists -- leaving it as is."
fi

info "Building and starting Postgres, Redis, Neo4j, the web app, and the worker (this installs all collector tools inside the worker/web images on first run -- can take several minutes)..."
docker compose up -d --build

info "Waiting for the web app to become reachable on port 2909..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:2909/health >/dev/null 2>&1; then
        success "CSAO is up."
        echo
        echo "Open http://localhost:2909/app -- first visit creates the admin account."
        exit 0
    fi
    sleep 3
done

fail "Web app did not become healthy within 3 minutes. Check: docker compose logs web"
