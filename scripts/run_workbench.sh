#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/venv/bin/python}"
UVICORN_BIN="${UVICORN_BIN:-$ROOT_DIR/venv/bin/uvicorn}"
HOST="${CSAO_HOST:-127.0.0.1}"
PORT="${CSAO_PORT:-2909}"
LOG_LEVEL="${CSAO_LOG_LEVEL:-info}"

cd "$ROOT_DIR"

if [[ ! -x "$PYTHON_BIN" ]]; then
    echo "Python executable not found: $PYTHON_BIN" >&2
    echo "Create the virtual environment and install dependencies first." >&2
    exit 1
fi

if [[ ! -x "$UVICORN_BIN" ]]; then
    echo "uvicorn executable not found: $UVICORN_BIN" >&2
    echo "Install dependencies into the virtual environment first." >&2
    exit 1
fi

exec "$UVICORN_BIN" workbench.app:app --host "$HOST" --port "$PORT" --log-level "$LOG_LEVEL"
