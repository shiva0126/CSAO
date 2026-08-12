#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${SERVICE_NAME:-csao}"
SERVICE_SRC="$ROOT_DIR/deploy/systemd/csao.service"
SERVICE_TMP="/tmp/${SERVICE_NAME}.service"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}.service"
RUN_AS_USER="${RUN_AS_USER:-$(id -un)}"
RUN_AS_GROUP="${RUN_AS_GROUP:-$(id -gn)}"

if [[ ! -f "$SERVICE_SRC" ]]; then
    echo "Missing unit file template: $SERVICE_SRC" >&2
    exit 1
fi

sed \
    -e "s|__ROOT_DIR__|$ROOT_DIR|g" \
    -e "s|__RUN_AS_USER__|$RUN_AS_USER|g" \
    -e "s|__RUN_AS_GROUP__|$RUN_AS_GROUP|g" \
    "$SERVICE_SRC" > "$SERVICE_TMP"

sudo install -m 0644 "$SERVICE_TMP" "$SERVICE_DST"
sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"
sudo systemctl status "$SERVICE_NAME" --no-pager
