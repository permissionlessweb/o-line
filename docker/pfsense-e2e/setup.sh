#!/usr/bin/env bash
# Start the pfSense mock Docker stack and wait for health.
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Starting pfSense mock stack..."
docker compose -f "$COMPOSE_DIR/docker-compose.yml" up -d --build --wait

echo "==> Stack ready."
echo "    pfSense mock: ssh admin@127.0.0.1 -p 2222 (password: pfsense)"
echo "    Mock API:     http://127.0.0.1:8880/status"
