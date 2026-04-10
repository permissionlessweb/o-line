# VPN tests
#
#   just test vpn all  — unit + e2e
#   just test vpn unit — no-infra unit tests
#   just test vpn e2e  — Docker mock pfSense + wg-client

import '../helpers.just'

set working-directory := "../../.."

# All VPN tests
all: unit e2e

# Unit tests (no pfSense needed)
unit:
    cargo test --lib vpn

# E2e against Docker mock pfSense + wg-client
e2e: _require-docker
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Starting pfsense-e2e containers..."
    docker compose -f docker/pfsense-e2e/docker-compose.yml up -d --build --wait
    echo "==> Running VPN e2e test..."
    cargo test --test vpn_pfsense -- --nocapture --ignored
    echo "==> VPN e2e test passed."
