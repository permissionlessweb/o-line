# Firewall tests
#
#   just test firewall all         — unit + integration
#   just test firewall unit        — no-infra unit tests
#   just test firewall integration — Docker compose pfSense stack
#   just test firewall e2e         — pfSense SSH setup e2e
#   just test firewall bootstrap   — pfSense bootstrap e2e

import '../helpers.just'

set working-directory := "../../.."

# All firewall tests (unit + integration)
all: unit integration

# Unit tests (no infrastructure required)
unit:
    cargo test --lib firewall

# Docker integration (starts/stops compose stack)
integration: _require-docker
    #!/usr/bin/env bash
    set -euo pipefail
    docker compose -f docker/pfsense-e2e/docker-compose.yml up -d --build --wait
    cargo test --test firewall_bootstrap -- --nocapture --ignored --test-threads=1; rc=$?
    docker compose -f docker/pfsense-e2e/docker-compose.yml down
    exit $rc

# pfSense SSH setup e2e
e2e:
    PFSENSE_E2E_MODE=local tests/e2e/tests/pfsense_ssh_setup.sh

# pfSense bootstrap e2e
bootstrap:
    tests/e2e/tests/pfsense_bootstrap.sh
