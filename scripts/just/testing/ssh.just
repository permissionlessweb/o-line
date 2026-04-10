# SSH/SFTP tests (oline_ssh.rs)
#
#   just test ssh plumbing          — 6-node SSH plumbing (no chain)
#   just test ssh offline-bootstrap — OLINE_OFFLINE with ict-rs chain
#   just test ssh network           — full local network (requires local-terp)
#   just test ssh all               — run all SSH tests

import '../helpers.just'

set working-directory := "../../.."

# All SSH/SFTP tests
all: plumbing offline-bootstrap

# Unified SSH/SFTP plumbing (cosmos-omnibus, no chain required)
plumbing omnibus="": _require-docker
    #!/usr/bin/env bash
    set -euo pipefail
    export OMNIBUS_IMAGE="$(just test ssh _resolve-omnibus "{{omnibus}}")"
    cargo test --features testing --test oline_ssh -- test_oline_ssh_plumbing --nocapture --ignored --test-threads=1

# Full OLINE_OFFLINE bootstrap with ict-rs chain
offline-bootstrap omnibus="": _require-docker
    #!/usr/bin/env bash
    set -euo pipefail
    export OMNIBUS_IMAGE="$(just test ssh _resolve-omnibus "{{omnibus}}")"
    cargo test --features testing --test oline_ssh -- test_oline_ssh_offline_bootstrap --nocapture --ignored --test-threads=1

# Full local network (requires local-terp running)
network omnibus="": _require-docker
    #!/usr/bin/env bash
    set -euo pipefail
    export OMNIBUS_IMAGE="$(just test ssh _resolve-omnibus "{{omnibus}}")"
    ./tests/localterp.sh wait
    cargo test --features testing --test local_network_e2e -- --nocapture --ignored --test-threads=1
