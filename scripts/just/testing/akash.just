# Akash deploy lifecycle tests (oline_akash.rs + akash_query_api.rs)
#
#   just test akash all       — every Akash test
#   just test akash query     — query API only
#   just test akash deploy    — core deploy lifecycle
#   just test akash trusted   — trusted-provider auto-selection
#   just test akash fallback  — direct-mode auto-default
#   just test akash benchmark — HD-funded parallel benchmark
#   just test akash tls       — single-container TLS workflow

import '../helpers.just'

set working-directory := "../../.."

# All Akash tests (query + deploy lifecycle)
all: _require-docker
    cargo test --features testing --test akash_query_api -- --nocapture --ignored
    cargo test --features testing --test oline_akash -- --nocapture --ignored --test-threads=1

# Akash query API only
query: _require-docker
    cargo test --features testing --test akash_query_api -- --nocapture --ignored

# Core deploy lifecycle (fund → deploy → 3 orders/bids/leases)
deploy: _require-docker
    RUST_LOG=info,akash_deploy_rs=debug,test_provider=debug,ict_rs=debug \
      cargo test --features testing --test oline_akash -- test_oline_akash_deploy --nocapture --ignored --test-threads=1

# Trusted-provider auto-selection
trusted: _require-docker
    RUST_LOG=info,akash_deploy_rs=debug,test_provider=debug,ict_rs=debug \
      cargo test --features testing --test oline_akash -- test_oline_akash_trusted_providers --nocapture --ignored --test-threads=1

# Direct-mode auto-default (no OLINE_FUNDING_METHOD)
fallback: _require-docker
    RUST_LOG=info,akash_deploy_rs=debug,test_provider=debug,ict_rs=debug \
      cargo test --features testing --test oline_akash -- test_oline_akash_direct_fallback --nocapture --ignored --test-threads=1

# HD-funded parallel deploy benchmark with container spawning
benchmark omnibus="": _require-docker
    #!/usr/bin/env bash
    set -euo pipefail
    export OMNIBUS_IMAGE="$(just test akash _resolve-omnibus "{{omnibus}}")"
    cargo test --features testing --test oline_akash -- test_oline_akash_benchmark --nocapture --ignored

# Single-container TLS cert delivery + node bootstrap
tls omnibus="": _require-docker
    #!/usr/bin/env bash
    set -euo pipefail
    export OMNIBUS_IMAGE="$(just test akash _resolve-omnibus "{{omnibus}}")"
    cargo test --features testing --test oline_akash -- test_oline_akash_tls_workflow --nocapture --ignored --test-threads=1
