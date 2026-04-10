# Registry tests (unit + integration + e2e)
#
#   just test registry unit         — pure-logic unit tests (no Docker)
#   just test registry integration  — registry server + Docker import round-trip
#   just test registry e2e          — deploy to local Akash with registry image
#   just test registry all          — everything

import '../helpers.just'

set working-directory := "../../.."

# Unit tests — no Docker required
unit:
    cargo test --lib registry

# Integration tests — requires Docker daemon
integration: _require-docker
    cargo test --features testing --test registry_integration -- --nocapture --ignored --test-threads=1

# E2E test — requires Docker + ict-rs chain
e2e: _require-docker
    RUST_LOG=info,akash_deploy_rs=debug,test_provider=debug,ict_rs=debug \
      cargo test --features testing --test registry_e2e -- --nocapture --ignored --test-threads=1

# All registry tests
all: unit integration e2e
