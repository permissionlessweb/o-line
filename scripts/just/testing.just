# ── Test Suite ────────────────────────────────────────────────────────────────
#
# Structured as nested subcommands:
#
#   just test unit                  — cargo unit tests (no infra)
#   just test nginx                 — nginx template validation
#   just test all                   — everything that needs no infrastructure
#   just test full                  — the whole enchilada
#
#   just test ssh plumbing          — 6-node SSH/SFTP plumbing
#   just test ssh offline-bootstrap — OLINE_OFFLINE with ict-rs chain
#   just test ssh network           — full local network
#
#   just test akash all             — all Akash tests
#   just test akash deploy          — core deploy lifecycle
#   just test akash trusted         — trusted-provider auto-selection
#   just test akash fallback        — direct-mode auto-default
#   just test akash benchmark       — HD-funded parallel benchmark
#   just test akash tls             — single-container TLS workflow
#   just test akash query           — query API only
#
#   just test firewall unit         — no-infra unit tests
#   just test firewall integration  — Docker compose pfSense stack
#   just test firewall e2e          — pfSense SSH setup
#   just test firewall bootstrap    — pfSense bootstrap
#
#   just test vpn unit              — no-infra unit tests
#   just test vpn e2e               — Docker mock pfSense + wg-client
#
#   just test testnet render         — SDL template rendering (no infra)
#   just test testnet deploy         — full Akash deploy lifecycle
#   just test testnet all            — all testnet tests
#
#   just test registry unit          — pure-logic unit tests (no Docker)
#   just test registry integration   — registry server + Docker import
#   just test registry e2e           — deploy to local Akash with registry image
#   just test registry all           — all registry tests
#
#   just test sites all             — all sites tests
#   just test sites docker          — S3→IPFS round-trip
#   just test sites akash           — deploy to local Akash
#   just test sites minio           — build + test minio-ipfs image

import 'helpers.just'

# Run recipes from the project root, not scripts/just/
set working-directory := "../.."

# ── Submodules ──────────────────────────────────────────────────────────────

mod ssh    'testing/ssh.just'
mod akash  'testing/akash.just'
mod testnet 'testing/testnet.just'
mod firewall 'testing/firewall.just'
mod vpn    'testing/vpn.just'
mod sites    'testing/sites.just'
mod registry 'testing/registry.just'

# ── Aggregates ───────────────────────────────────────────────────────────────

# Show all available test recipes
list:
    #!/usr/bin/env bash
    just --list --list-submodules 2>/dev/null | sed -n '/test:/,$ p'

# All no-infra tests (unit + nginx + envcheck + testnet render + firewall unit + vpn unit)
all: unit nginx envcheck testnet-render
    cargo test --lib firewall
    cargo test --lib vpn

# Full suite — requires Docker + Akash devnet
full: all ssh-all akash-all testnet-all firewall-all vpn-all sites-all registry-all

# ── Shortcut aliases (invoke submodule aggregates) ───────────────────────────

[private]
ssh-all:
    just test ssh all

[private]
akash-all:
    just test akash all

[private]
testnet-all:
    just test testnet all

[private]
testnet-render:
    just test testnet render

[private]
firewall-all:
    just test firewall all

[private]
vpn-all:
    just test vpn all

[private]
sites-all:
    just test sites all

[private]
registry-all:
    just test registry all

# ── Unit / No-Infra ─────────────────────────────────────────────────────────

# Cargo unit tests (no infrastructure required)
unit:
    cargo test --features testing --lib --bins

# Nginx template validation (no Docker required)
nginx:
    bash tests/test-tls-nginx.sh

# Cross-file env var consistency (FD naming, refresh vars, nginx templates)
envcheck:
    cargo test --features testing --test env_var_consistency
