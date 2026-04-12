#!/usr/bin/env bash
# tests/e2e.sh
#
# O-Line E2E test runner.
#
# Two test suites:
#
#   single  — Single-container TLS workflow test (e2e_workflow).
#             Starts one cosmos-omnibus container, pushes TLS certs via SFTP,
#             verifies cert delivery, signals node start. Fast (~2 min).
#
#   multi   — Multi-node Phase A test (local_phase_a).
#             Starts snapshot + seed containers, runs the full Phase A workflow:
#             cert delivery → start signal → peer ID polling.
#             Validates the exact code paths used against Akash providers. Slower (~15 min).
#
# Usage:
#   # Single-container TLS test (default):
#   OMNIBUS_IMAGE=ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic \
#   CHAIN_JSON=https://raw.githubusercontent.com/cosmos/chain-registry/master/terp/chain.json \
#   tests/e2e.sh
#
#   # Multi-node Phase A test:
#   OMNIBUS_IMAGE=ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic \
#   CHAIN_JSON=https://raw.githubusercontent.com/cosmos/chain-registry/master/terp/chain.json \
#   tests/e2e.sh --multi
#
#   # Run both suites sequentially:
#   tests/e2e.sh --all
#
# Required env:
#   OMNIBUS_IMAGE   — cosmos-omnibus Docker image tag
#   CHAIN_JSON      — URL to chain.json (cosmos chain-registry format)
#
# Optional env:
#   ENTRYPOINT_URL  — URL to oline-entrypoint.sh (defaults to master branch)
#   TLS_CONFIG_URL  — URL to tls-setup.sh (defaults to master branch)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Container cleanup ──────────────────────────────────────────────────────────
# Well-known container names used by each test suite.
_SINGLE_CONTAINERS=(oline-e2e-test)
_MULTI_CONTAINERS=(oline-test-snapshot oline-test-seed)
_ALL_CONTAINERS=("${_SINGLE_CONTAINERS[@]}" "${_MULTI_CONTAINERS[@]}")

_cleanup_containers() {
    local names=("$@")
    for name in "${names[@]}"; do
        docker rm -f "$name" >/dev/null 2>&1 || true
    done
}

# Trap: always remove containers when the script exits (normal, error, or signal).
trap '_cleanup_containers "${_ALL_CONTAINERS[@]}"' EXIT INT TERM

# Pre-run cleanup: remove any leftover containers from a previous interrupted run.
_cleanup_containers "${_ALL_CONTAINERS[@]}"

# ── Parse args ────────────────────────────────────────────────────────────────
MODE="single"
case "${1:-}" in
    --multi)  MODE="multi"  ;;
    --all)    MODE="all"    ;;
    --single) MODE="single" ;;
    "")       MODE="single" ;;
    *)
        echo "ERROR: Unknown argument: ${1}"
        echo "Usage: $0 [--single|--multi|--all]"
        exit 1
        ;;
esac

# ── Defaults ──────────────────────────────────────────────────────────────────
export ENTRYPOINT_URL="${ENTRYPOINT_URL:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/audible/oline-entrypoint.sh}"
export TLS_CONFIG_URL="${TLS_CONFIG_URL:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/audible/tls-setup.sh}"

# CHAIN_JSON may come directly or via the deployer's OLINE_CHAIN_JSON key
CHAIN_JSON="${CHAIN_JSON:-${OLINE_CHAIN_JSON:-}}"
export CHAIN_JSON

# CHAIN_ID may come directly or via the deployer's OLINE_CHAIN_ID key
CHAIN_ID="${CHAIN_ID:-${OLINE_CHAIN_ID:-}}"
export CHAIN_ID

# ── Validate required env ─────────────────────────────────────────────────────
if [ -z "${OMNIBUS_IMAGE:-}" ]; then
    echo "ERROR: OMNIBUS_IMAGE is required."
    echo ""
    echo "  Example:"
    echo "    OMNIBUS_IMAGE=ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic \\"
    echo "    CHAIN_JSON=https://raw.githubusercontent.com/cosmos/chain-registry/master/terp/chain.json \\"
    echo "    $0 [--single|--multi|--all]"
    exit 1
fi

# CHAIN_JSON is optional — the test pushes templates/json/chain.json via SFTP.
# Only validate it if explicitly set (a bad URL is worse than no URL).

# ── Validate prerequisites ────────────────────────────────────────────────────
missing_tools=()
for cmd in docker openssl ssh-keygen cargo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_tools+=("$cmd")
    fi
done

if [ "${#missing_tools[@]}" -gt 0 ]; then
    echo "ERROR: Required tools not found: ${missing_tools[*]}"
    echo "  Install the missing tools and re-run."
    exit 1
fi

# ── Header ────────────────────────────────────────────────────────────────────
echo "========================================"
echo "  O-Line E2E Test Runner (mode: ${MODE})"
echo "========================================"
echo "  OMNIBUS_IMAGE:  ${OMNIBUS_IMAGE}"
echo "  CHAIN_ID:       ${CHAIN_ID:-"(not set — using templates/json/chain.json default)"}"
echo "  CHAIN_JSON:     ${CHAIN_JSON:-"(not set — using local /tmp/chain.json via SFTP)"}"
echo "  ENTRYPOINT_URL: ${ENTRYPOINT_URL}"
echo "  TLS_CONFIG_URL: ${TLS_CONFIG_URL:-"(not set — using local /tmp/tls-setup.sh)"}"
echo ""

cd "${REPO_ROOT}"

# ── Test functions ────────────────────────────────────────────────────────────

run_single() {
    echo "────────────────────────────────────────"
    echo "  Suite: single-container TLS workflow"
    echo "  Test:  e2e_workflow"
    echo "────────────────────────────────────────"
    cargo test \
        -p o-line-sdl \
        --test e2e_workflow \
        -- --nocapture --test-threads=1
    echo ""
    echo "  [single] PASSED"
}

run_multi() {
    echo "────────────────────────────────────────"
    echo "  Suite: multi-node Phase A"
    echo "  Test:  local_phase_a"
    echo ""
    echo "  Starts snapshot + seed containers and runs:"
    echo "    1. SFTP cert delivery to both nodes"
    echo "    2. SSH start signal to both nodes"
    echo "    3. Peer ID polling (RPC /status)"
    echo "────────────────────────────────────────"
    cargo test \
        -p o-line-sdl \
        --test local_phase_a \
        -- --nocapture --test-threads=1
    echo ""
    echo "  [multi] PASSED"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

case "${MODE}" in
    single)
        run_single
        ;;
    multi)
        run_multi
        ;;
    all)
        run_single
        echo ""
        run_multi
        echo ""
        echo "========================================"
        echo "  All suites PASSED"
        echo "========================================"
        ;;
esac
