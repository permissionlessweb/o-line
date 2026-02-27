#!/usr/bin/env bash
# plays/tests/e2e.sh
#
# One-command runner for the O-Line E2E TLS workflow test.
# Validates prerequisites, exports env, then delegates to `cargo test`.
#
# Usage:
#   OMNIBUS_IMAGE=ghcr.io/akash-network/cosmos-omnibus:v0.5.0-terp-v2.0.0 \
#   CHAIN_JSON=https://raw.githubusercontent.com/cosmos/chain-registry/master/terp/chain.json \
#   plays/tests/e2e.sh
#
# Required env:
#   OMNIBUS_IMAGE   — cosmos-omnibus Docker image to test against
#   CHAIN_JSON      — URL to chain.json (cosmos chain-registry format)
#
# Optional env (default to feat/tls branch scripts):
#   ENTRYPOINT_URL  — URL to oline-entrypoint.sh (wrapper downloaded into container)
#   TLS_CONFIG_URL  — URL to tls-setup.sh (runs nginx TLS setup after certs arrive)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OLINE_SDL_DIR="$(cd "${SCRIPT_DIR}/../oline-sdl" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
export ENTRYPOINT_URL="${ENTRYPOINT_URL:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/tls/plays/scripts/oline-entrypoint.sh}"
export TLS_CONFIG_URL="${TLS_CONFIG_URL:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/tls/plays/scripts/tls-setup.sh}"

# ── Resolve env vars (support OLINE_* names from the .env file) ──────────────
# CHAIN_JSON may come directly or via the deployer's OLINE_CHAIN_JSON key
CHAIN_JSON="${CHAIN_JSON:-${OLINE_CHAIN_JSON:-}}"
export CHAIN_JSON

# ── Validate required env ─────────────────────────────────────────────────────
if [ -z "${OMNIBUS_IMAGE:-}" ]; then
    echo "ERROR: OMNIBUS_IMAGE is required."
    echo ""
    echo "  Example:"
    echo "    OMNIBUS_IMAGE=ghcr.io/akash-network/cosmos-omnibus:v0.5.0-terp-v2.0.0 \\"
    echo "    CHAIN_JSON=https://raw.githubusercontent.com/cosmos/chain-registry/master/terp/chain.json \\"
    echo "    $0"
    exit 1
fi

if [ -z "${CHAIN_JSON:-}" ]; then
    echo "ERROR: CHAIN_JSON is required."
    echo ""
    echo "  Example:"
    echo "    CHAIN_JSON=https://raw.githubusercontent.com/cosmos/chain-registry/master/terp/chain.json"
    exit 1
fi

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

echo "========================================"
echo "  O-Line E2E TLS Workflow Test"
echo "========================================"
echo "  OMNIBUS_IMAGE:  ${OMNIBUS_IMAGE}"
echo "  CHAIN_JSON:     ${CHAIN_JSON}"
echo "  ENTRYPOINT_URL: ${ENTRYPOINT_URL}"
echo "  TLS_CONFIG_URL: ${TLS_CONFIG_URL}"
echo ""

# ── Run ───────────────────────────────────────────────────────────────────────
cd "${OLINE_SDL_DIR}"
exec cargo test \
    -p o-line-sdl \
    --test e2e_workflow \
    -- --nocapture --test-threads=1
