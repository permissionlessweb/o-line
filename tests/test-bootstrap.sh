#!/usr/bin/env bash
# plays/tests/test-bootstrap.sh
#
# End-to-end test for `oline bootstrap` using a local Docker container.
# Builds the oline binary, starts a cosmos-omnibus container with SSH,
# and exercises the full bootstrap workflow via CLI flags — no interactive prompts.
#
# After building, an alias is set so `oline` is callable just like a native binary:
#   alias oline="<repo>/target/debug/oline"
#
# Standalone (full test + cleanup):
#   plays/tests/test-bootstrap.sh
#
# Source to just set the alias after building:
#   source plays/tests/test-bootstrap.sh --alias-only
#
# Optional env:
#   OMNIBUS_IMAGE           default: ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic
#   SSH_TEST_P           default: 2222
#   CONTAINER_NAME          default: oline-bootstrap-test
#   NODE_HOME               default: /root/.terpd
#   OLINE_BINARY_NAME       default: terpd
#   OLINE_PERSISTENT_PEERS  default: public Terp mainnet peers
#   SKIP_SNAP           default: 1 (set to 0 to test real snapshot download)
#   OLINE_SNAP_BASE_URL      only used when SKIP_SNAP=0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OLINE_BIN="${REPO_ROOT}/target/debug/oline"
WORK_DIR="/tmp/oline-bootstrap-test"

# ── Config ────────────────────────────────────────────────────────────────────
OMNIBUS_IMAGE="${OMNIBUS_IMAGE:-ghcr.io/akash-network/cosmos-omnibus:v1.2.42-generic}"
SSH_TEST_P="${SSH_TEST_P:-2222}"
CONTAINER_NAME="${CONTAINER_NAME:-oline-bootstrap-test}"
NODE_HOME="${NODE_HOME:-/root/.terpd}"
OLINE_BINARY_NAME="${OLINE_BINARY_NAME:-terpd}"
SKIP_SNAP="${SKIP_SNAP:-1}"

# Public Terp mainnet peers (from lib.rs default)
export OLINE_PERSISTENT_PEERS="${OLINE_PERSISTENT_PEERS:-5bf887027701d3b8c4d95c0ba898cc8bf6d166ff@188.165.194.110:26676,58e01ab84eb931a82a024324520021d2e075ec67@185.16.39.125:29656,fafb76ea47967a229d092d7ffb0d9957a4254667@94.130.138.48:33656,6f3677c65945ddb6946cbdaa6ec74b4cfec737f8@65.108.232.168:37656,06a68cd28f6b57768c950af7f2ba37b4d8bd7f5e@142.132.248.253:65532,3e04cc80b4647c9ff652d75b0cb12cb6fc36f5d4@46.4.23.120:13656}"

# Ensure snapshot env vars don't trigger auto-resolve unless explicitly set
if [ "${SKIP_SNAP}" = "1" ]; then
    unset OLINE_SNAP_BASE_URL        2>/dev/null || true
    unset OLINE_SNAP_STATE_URL  2>/dev/null || true
    unset OLINE_SNAP_BASE_URL   2>/dev/null || true
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
_pass() { echo "  [PASS] $*"; }
_fail() { echo "  [FAIL] $*" >&2; exit 1; }
_info() { echo "  $*"; }
_section() { echo ""; echo "========================================"; echo "  $*"; echo "========================================"; }

# ── Alias mode ───────────────────────────────────────────────────────────────
# When sourced with --alias-only, build and set alias, then return.
if [[ "${1:-}" == "--alias-only" ]]; then
    _section "Building oline binary"
    (cd "${REPO_ROOT}" && cargo build -p oline 2>&1)
    # shellcheck disable=SC2139
    alias oline="${OLINE_BIN}"
    _info "alias oline -> ${OLINE_BIN}"
    _info "Run: oline bootstrap --help"
    return 0 2>/dev/null || exit 0
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────
for tool in docker cargo ssh-keygen ssh; do
    command -v "$tool" >/dev/null 2>&1 || _fail "Required tool not found: $tool"
done

# ── Build ────────────────────────────────────────────────────────────────────
_section "Building oline binary"
(cd "${REPO_ROOT}" && cargo build -p oline 2>&1) || _fail "cargo build failed"

# Set alias so oline is callable just like a native go binary
# shellcheck disable=SC2139
alias oline="${OLINE_BIN}"
_info "alias oline -> ${OLINE_BIN}"

# ── Cleanup on exit ───────────────────────────────────────────────────────────
_cleanup() {
    _info "Cleaning up..."
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
    rm -rf "${WORK_DIR}"
}
trap _cleanup EXIT

# ── Generate SSH keypair ──────────────────────────────────────────────────────
_section "Setting up test environment"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"
SSH_KEY="${WORK_DIR}/id_ed25519"
ssh-keygen -t ed25519 -f "${SSH_KEY}" -N "" -q
SSH_PUBKEY="$(cat "${SSH_KEY}.pub")"
chmod 600 "${SSH_KEY}"
_info "SSH keypair: ${SSH_KEY}"

# ── Start container ───────────────────────────────────────────────────────────
_section "Starting container: ${CONTAINER_NAME}"
_info "Image: ${OMNIBUS_IMAGE}"
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
docker run -d \
    --name "${CONTAINER_NAME}" \
    -e SSH_PUBKEY="${SSH_PUBKEY}" \
    -e BINARY="${OLINE_BINARY_NAME}" \
    -e MONIKER="oline-test" \
    -e DOWNLOAD_SNAP=0 \
    -e DOWNLOAD_GENESIS=0 \
    -p "${SSH_TEST_P}:22" \
    "${OMNIBUS_IMAGE}"

# ── Wait for SSH ──────────────────────────────────────────────────────────────
_info "Waiting for SSH on 127.0.0.1:${SSH_TEST_P}..."
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o BatchMode=yes -p ${SSH_TEST_P}"
TIMEOUT=120
ELAPSED=0
until ssh ${SSH_OPTS} root@127.0.0.1 'echo ok' >/dev/null 2>&1; do
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    if [ $ELAPSED -ge $TIMEOUT ]; then
        docker logs "${CONTAINER_NAME}" 2>&1 | tail -30
        _fail "SSH did not become ready after ${TIMEOUT}s"
    fi
    _info "  ...waiting (${ELAPSED}s / ${TIMEOUT}s)"
done
_pass "SSH ready"

# ── Ensure minimal node home structure ───────────────────────────────────────
# The omnibus image may have already initialized the node; if not, create stubs.
# ssh -n: do not read stdin (avoids consuming oline's stdin)
ssh -n ${SSH_OPTS} root@127.0.0.1 "
    mkdir -p '${NODE_HOME}/config' '${NODE_HOME}/data'
    if [ ! -f '${NODE_HOME}/config/config.toml' ]; then
        printf '[p2p]\npersistent_peers = \"\"\n' > '${NODE_HOME}/config/config.toml'
        echo '  created minimal config.toml'
    else
        # Make sure persistent_peers key exists so sed can patch it
        if ! grep -q 'persistent_peers' '${NODE_HOME}/config/config.toml'; then
            echo 'persistent_peers = \"\"' >> '${NODE_HOME}/config/config.toml'
            echo '  appended persistent_peers to config.toml'
        else
            echo '  config.toml OK'
        fi
    fi
"

# ── Run: oline bootstrap (SSH mode) ──────────────────────────────────────────
_section "Running: oline bootstrap"
_info "Host: 127.0.0.1  Port: ${SSH_TEST_P}"
_info "Peers: ${OLINE_PERSISTENT_PEERS}"
_info "Snapshot: $([ "${SKIP_SNAP}" = "1" ] && echo 'skip' || echo "${OLINE_SNAP_BASE_URL:-auto-resolve}")"
echo ""

SNAPSHOT_FLAG=""
if [ "${SKIP_SNAP}" = "0" ] && [ -n "${OLINE_SNAP_BASE_URL:-}" ]; then
    SNAPSHOT_FLAG="--snapshot ${OLINE_SNAP_BASE_URL}"
fi

# stdin closed (</dev/null) so read_input falls back to flag/env defaults
"${OLINE_BIN}" bootstrap \
    --host 127.0.0.1 \
    --port "${SSH_TEST_P}" \
    --key  "${SSH_KEY}" \
    --binary "${OLINE_BINARY_NAME}" \
    --home "${NODE_HOME}" \
    --peers "${OLINE_PERSISTENT_PEERS}" \
    --yes \
    ${SNAPSHOT_FLAG} \
    </dev/null

# ── Verify ────────────────────────────────────────────────────────────────────
_section "Verifying bootstrap results"

# 1. persistent_peers set in config.toml
PEERS_LINE="$(ssh -n ${SSH_OPTS} root@127.0.0.1 \
    "grep 'persistent_peers' '${NODE_HOME}/config/config.toml' 2>/dev/null || true")"
FIRST_PEER="${OLINE_PERSISTENT_PEERS%%,*}"   # e.g. 5bf887...@host:port

if echo "${PEERS_LINE}" | grep -qF "${FIRST_PEER}"; then
    _pass "persistent_peers set correctly in config.toml"
else
    _info "config.toml line: ${PEERS_LINE}"
    _fail "persistent_peers NOT updated. Expected to contain: ${FIRST_PEER}"
fi

# 2. data directory exists (was cleared and re-created)
DATA_EXISTS="$(ssh -n ${SSH_OPTS} root@127.0.0.1 \
    "[ -d '${NODE_HOME}/data' ] && echo yes || echo no")"
if [ "${DATA_EXISTS}" = "yes" ]; then
    _pass "data directory exists"
else
    _fail "data directory missing after bootstrap"
fi

# 3. If snapshot was requested, check data dir is non-empty
if [ "${SKIP_SNAP}" = "0" ] && [ -n "${OLINE_SNAP_BASE_URL:-}" ]; then
    DATA_CONTENTS="$(ssh -n ${SSH_OPTS} root@127.0.0.1 \
        "ls '${NODE_HOME}/data' 2>/dev/null | wc -l | tr -d ' '")"
    if [ "${DATA_CONTENTS}" -gt 0 ]; then
        _pass "snapshot data extracted (${DATA_CONTENTS} entries in data/)"
    else
        _fail "data directory is empty after snapshot extraction"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  All checks passed!"
echo "========================================"
echo ""
echo "  To use oline like a native binary in your current shell:"
echo "    alias oline='${OLINE_BIN}'"
echo ""
echo "  Or source this script with --alias-only:"
echo "    source plays/tests/test-bootstrap.sh --alias-only"
echo ""
