#!/usr/bin/env bash
# pfSense SSH Bootstrap E2E Test
#
# Modes:
#   local (default) — uses Docker mock pfSense container
#   live            — uses a real pfSense box
#
# Usage:
#   PFSENSE_E2E_MODE=local ./pfsense_ssh_setup.sh
#   PFSENSE_E2E_MODE=live PFSENSE_LIVE_HOST=192.168.1.1 PFSENSE_LIVE_PASSWORD=secret ./pfsense_ssh_setup.sh
#
# Env vars:
#   PFSENSE_E2E_MODE     — "local" (Docker, default) or "live" (real pfSense)
#   PFSENSE_LIVE_HOST    — IP for live mode
#   PFSENSE_LIVE_USER    — username for live mode (default: admin)
#   PFSENSE_LIVE_PASSWORD — password for live mode
#   PFSENSE_SSH_P     — SSH port (default: 22 for live, 2222 for local)

set -euo pipefail

MODE="${PFSENSE_E2E_MODE:-local}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/pfsense-e2e/docker-compose.yml"
PASS=0
FAIL=0

_pass() { PASS=$((PASS+1)); echo "  PASS: $1"; }
_fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

echo "══════════════════════════════════════════════════════════════"
echo "  pfSense SSH Bootstrap E2E (mode: $MODE)"
echo "══════════════════════════════════════════════════════════════"

# ── Phase 1: Setup ──────────────────────────────────────────────────────────

echo -e "\n── Phase 1: Setup ──"

if [ "$MODE" = "local" ]; then
    HOST="127.0.0.1"
    PORT="${PFSENSE_SSH_P:-2222}"
    USER="admin"
    PASSWORD="pfsense"

    echo "  Starting Docker mock pfSense..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" up -d --build --wait
    _pass "Docker stack started"
elif [ "$MODE" = "live" ]; then
    HOST="${PFSENSE_LIVE_HOST:?PFSENSE_LIVE_HOST required for live mode}"
    PORT="${PFSENSE_SSH_P:-22}"
    USER="${PFSENSE_LIVE_USER:-admin}"
    PASSWORD="${PFSENSE_LIVE_PASSWORD:?PFSENSE_LIVE_PASSWORD required for live mode}"
    _pass "Live mode configured: $USER@$HOST:$PORT"
else
    echo "  ERROR: Unknown mode '$MODE'. Use 'local' or 'live'."
    exit 1
fi

# Verify sshpass is available
if command -v sshpass &>/dev/null; then
    _pass "sshpass found"
else
    _fail "sshpass not found"
    echo "  Install: brew install hudochenkov/sshpass/sshpass (macOS)"
    exit 1
fi

# Verify SSH connectivity with password
echo "  Testing SSH connectivity..."
for i in $(seq 1 20); do
    if sshpass -p "$PASSWORD" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=3 \
        -p "$PORT" "${USER}@${HOST}" \
        "echo ok" 2>/dev/null | grep -q ok; then
        _pass "SSH password auth works"
        break
    fi
    [ "$i" -eq 20 ] && { _fail "SSH connectivity check"; exit 1; }
    sleep 1
done

# ── Phase 2: Bootstrap ──────────────────────────────────────────────────────

echo -e "\n── Phase 2: Bootstrap ──"

SECRETS_DIR=$(mktemp -d)
export SECRETS_PATH="$SECRETS_DIR"
export OLINE_NON_INTERACTIVE=1
export PFSENSE_HOST="$HOST"
export PFSENSE_PASSWORD="$PASSWORD"
export PFSENSE_SSH_P="$PORT"
export PFSENSE_USER="$USER"

echo "  Running: oline firewall bootstrap --label e2e-test"
if "$REPO_ROOT/target/debug/oline" firewall bootstrap --label e2e-test 2>&1; then
    _pass "oline firewall bootstrap succeeded"
else
    _fail "oline firewall bootstrap failed"
fi

# ── Phase 3: Verify SSH ────────────────────────────────────────────────────

echo -e "\n── Phase 3: Verify SSH ──"

KEY_FILE="$SECRETS_DIR/e2e-test-ssh-key"
if [ -f "$KEY_FILE" ]; then
    _pass "SSH key file exists: $KEY_FILE"
else
    _fail "SSH key file missing: $KEY_FILE"
fi

if [ -f "$KEY_FILE" ]; then
    echo "  Testing key-based SSH..."
    if ssh -i "$KEY_FILE" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        -p "$PORT" "${USER}@${HOST}" \
        "echo key-auth-ok" 2>/dev/null | grep -q "key-auth-ok"; then
        _pass "Key-based SSH auth works"
    else
        _fail "Key-based SSH auth failed"
    fi
fi

# ── Phase 4: Verify Store ──────────────────────────────────────────────────

echo -e "\n── Phase 4: Verify Store ──"

STORE_FILE="$SECRETS_DIR/firewalls.enc"
if [ -f "$STORE_FILE" ]; then
    _pass "Encrypted store exists: $STORE_FILE"
    SIZE=$(wc -c < "$STORE_FILE")
    if [ "$SIZE" -gt 10 ]; then
        _pass "Store file has content ($SIZE bytes)"
    else
        _fail "Store file too small ($SIZE bytes)"
    fi
else
    _fail "Encrypted store missing"
fi

# ── Phase 5: Cleanup ───────────────────────────────────────────────────────

echo -e "\n── Phase 5: Cleanup ──"

rm -rf "$SECRETS_DIR"
_pass "Temp secrets cleaned up"

if [ "$MODE" = "local" ]; then
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null
    _pass "Docker stack stopped"
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo -e "\n══════════════════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ]
