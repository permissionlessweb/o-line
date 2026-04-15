#!/bin/bash
# plays/tests/test-tls-nginx.sh
#
# Tests that tls-setup.sh's nginx config rendering works correctly:
#   - The main template uses a glob include (no fragile sed uncomment)
#   - Per-service templates render with correct values
#   - No `ssl` directive leaks into listen lines
#   - nginx -t passes on the assembled config (requires nginx installed)
#
# Usage:
#   plays/tests/test-tls-nginx.sh
#   NGINX_TEMPLATES=/custom/path plays/tests/test-tls-nginx.sh

set -e

PASS=0; FAIL=0

ok()   { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
section() { echo ""; echo "=== $* ==="; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NGINX_TEMPLATES="${NGINX_TEMPLATES:-$REPO_ROOT/plays/flea-flicker/nginx}"

# ── workspace ────────────────────────────────────────────────────────────────
WORK_DIR=$(mktemp -d /tmp/tls-nginx-test.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT
CONF_D="$WORK_DIR/conf.d"
NGINX_CONF="$WORK_DIR/nginx.conf"
mkdir -p "$CONF_D"

# ── 1. main template uses glob include ───────────────────────────────────────
section "1. nginx main template structure"

TEMPLATE="$NGINX_TEMPLATES/template"
[ -f "$TEMPLATE" ] || { echo "ERROR: template not found at $TEMPLATE"; exit 1; }

if grep -qE 'include[[:space:]]+.*/\*\.conf' "$TEMPLATE"; then
    ok "main template uses glob include (*.conf)"
else
    fail "main template does NOT use a glob include — found:"
    grep 'include' "$TEMPLATE" | sed 's/^/    /'
fi

if grep -q '^[[:space:]]*#[[:space:]]*include' "$TEMPLATE"; then
    fail "main template still has commented-out include lines (should be removed)"
else
    ok "main template has no commented-out includes"
fi

cp "$TEMPLATE" "$NGINX_CONF"

# ── 2. RPC template rendering ────────────────────────────────────────────────
section "2. RPC template rendering"

RPC_TMPL="$NGINX_TEMPLATES/rpc"
[ -f "$RPC_TMPL" ] || { fail "rpc template not found"; }

if [ -f "$RPC_TMPL" ]; then
    export RPC_D="rpc.example.com" RPC_P="26657"
    envsubst '$RPC_D,$RPC_P' < "$RPC_TMPL" > "$CONF_D/rpc.conf"

    grep -q "server_name rpc.example.com" "$CONF_D/rpc.conf" \
        && ok "RPC: server_name rendered" \
        || fail "RPC: server_name not rendered (got: $(grep 'server_name' "$CONF_D/rpc.conf"))"

    grep -q "server 127.0.0.1:26657" "$CONF_D/rpc.conf" \
        && ok "RPC: upstream port rendered" \
        || fail "RPC: upstream port not rendered"

    grep -qE 'listen[[:space:]]+80[^;]*;' "$CONF_D/rpc.conf" \
        && ok "RPC: listen 80 present" \
        || fail "RPC: listen 80 missing"

    if grep -qE 'listen[[:space:]]+.*ssl' "$CONF_D/rpc.conf"; then
        fail "RPC: 'ssl' found in listen directive — must not be present (Akash ingress handles TLS)"
    else
        ok "RPC: no ssl in listen directive"
    fi

    # Verify no unreplaced template variables remain
    if grep -qE '\$\{RPC_(D|P)\}' "$CONF_D/rpc.conf"; then
        fail "RPC: unreplaced template variable remains in rendered conf"
    else
        ok "RPC: all template variables substituted"
    fi
fi

# ── 3. API template rendering ────────────────────────────────────────────────
section "3. API template rendering"

API_TMPL="$NGINX_TEMPLATES/api"
[ -f "$API_TMPL" ] || { fail "api template not found"; }

if [ -f "$API_TMPL" ]; then
    export API_D="api.example.com" API_P="1317"
    envsubst '$API_D,$API_P' < "$API_TMPL" > "$CONF_D/api.conf"

    grep -q "server_name api.example.com" "$CONF_D/api.conf" \
        && ok "API: server_name rendered" \
        || fail "API: server_name not rendered"

    grep -q "server 127.0.0.1:1317" "$CONF_D/api.conf" \
        && ok "API: upstream port rendered" \
        || fail "API: upstream port not rendered"

    if grep -qE 'listen[[:space:]]+.*ssl' "$CONF_D/api.conf"; then
        fail "API: 'ssl' found in listen directive"
    else
        ok "API: no ssl in listen directive"
    fi
fi

# ── 4. gRPC template rendering ───────────────────────────────────────────────
section "4. gRPC template rendering"

GRPC_TMPL="$NGINX_TEMPLATES/grpc"
[ -f "$GRPC_TMPL" ] || { fail "grpc template not found"; }

if [ -f "$GRPC_TMPL" ]; then
    export GRPC_D="grpc.example.com" GRPC_P="9090"
    export TLS_CERT="/tmp/tls/cert.pem" TLS_KEY="/tmp/tls/privkey.pem"
    envsubst '$GRPC_D,$GRPC_P,$TLS_CERT,$TLS_KEY' < "$GRPC_TMPL" > "$CONF_D/grpc.conf"

    grep -q "server_name grpc.example.com" "$CONF_D/grpc.conf" \
        && ok "gRPC: server_name rendered" \
        || fail "gRPC: server_name not rendered"

    grep -q "grpc://127.0.0.1:9090" "$CONF_D/grpc.conf" \
        && ok "gRPC: upstream port rendered" \
        || fail "gRPC: upstream port not rendered"

    # gRPC uses NodePort TLS (not Akash HTTP ingress) — must have ssl + http2
    grep -qE 'listen[[:space:]]+9091[[:space:]]+ssl' "$CONF_D/grpc.conf" \
        && ok "gRPC: listen 9091 ssl" \
        || fail "gRPC: missing 'listen 9091 ssl'"

    grep -qE 'http2[[:space:]]+on' "$CONF_D/grpc.conf" \
        && ok "gRPC: http2 on" \
        || fail "gRPC: missing 'http2 on'"

    grep -q "ssl_certificate.*cert.pem" "$CONF_D/grpc.conf" \
        && ok "gRPC: ssl_certificate rendered" \
        || fail "gRPC: ssl_certificate not rendered"
fi

# ── 5. glob include activates rendered files ─────────────────────────────────
section "5. glob include picks up rendered conf files"

# Replace the absolute /etc/nginx/conf.d path with our test path so nginx -t
# can validate the assembled config without being installed system-wide.
sed "s|/etc/nginx/conf.d/|$CONF_D/|g" "$NGINX_CONF" > "$WORK_DIR/nginx-test.conf"

if grep -q "$CONF_D" "$WORK_DIR/nginx-test.conf"; then
    ok "test nginx.conf references our test conf.d directory"
else
    fail "path substitution failed in test nginx.conf"
fi

if command -v nginx > /dev/null 2>&1; then
    if nginx -t -c "$WORK_DIR/nginx-test.conf" 2>&1; then
        ok "nginx -t passes on assembled config (rpc + api + grpc)"
    else
        fail "nginx -t FAILED — see output above"
    fi

    # Test partial config: only RPC configured
    rm -f "$CONF_D/api.conf" "$CONF_D/grpc.conf"
    if nginx -t -c "$WORK_DIR/nginx-test.conf" 2>&1; then
        ok "nginx -t passes with only RPC configured"
    else
        fail "nginx -t FAILED with only RPC conf"
    fi
else
    echo "  [SKIP] nginx not installed — skipping nginx -t validation"
    echo "         Install nginx to enable config syntax checks."
fi

# ── summary ──────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────"
if [ $FAIL -eq 0 ]; then
    echo "  RESULT: $PASS passed, 0 failed — all good"
else
    echo "  RESULT: $PASS passed, $FAIL FAILED"
fi
echo "────────────────────────────────────────────────"
[ $FAIL -eq 0 ]
