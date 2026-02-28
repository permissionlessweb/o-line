#!/bin/bash
# tls-setup.sh
#
# Sets up nginx reverse-proxy for RPC, API, and/or GRPC services.
# Reads *_DOMAIN + *_PORT env vars (as set by the Akash SDL).
#
# TLS is terminated by the Akash provider's nginx-ingress at port 443.
# Traffic arriving at this nginx instance is already plain HTTP — the nginx
# server blocks do NOT use `ssl`.  The TLS cert + key at $TLS_CERT / $TLS_KEY
# are delivered by oline via SFTP as a startup synchronisation signal; they
# are verified below to confirm delivery succeeded but are NOT loaded by nginx.
#
# NOTE: sshd is started and managed by oline-entrypoint.sh. Do NOT start it here.

set -e
log() { echo "[tls-setup] $*"; }
die() { echo "[tls-setup] ERROR: $*" >&2; exit 1; }

NGINX_CONFIG_TEMPLATES="${NGINX_CONFIG_TEMPLATES:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/tls/plays/flea-flicker/nginx}"

# ── paths ──────────────────────────────────────────────────────────────────────
# Certs are delivered via SFTP to /tmp/tls/ by oline before this script runs.
TLS_CERT="${TLS_CERT:-/tmp/tls/cert.pem}"
TLS_KEY="${TLS_KEY:-/tmp/tls/privkey.pem}"
RENDERED_DIR="${RENDERED_DIR:-/etc/nginx/conf.d}"
NGINX_FULL="${NGINX_FULL:-/etc/nginx/nginx.conf}"

# ── validation ─────────────────────────────────────────────────────────────────
# Services use *_DOMAIN + *_PORT naming (SDL env convention: RPC_DOMAIN, P2P_DOMAIN, etc.)
services="RPC API GRPC"
at_least_one=false
for svc in $services; do
    eval "domain_val=\"\$${svc}_DOMAIN\""
    eval "port_val=\"\$${svc}_PORT\""
    if [ -n "$domain_val" ] && [ -n "$port_val" ]; then
        case "$port_val" in
            ''|*[!0-9]*)
                die "${svc}_PORT must be a numeric value"
                ;;
            *)
                if [ "$port_val" -lt 1 ] || [ "$port_val" -gt 65535 ]; then
                   die "${svc}_PORT $port_val out of range 1-65535"
                fi
                at_least_one=true
                ;;
        esac
    fi
done

if [ "$at_least_one" = false ]; then
    echo "Error: At least one service must have both DOMAIN and PORT set." >&2
    echo "  Services: RPC, API, GRPC" >&2
    echo "Example: RPC_DOMAIN=rpc.example.com RPC_PORT=443 $0" >&2
    exit 1
fi
log "Configuration validated."
[ -n "$RPC_DOMAIN"  ] && [ -n "$RPC_PORT"  ] && log "  RPC:  $RPC_DOMAIN:$RPC_PORT"
[ -n "$API_DOMAIN"  ] && [ -n "$API_PORT"  ] && log "  API:  $API_DOMAIN:$API_PORT"
[ -n "$GRPC_DOMAIN" ] && [ -n "$GRPC_PORT" ] && log "  GRPC: $GRPC_DOMAIN:$GRPC_PORT"

# Verify TLS certs are present (SFTP'd by orchestrator before this script runs)
[ -f "$TLS_CERT" ] || die "TLS cert not found at $TLS_CERT"
[ -f "$TLS_KEY" ]  || die "TLS key not found at $TLS_KEY"
log "TLS cert: $TLS_CERT"
log "TLS key:  $TLS_KEY"

# ── 1. install nginx + gettext ─────────────────────────────────────────────────
log "Installing nginx, gettext..."
if command -v apt-get > /dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq nginx gettext-base curl jq >/dev/null 2>&1
elif command -v apk > /dev/null 2>&1; then
    apk add --no-cache nginx gettext curl jq >/dev/null 2>&1
else
    die "Unsupported package manager (need apt-get or apk)"
fi
mkdir -p "$RENDERED_DIR"

# ── 2. fetch main nginx.conf template ──────────────────────────────────────────
log "Fetching main nginx.conf template..."
MAIN_NGINX_TMPL=$(mktemp /tmp/nginx-main.XXXXXX)
curl -fsSL "${NGINX_CONFIG_TEMPLATES}/template" -o "$MAIN_NGINX_TMPL" \
    || die "Failed to fetch main nginx.conf template"
cp "$MAIN_NGINX_TMPL" "$NGINX_FULL"

# ── 3. fetch + render per-service config templates ─────────────────────────────
log "Rendering per-service nginx configs..."
export TLS_CERT TLS_KEY
for svc in $services; do
    PORT_VAR="${svc}_PORT"
    DOMAIN_VAR="${svc}_DOMAIN"
    port_val=$(printenv "$PORT_VAR" || true)
    domain_val=$(printenv "$DOMAIN_VAR" || true)
    if [ -n "$port_val" ] && [ -n "$domain_val" ]; then
        log "  Configuring $svc ($domain_val:$port_val)"
        # Template filenames and rendered conf names are lowercase (rpc, api, p2p, grpc)
        svc_lower=$(echo "$svc" | tr '[:upper:]' '[:lower:]')
        TEMPLATE_FILE=$(mktemp /tmp/nginx-tmpl."${svc}".XXXXXX)
        curl -fsSL "${NGINX_CONFIG_TEMPLATES}/${svc_lower}" -o "${TEMPLATE_FILE}" \
            || die "Failed to fetch nginx template for ${svc}"
        export "$PORT_VAR=$port_val" "$DOMAIN_VAR=$domain_val"
        RENDERED_CONF="${RENDERED_DIR}/${svc_lower}.conf"
        VARS='$'"${PORT_VAR}"',$'"${DOMAIN_VAR}"
        envsubst "$VARS" < "${TEMPLATE_FILE}" > "${RENDERED_CONF}"
        log "  Rendered: ${RENDERED_CONF}"
    fi
done

# ── 4. uncomment service includes in main nginx.conf ──────────────────────────
# Must check BOTH port and domain — port vars have defaults (e.g. API_PORT=1317)
# even when no domain is configured. Uncommenting without rendering the conf file
# causes `nginx -t` to fail.
for svc in $services; do
    PORT_VAR="${svc}_PORT"
    DOMAIN_VAR="${svc}_DOMAIN"
    port_val=$(printenv "$PORT_VAR" || true)
    domain_val=$(printenv "$DOMAIN_VAR" || true)
    if [ -n "$port_val" ] && [ -n "$domain_val" ]; then
        log "  Enabling $svc include in nginx.conf"
        sed -i.bak "/PORT:${svc}_PORT/s/^#[[:space:]]*//" "$NGINX_FULL"
    fi
done

# ── 5. validate nginx configuration (start deferred to entrypoint) ─────────────
log "Testing nginx configuration..."
nginx -t || die "nginx config test failed — check rendered configs above"
log "nginx config OK — will be started by entrypoint after cosmos setup."
if [ -n "$RPC_DOMAIN"  ]; then log "  RPC  -> https://$RPC_DOMAIN";  fi
if [ -n "$API_DOMAIN"  ]; then log "  API  -> https://$API_DOMAIN";  fi
if [ -n "$GRPC_DOMAIN" ]; then log "  GRPC -> https://$GRPC_DOMAIN"; fi
