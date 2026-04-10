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

NGINX_CONFIG_TEMPLATES="${NGINX_CONFIG_TEMPLATES:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/flea-flicker/nginx}"

# ── paths ──────────────────────────────────────────────────────────────────────
# Certs are delivered via SFTP to /tmp/tls/ by oline before this script runs.
export TLS_CERT="${TLS_CERT:-/tmp/tls/cert.pem}"
export TLS_KEY="${TLS_KEY:-/tmp/tls/privkey.pem}"
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
    log "No service domains configured — nginx setup skipped."
    # When invoked as START_CMD (e.g. 'tls-setup.sh terpd start'), exec the
    # remaining args directly so the node process still starts.
    if [ "$#" -gt 0 ]; then exec "$@"; fi
    exit 0
fi
log "Configuration validated."
if [ -n "$RPC_DOMAIN"  ] && [ -n "$RPC_PORT"  ]; then log "  RPC:  $RPC_DOMAIN:$RPC_PORT";  fi
if [ -n "$API_DOMAIN"  ] && [ -n "$API_PORT"  ]; then log "  API:  $API_DOMAIN:$API_PORT";   fi
if [ -n "$GRPC_DOMAIN" ] && [ -n "$GRPC_PORT" ]; then log "  GRPC: $GRPC_DOMAIN:$GRPC_PORT"; fi

# TLS certs were previously used as a startup sync signal (SFTP delivery).
# Akash provider terminates TLS at the ingress — nginx here uses plain HTTP
# for RPC and API. However, gRPC uses NodePort TLS (not Akash ingress) and
# NEEDS actual cert files. Generate a self-signed cert if none exists.
if [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ]; then
  log "TLS cert: $TLS_CERT (present)"
else
  log "No TLS certs found at $TLS_CERT / $TLS_KEY"
  if [ -n "$GRPC_DOMAIN" ] && [ -n "$GRPC_PORT" ]; then
    log "gRPC configured — generating self-signed cert for NodePort TLS..."
    mkdir -p "$(dirname "$TLS_CERT")"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$TLS_KEY" -out "$TLS_CERT" -days 365 -nodes \
      -subj "/CN=${GRPC_DOMAIN}" 2>/dev/null
    log "Self-signed cert generated for ${GRPC_DOMAIN}"
  else
    log "Continuing without certs (Akash ingress handles TLS for RPC/API)"
  fi
fi

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
# Clear any stale .conf files from a previous run so the glob include
# in nginx.conf only picks up services configured for this deployment.
rm -f "$RENDERED_DIR"/*.conf "$RENDERED_DIR"/*.conf.bak 2>/dev/null || true

# ── 2. fetch main nginx.conf template ──────────────────────────────────────────
log "Fetching main nginx.conf template..."
MAIN_NGINX_TMPL=$(mktemp /tmp/nginx-main.XXXXXX)
if [ -f "/tmp/nginx/template" ]; then
    log "  Using pre-uploaded nginx/template"
    cp /tmp/nginx/template "$MAIN_NGINX_TMPL"
else
    curl -fsSL "${NGINX_CONFIG_TEMPLATES}/template" -o "$MAIN_NGINX_TMPL" \
        || die "Failed to fetch main nginx.conf template"
fi
cp "$MAIN_NGINX_TMPL" "$NGINX_FULL"

# ── 3. fetch + render per-service config templates ─────────────────────────────
# nginx.conf uses `include /etc/nginx/conf.d/*.conf` — a service becomes active
# simply by writing its .conf file here.  No sed editing of nginx.conf needed.
log "Rendering per-service nginx configs..."
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
        if [ -f "/tmp/nginx/${svc_lower}" ]; then
            log "  Using pre-uploaded nginx/${svc_lower}"
            cp "/tmp/nginx/${svc_lower}" "${TEMPLATE_FILE}"
        else
            curl -fsSL "${NGINX_CONFIG_TEMPLATES}/${svc_lower}" -o "${TEMPLATE_FILE}" \
                || die "Failed to fetch nginx template for ${svc}"
        fi
        export "$PORT_VAR=$port_val" "$DOMAIN_VAR=$domain_val"
        RENDERED_CONF="${RENDERED_DIR}/${svc_lower}.conf"
        # gRPC template uses TLS cert/key (NodePort TLS termination) in addition to domain/port
        if [ "$svc" = "GRPC" ]; then
            VARS='$'"${DOMAIN_VAR}"',$'"${PORT_VAR}"',$TLS_CERT,$TLS_KEY'
        else
            VARS='$'"${PORT_VAR}"',$'"${DOMAIN_VAR}"
        fi
        envsubst "$VARS" < "${TEMPLATE_FILE}" > "${RENDERED_CONF}"
        log "  Rendered: ${RENDERED_CONF}"
    fi
done

# ── 4. validate nginx configuration (start deferred to entrypoint) ─────────────
log "Testing nginx configuration..."
nginx -t 2>&1 || die "nginx config test failed — check rendered configs above"
if [ -n "$RPC_DOMAIN"  ]; then log "  RPC  -> https://$RPC_DOMAIN";  fi
if [ -n "$API_DOMAIN"  ]; then log "  API  -> https://$API_DOMAIN";  fi
if [ -n "$GRPC_DOMAIN" ]; then log "  GRPC -> https://$GRPC_DOMAIN"; fi
# When invoked as START_CMD with a command (e.g. 'terpd start'), exec it now.
# When called with no args (from oline-entrypoint.sh), exit 0 — the entrypoint
# starts nginx and the cosmos node separately.
if [ "$#" -gt 0 ]; then exec "$@"; fi
exit 0
