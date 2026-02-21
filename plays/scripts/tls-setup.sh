#!/bin/sh
# tls-setup.sh — pre-start TLS curation for cosmos-sdk nodes
#
# Fetched and executed by START_CMD before the node binary starts.
# Installs nginx, obtains a Let's Encrypt cert, wires up a reverse proxy,
# and patches config.toml / app.toml so the node advertises HTTPS endpoints.
#
# Required env vars:
#   RPC_DOMAIN        - public domain for CometBFT RPC (e.g. statesync.terp.network)
#   CERTBOT_EMAIL     - email for Let's Encrypt registration
#
# Optional env vars (each section omitted when unset):
#   API_DOMAIN        - public domain for Cosmos REST API
#   GRPC_DOMAIN       - public domain for Cosmos gRPC
#   P2P_DOMAIN        - public domain for P2P seed endpoint (HTTP passthrough)
#   RPC_PORT          - internal RPC port          (default: 26657)
#   API_PORT          - internal REST API port     (default: 1317)
#   GRPC_PORT         - internal gRPC port         (default: 9090)
#   P2P_PORT          - internal P2P port          (default: 26656)
#   NODE_HOME         - node home directory        (default: /root/.terpd)
#   NGINX_CONF_URL    - URL of the nginx config template to fetch
#                       (defaults to the rpc-api-grpc-peer template in this repo)
#
# Usage in SDL env:
#   START_CMD=/bin/sh -c "curl -fsSL $TLS_SETUP_URL | sh && exec terpd start"

set -e

log() { echo "[tls-setup] $*"; }
die() { echo "[tls-setup] ERROR: $*" >&2; exit 1; }

# ── defaults ──────────────────────────────────────────────────────────────────
RPC_PORT="${RPC_PORT:-26657}"
API_PORT="${API_PORT:-1317}"
GRPC_PORT="${GRPC_PORT:-9090}"
P2P_PORT="${P2P_PORT:-26656}"
NODE_HOME="${NODE_HOME:-/root/.terpd}"
CONFIG_DIR="${NODE_HOME}/config"

NGINX_CONF_URL="${NGINX_CONF_URL:-https://raw.githubusercontent.com/permissionlessweb/o-line/master/plays/flea-flicker/nginx/rpc-api-grpc-peer}"

[ -n "${RPC_DOMAIN}" ]    || die "RPC_DOMAIN must be set"
[ -n "${CERTBOT_EMAIL}" ] || die "CERTBOT_EMAIL must be set"

# ── 1. install nginx + certbot ─────────────────────────────────────────────────
log "Installing nginx, certbot, gettext..."

if command -v apt-get > /dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq nginx certbot python3-certbot-nginx gettext-base curl jq
elif command -v apk > /dev/null 2>&1; then
    apk add --no-cache nginx certbot certbot-nginx gettext curl jq
else
    die "Unsupported package manager (need apt-get or apk)"
fi

# ── 2. fetch nginx config template ───────────────────────────────────────────
log "Fetching nginx config template from ${NGINX_CONF_URL}"
NGINX_TEMPLATE=$(mktemp /tmp/nginx-template.XXXXXX)
curl -fsSL "${NGINX_CONF_URL}" -o "${NGINX_TEMPLATE}" \
    || die "Failed to fetch nginx config template"

# ── 3. gather node environment & set TLS cert paths ───────────────────────────
# certonly --webroot stores certs under /etc/letsencrypt/live/<primary-domain>/
TLS_CERT="/etc/letsencrypt/live/${RPC_DOMAIN}/fullchain.pem"
TLS_KEY="/etc/letsencrypt/live/${RPC_DOMAIN}/privkey.pem"

log "Node home:    ${NODE_HOME}"
log "RPC:          https://${RPC_DOMAIN} → 127.0.0.1:${RPC_PORT}"
[ -n "${API_DOMAIN}" ]  && log "API:          https://${API_DOMAIN} → 127.0.0.1:${API_PORT}"
[ -n "${GRPC_DOMAIN}" ] && log "gRPC:         https://${GRPC_DOMAIN} → 127.0.0.1:${GRPC_PORT}"
[ -n "${P2P_DOMAIN}" ]  && log "P2P:          http://${P2P_DOMAIN}  → 127.0.0.1:${P2P_PORT}"

# Build envsubst variable list (only substitute our vars, not nginx's $host etc.)
SUBST_VARS='${RPC_DOMAIN} ${RPC_PORT} ${API_DOMAIN} ${API_PORT} ${GRPC_DOMAIN} ${GRPC_PORT} ${P2P_DOMAIN} ${P2P_PORT} ${TLS_CERT} ${TLS_KEY}'

# Export all vars so envsubst can see them
export RPC_DOMAIN RPC_PORT API_DOMAIN API_PORT GRPC_DOMAIN GRPC_PORT P2P_DOMAIN P2P_PORT TLS_CERT TLS_KEY

# Generate the full template (with all optional blocks) to a temp file
NGINX_FULL=$(mktemp /tmp/nginx-full.XXXXXX)
envsubst "${SUBST_VARS}" < "${NGINX_TEMPLATE}" > "${NGINX_FULL}"

# Strip optional server blocks whose domain is empty.
# Marks server blocks that contain server_name with an empty value and removes them.
strip_server_block() {
    local file="$1"
    local domain_val="$2"
    if [ -z "${domain_val}" ]; then
        # Remove the server block containing server_name ;  (substituted from empty var)
        awk '
            /server[[:space:]]*\{/ { buf = $0; depth = 1; next }
            depth > 0 {
                buf = buf "\n" $0
                if (/\{/) depth++
                if (/\}/) { depth--; if (depth == 0) { print_block = 1 } }
            }
            depth == 0 && print_block {
                if (buf !~ /server_name[[:space:]]*;/) printf "%s\n", buf
                print_block = 0; buf = ""
                next
            }
            depth == 0 && !print_block { print }
        ' "${file}" > "${file}.stripped" && mv "${file}.stripped" "${file}"
    fi
}

strip_server_block "${NGINX_FULL}" "${API_DOMAIN}"
strip_server_block "${NGINX_FULL}" "${GRPC_DOMAIN}"
strip_server_block "${NGINX_FULL}" "${P2P_DOMAIN}"

# ── 4. bootstrap nginx for certbot HTTP-01 challenge ─────────────────────────
log "Writing minimal HTTP nginx config for certbot challenge..."

mkdir -p /var/www/certbot

# Build server_name list for the challenge server (all domains using same cert)
CHALLENGE_NAMES="${RPC_DOMAIN}"
[ -n "${API_DOMAIN}" ]  && CHALLENGE_NAMES="${CHALLENGE_NAMES} ${API_DOMAIN}"
[ -n "${GRPC_DOMAIN}" ] && CHALLENGE_NAMES="${CHALLENGE_NAMES} ${GRPC_DOMAIN}"

cat > /etc/nginx/nginx.conf << NGINX_HTTP_CONF
events { worker_connections 512; }
http {
    server {
        listen 80;
        server_name ${CHALLENGE_NAMES};
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
        location / { return 200 'ok'; }
    }
}
NGINX_HTTP_CONF

log "Starting nginx for ACME challenge..."
nginx -t && nginx

# ── 5. obtain TLS certificate via certbot ─────────────────────────────────────
log "Running certbot for ${RPC_DOMAIN}..."

CERTBOT_DOMAINS="-d ${RPC_DOMAIN}"
[ -n "${API_DOMAIN}" ]  && CERTBOT_DOMAINS="${CERTBOT_DOMAINS} -d ${API_DOMAIN}"
[ -n "${GRPC_DOMAIN}" ] && CERTBOT_DOMAINS="${CERTBOT_DOMAINS} -d ${GRPC_DOMAIN}"

certbot certonly \
    --webroot \
    --webroot-path /var/www/certbot \
    --non-interactive \
    --agree-tos \
    --email "${CERTBOT_EMAIL}" \
    ${CERTBOT_DOMAINS} \
    || {
        log "WARNING: certbot failed (DNS may not be propagated yet). Continuing without TLS."
        nginx -s stop 2>/dev/null || true
        rm -f "${NGINX_TEMPLATE}" "${NGINX_FULL}"
        # Node will still start — nginx won't be running
        exit 0
    }

log "Certificate obtained at ${TLS_CERT}"

# ── 6. stop temporary nginx, apply full HTTPS config, restart ─────────────────
log "Stopping temporary nginx..."
nginx -s stop 2>/dev/null || true
sleep 1

log "Applying full HTTPS nginx config..."
cp "${NGINX_FULL}" /etc/nginx/nginx.conf

nginx -t || die "nginx config test failed after applying HTTPS config"

log "Starting nginx daemon..."
nginx

log "nginx running with TLS for ${RPC_DOMAIN}"

# ── 7. patch config.toml ──────────────────────────────────────────────────────
if [ -f "${CONFIG_DIR}/config.toml" ]; then
    log "Patching config.toml..."

    # rpc.laddr — bind locally (nginx handles external TLS)
    sed -i \
        -e "/^\[rpc\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://127.0.0.1:${RPC_PORT}\"|" \
        "${CONFIG_DIR}/config.toml"

    # rpc.tls_cert_file / rpc.tls_key_file — enable native CometBFT HTTPS on RPC
    sed -i \
        -e "/^\[rpc\]$/,/^\[/ s|^tls_cert_file *=.*|tls_cert_file = \"${TLS_CERT}\"|" \
        -e "/^\[rpc\]$/,/^\[/ s|^tls_key_file *=.*|tls_key_file = \"${TLS_KEY}\"|" \
        "${CONFIG_DIR}/config.toml"

    # p2p.laddr — P2P always on all interfaces (not proxied by nginx)
    sed -i \
        -e "/^\[p2p\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://0.0.0.0:${P2P_PORT}\"|" \
        "${CONFIG_DIR}/config.toml"

    log "config.toml patched"
else
    log "WARNING: ${CONFIG_DIR}/config.toml not found — skipping"
fi

# ── 8. patch app.toml ─────────────────────────────────────────────────────────
if [ -f "${CONFIG_DIR}/app.toml" ]; then
    log "Patching app.toml..."

    # api.enabled = true
    sed -i \
        -e "/^\[api\]$/,/^\[/ s|^enable *=.*|enable = true|" \
        "${CONFIG_DIR}/app.toml"

    # api.address — bind locally (nginx handles external TLS)
    sed -i \
        -e "/^\[api\]$/,/^\[/ s|^address *=.*|address = \"tcp://127.0.0.1:${API_PORT}\"|" \
        "${CONFIG_DIR}/app.toml"

    # grpc.address — gRPC on all interfaces (nginx or direct access)
    sed -i \
        -e "/^\[grpc\]$/,/^\[/ s|^address *=.*|address = \"0.0.0.0:${GRPC_PORT}\"|" \
        "${CONFIG_DIR}/app.toml"

    log "app.toml patched"
else
    log "WARNING: ${CONFIG_DIR}/app.toml not found — skipping"
fi

# ── cleanup ───────────────────────────────────────────────────────────────────
rm -f "${NGINX_TEMPLATE}" "${NGINX_FULL}"

log "TLS setup complete. Handing off to node start command."
