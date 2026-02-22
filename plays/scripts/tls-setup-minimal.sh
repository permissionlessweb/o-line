#!/bin/sh
# tls-setup.sh — minimal TLS setup for cosmos-sdk nodes on Akash
#
# Required env vars:
#   RPC_DOMAIN      - e.g. rpc.terp.network
#   CERTBOT_EMAIL   - e.g. admin@terp.network
#
# Optional env vars:
#   API_DOMAIN      - e.g. api.terp.network
#   SEED_DOMAIN     - e.g. seed.terp.network
#   RPC_PORT        - default: 26657
#   API_PORT        - default: 1317
#   SEED_PORT       - default: 26656

set -e

log() { echo "[tls-setup] $*"; }

RPC_PORT="${RPC_PORT:-26657}"
API_PORT="${API_PORT:-1317}"
SEED_PORT="${SEED_PORT:-26656}"

[ -n "${RPC_DOMAIN}" ]    || { log "RPC_DOMAIN not set — skipping TLS"; exec "$@"; }
[ -n "${CERTBOT_EMAIL}" ] || { log "CERTBOT_EMAIL not set — skipping TLS"; exec "$@"; }

# ── 1. install dependencies ───────────────────────────────────────────────────
if command -v apt-get > /dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq nginx certbot python3-certbot-nginx gettext-base
elif command -v apk > /dev/null 2>&1; then
    apk add --no-cache nginx certbot certbot-nginx gettext
fi

# Remove default nginx config to avoid port 80 conflicts
rm -f /etc/nginx/http.d/default.conf /etc/nginx/conf.d/default.conf

# ── 2. start nginx on port 80 for ACME challenge ──────────────────────────────
# Build server_name list
CHALLENGE_NAMES="${RPC_DOMAIN}"
[ -n "${API_DOMAIN}" ]  && CHALLENGE_NAMES="${CHALLENGE_NAMES} ${API_DOMAIN}"
[ -n "${SEED_DOMAIN}" ] && CHALLENGE_NAMES="${CHALLENGE_NAMES} ${SEED_DOMAIN}"

mkdir -p /var/www/certbot/.well-known/acme-challenge

cat > /etc/nginx/nginx.conf << EOF
events { worker_connections 512; }
http {
    server {
        listen 80;
        server_name ${CHALLENGE_NAMES};
        location /.well-known/acme-challenge/ {
            alias /var/www/certbot/.well-known/acme-challenge/;
        }
        location / { return 200 'ok'; }
    }
}
EOF

nginx -t && nginx
log "nginx started for ACME challenge"

# ── 3. obtain certificate ─────────────────────────────────────────────────────
CERTBOT_DOMAINS="-d ${RPC_DOMAIN}"
[ -n "${API_DOMAIN}" ]  && CERTBOT_DOMAINS="${CERTBOT_DOMAINS} -d ${API_DOMAIN}"
[ -n "${SEED_DOMAIN}" ] && CERTBOT_DOMAINS="${CERTBOT_DOMAINS} -d ${SEED_DOMAIN}"

log "Running certbot for ${RPC_DOMAIN}..."

certbot certonly \
    --webroot \
    --webroot-path /var/www/certbot \
    --non-interactive \
    --agree-tos \
    --email "${CERTBOT_EMAIL}" \
    -d "${RPC_DOMAIN}" \
    ${API_DOMAIN:+-d "${API_DOMAIN}"} \
    ${SEED_DOMAIN:+-d "${SEED_DOMAIN}"}\
    || {
        log "WARNING: certbot failed — starting node without TLS"
        nginx -s stop 2>/dev/null || true
        exec "$@"
    }

TLS_CERT="/etc/letsencrypt/live/${RPC_DOMAIN}/fullchain.pem"
TLS_KEY="/etc/letsencrypt/live/${RPC_DOMAIN}/privkey.pem"
log "Certificate obtained: ${TLS_CERT}"

# ── 4. apply full nginx config with HTTPS proxy ───────────────────────────────
nginx -s stop 2>/dev/null || true
sleep 1

cat > /etc/nginx/nginx.conf << EOF
events { worker_connections 1024; }
http {
    server {
        listen 80;
        server_name ${CHALLENGE_NAMES};
        location /.well-known/acme-challenge/ {
            alias /var/www/certbot/.well-known/acme-challenge/;
        }
        location / { return 301 https://\$host\$request_uri; }
    }

    server {
        listen 443 ssl;
        server_name ${RPC_DOMAIN};
        ssl_certificate     ${TLS_CERT};
        ssl_certificate_key ${TLS_KEY};
        location / {
            proxy_pass http://127.0.0.1:${RPC_PORT};
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }
    }
EOF

# Optional API block
if [ -n "${API_DOMAIN}" ]; then
cat >> /etc/nginx/nginx.conf << EOF
    server {
        listen 443 ssl;
        server_name ${API_DOMAIN};
        ssl_certificate     ${TLS_CERT};
        ssl_certificate_key ${TLS_KEY};
        location / {
            proxy_pass http://127.0.0.1:${API_PORT};
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }
    }
EOF
fi

# Close http block
echo "}" >> /etc/nginx/nginx.conf

nginx -t || { log "nginx config invalid — starting node without nginx"; exec "$@"; }
nginx
log "nginx running with TLS"

# ── 5. hand off to node ───────────────────────────────────────────────────────
log "TLS setup complete. Handing off to entrypoint."
exec "$@"