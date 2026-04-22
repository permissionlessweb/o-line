#!/bin/sh
set -e

echo "[lb] Starting load balancer init..."

# ── 1. Generate nginx upstream config from env ──
echo "[lb] Generating upstream config..."

# UPSTREAM_RPC="sentry-a:26657,sentry-b:26657"
# UPSTREAM_API="sentry-a:1317,sentry-b:1317"
# UPSTREAM_GRPC="sentry-a:9090,sentry-b:9090"

cat > /etc/nginx/conf.d/upstreams.conf << NGINX_EOF
upstream rpc_pool {
$(echo "${UPSTREAM_RPC:-}" | tr "," "\n" | while read -r s; do
  [ -n "$s" ] && echo "    server $s;"
done)
}

upstream api_pool {
$(echo "${UPSTREAM_API:-}" | tr "," "\n" | while read -r s; do
  [ -n "$s" ] && echo "    server $s;"
done)
}

upstream grpc_pool {
$(echo "${UPSTREAM_GRPC:-}" | tr "," "\n" | while read -r s; do
  [ -n "$s" ] && echo "    server $s;"
done)
}
NGINX_EOF

# ── 3. Generate per-service server blocks ──
echo "[lb] Generating server blocks..."

# RPC proxy (with WebSocket support)
if [ -n "${RPC_DOMAIN:-}" ]; then
cat > /etc/nginx/conf.d/rpc.conf << NGINX_EOF
server {
    listen 80;
    server_name ${RPC_DOMAIN};

    location /websocket {
        proxy_pass         http://rpc_pool/websocket;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    \$http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       \$host;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass         http://rpc_pool;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Upgrade           \$http_upgrade;
        proxy_set_header   Connection        "upgrade";
        add_header Access-Control-Allow-Origin  *;
        add_header Access-Control-Allow-Methods *;
        add_header Access-Control-Max-Age       3600;
    }
}
NGINX_EOF
echo "[lb]   RPC: ${RPC_DOMAIN} -> rpc_pool"
fi

# API proxy
if [ -n "${API_DOMAIN:-}" ]; then
cat > /etc/nginx/conf.d/api.conf << NGINX_EOF
server {
    listen 80;
    server_name ${API_DOMAIN};

    location / {
        proxy_pass         http://api_pool;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        add_header Access-Control-Allow-Origin   *;
        add_header Access-Control-Allow-Methods  *;
        add_header Access-Control-Max-Age        3600;
        add_header Access-Control-Expose-Headers Content-Length;
    }
}
NGINX_EOF
echo "[lb]   API: ${API_DOMAIN} -> api_pool"
fi

# gRPC proxy
if [ -n "${GRPC_DOMAIN:-}" ]; then
cat > /etc/nginx/conf.d/grpc.conf << NGINX_EOF
server {
    listen 80 http2;
    server_name ${GRPC_DOMAIN};

    location / {
        grpc_pass grpc://grpc_pool;
        grpc_set_header Host \$host;
    }
}
NGINX_EOF
echo "[lb]   GRPC: ${GRPC_DOMAIN} -> grpc_pool"
fi

# ── 4. Remove default server ──
rm -f /etc/nginx/conf.d/default.conf

# ── 5. Test and start nginx ──
echo "[lb] Testing nginx config..."
nginx -t
echo "[lb] Starting nginx (foreground)..."
exec nginx -g "daemon off;"
