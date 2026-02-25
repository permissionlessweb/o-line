#!/bin/bash
# tls-setup.sh --rpc <P2P_DOMAIN>:<RPC_PORT> --grpc <GRPC_DOMAIN>:<GRPC_PORT> --p2p <P2P_DOMAIN>:<P2P_PORT> --api <API_DOMAIN>:<API_PORT>
#
# NOTE: if any flag is omitted, this means this node is not exposing/providing these ports, so we avoid configuring nginx 
#

set -e
log() { echo "[tls-setup] $*"; }
die() { echo "[tls-setup] ERROR: $*" >&2; exit 1; }

NODE_CONFIG_SCRIPT="${NODE_CONFIG_SCRIPT:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/tls/plays/scripts/config-node-endpoints.sh}"
NGINX_CONFIG_TEMPLATES="${NGINX_CONFIG_TEMPLATES:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/tls/plays/flea-flicker/nginx}"
TLS_CERT_PATH="/etc/letsencrypt/live/cert.pem"
TLS_PRIVKEY_PATH="/etc/letsencrypt/live/privkey.pem"

# ── defaults ──────────────────────────────────────────────────────────────────
services="RPC API PEER GRPC"
at_least_one=false
for svc in $services; do
    eval "origin_val=\"\$${svc}_ORIGIN\""
    eval "port_val=\"\$${svc}_PORT\""
    # echo "DEBUG: ${svc}_ORIGIN=$origin_val, ${svc}_PORT=$port_val" >&2
    if [ -n "$origin_val" ] && [ -n "$port_val" ]; then
        # Check port is numeric using POSIX case statement
        case "$port_val" in
            ''|*[!0-9]*)
                die "port must a numeric value  be numeric"
                ;;
            *)
                # Port is numeric - additional validation
                if [ "$port_val" -lt 1 ] || [ "$port_val" -gt 65535 ]; then
                   die " ${svc}_PORT $port_val out of range 1-65535"
                fi
                at_least_one=true
                ;;
        esac
    fi
done

# Fail if no service has both ORIGIN and PORT set
if [ "$at_least_one" = false ]; then
    echo "Error: At least one of the following must be fully set (ORIGIN and PORT):" >&2
    echo "  RPC, API, PEER, or GRPC" >&2
    echo "Example: RPC_ORIGIN=localhost RPC_PORT=8545 $0" >&2
    exit 1
fi
log "Configuration validated."
eval "RPC_ORIGIN=\"\$RPC_ORIGIN\"; RPC_PORT=\"\$RPC_PORT\""
eval "API_ORIGIN=\"\$API_ORIGIN\"; API_PORT=\"\$API_PORT\""
eval "PEER_ORIGIN=\"\$PEER_ORIGIN\"; PEER_PORT=\"\$PEER_PORT\""
eval "GRPC_ORIGIN=\"\$GRPC_ORIGIN\"; GRPC_PORT=\"\$GRPC_PORT\""
[ -n "$RPC_ORIGIN" ] && [ -n "$RPC_PORT" ] && log "RPC: $RPC_ORIGIN:$RPC_PORT"
[ -n "$API_ORIGIN" ] && [ -n "$API_PORT" ] && log "API: $API_ORIGIN:$API_PORT"
[ -n "$PEER_ORIGIN" ] && [ -n "$PEER_PORT" ] && log "PEER: $PEER_ORIGIN:$PEER_PORT"
[ -n "$GRPC_ORIGIN" ] && [ -n "$GRPC_PORT" ] && log "GRPC: $GRPC_ORIGIN:$GRPC_PORT"
# die "testing"

# ── 1. install nginx + certbot ─────────────────────────────────────────────────
log "Installing nginx, certbot, gettext..."
if command -v apt-get > /dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq nginx certbot python3-certbot-nginx gettext-base curl jq openssh-server
elif command -v apk > /dev/null 2>&1; then
    apk add --no-cache nginx certbot certbot-nginx gettext curl jq
else
    die "Unsupported package manager (need apt-get or apk)"
fi

# ── 2. fetch each nginx config template based on which flags are being configured  ───────────────────────────────────────────
log "Fetching nginx config template from ${NGINX_CONFIG_TEMPLATES}"
for svc in $services; do
    PORT_VAR="${svc}_PORT"
    DOMAIN_VAR="${svc}_DOMAIN"
    port_val=$(printenv "$PORT_VAR" || true)
    domain_val=$(printenv "$DOMAIN_VAR" || true)
    if [ -n "$port_val" ] && [ -n "$domain_val" ]; then
        log "Configuring service: $svc"
        TEMPLATE_FILE=$(mktemp /tmp/nginx-template."${svc}".XXXXXX)
        curl -fsSL "${NGINX_CONFIG_TEMPLATES}/${svc}" -o "${TEMPLATE_FILE}" || die "Failed to fetch nginx config template for ${svc}"
        export "$PORT_VAR=$port_val"
        export "$DOMAIN_VAR=$domain_val"
        RENDERED_CONF="${RENDERED_DIR}/${svc}.conf"

        VARS='$'"${PORT_VAR}"',$'"${DOMAIN_VAR}"',$TLS_CERT,$TLS_KEY'
        envsubst "$VARS" < "${TEMPLATE_FILE}" > "${RENDERED_CONF}"
        log "Rendered config written to ${RENDERED_CONF}"
    fi
done
# -------------------------------------------------------------------
# Update main nginx config (uncomment includes per service)
# -------------------------------------------------------------------
cp "${MAIN_NGINX_CONF}" "${NGINX_FULL}"
for svc in $services; do
    PORT_VAR="${svc}_PORT"
    port_val=$(printenv "$PORT_VAR" || true)
    if [ -n "$port_val" ]; then
        log "Enabling include for $svc"
        sed -i.bak "/PORT:${svc}_PORT/s/^#[[:space:]]*//" "${NGINX_FULL}"
    fi
done

# open up ssh to dedicated port (remove default from 22)
# install ssh server 
mkdir -p /var/run/sshd ~/.ssh
chmod 700 ~/.ssh
# change default port
sed -i "s/#Port 22/Port ${SSH_PORT}/" /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
# remove default password (if exists)
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
# add authorized ssh pubkey 
touch ~/.ssh/authorized_keys
echo "$SSH_PUBKEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
# Start SSH daemon
/usr/sbin/sshd -D

# ── 5. wait for TLS certificate to be set via sftp ─────────────────────────────────────
log "Waiting for tls cert & keys to be provided via sftp"
while [ ! -e "$TLS_CERT_PATH" ] && [ ! -e "$TLS_PRIVKEY_PATH" ]; do
    sleep 5
done
log "Set key & cert at path: $TLS_CERT_PATH & $TLS_PRIVKEY_PATH  "

# ── 6. configure nginx based on flags  ─────────────────
log "Stopping temporary nginx..."
log "Starting nginx daemon..."
nginx
log "nginx running with TLS for:"

# ── 7. patch config.toml ──────────────────────────────────────────────────────
NODE_SCRIPT=node-config.sh
# download patch file, provide flags to setup ports + comptaible with nginx reverse proxy setup
curl -fsSL "${NODE_CONFIG_SCRIPT}" -o "$NODE_SCRIPT" || die "Failed to fetch node config template"
sh $NODE_SCRIPT