#!/bin/bash
log() { echo "[node-config] $*"; }

## confirm all required env variables exists
# oline-entrypoint.sh exports PROJECT_ROOT as the absolute path (e.g. /root/.terpd).
# Do NOT use PROJECT_DIR here — it is a relative path (.terpd) and the working
# directory changes during snapshot download, which would produce a doubled path.
if [ -z "${PROJECT_ROOT}" ]; then
    echo "Environment variable PROJECT_ROOT is not set"
    exit 1
fi

if [ -n "${GRPC_DOMAIN}" ]; then
  log "Patching grpc support..."
   sed -i \
        -e "/^\[grpc\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[grpc-web\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[grpc\]$/,/^\[/ s|^address *=.*|address = \"0.0.0.0:${GRPC_PORT}\"|" \
        "${PROJECT_ROOT}/config/app.toml"
fi
if [ -n "${RPC_DOMAIN}" ]; then
  log "Patching rpc support..."
    # rpc.laddr — bind locally (nginx handles external TLS termination)
    sed -i \
        -e "/^\[rpc\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://127.0.0.1:${RPC_PORT}\"|" \
        "${PROJECT_ROOT}/config/config.toml"
fi

if [ -n "${API_DOMAIN}" ]; then
  log "Patching api support..."
    # api.enabled = true
    sed -i \
        -e "/^\[api\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[api\]$/,/^\[/ s/^swagger *=.*/swagger = \"true\"/" \
        "${PROJECT_ROOT}/config/app.toml"

    # api.address — bind locally (nginx handles external TLS termination)
    sed -i \
        -e "/^\[api\]$/,/^\[/ s|^address *=.*|address = \"tcp://127.0.0.1:${API_PORT}\"|" \
        "${PROJECT_ROOT}/config/app.toml"
fi

if [ -n "${P2P_DOMAIN}" ]; then
  log "Patching p2p support..."
    # p2p.laddr — P2P always on all interfaces (not proxied by nginx)
    sed -i \
        -e "/^\[p2p\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://0.0.0.0:${P2P_PORT}\"|" \
        "${PROJECT_ROOT}/config/config.toml"
fi
