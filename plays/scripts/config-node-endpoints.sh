#!/bin/bash
## confirm all required env variables exists
# expect home path PROJECT_DIR from oline to have been set.
if [ -z "${PROJECT_DIR}" ]; then
    echo "Environment variable PROJECT_DIR is not set"
    exit 1
fi

if [ -d "${GRPC_DOMAIN}" ]; then
  log "Patching grpc support..."
   sed -i \
        -e "/^\[grpc\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[grpc-web\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[grpc\]$/,/^\[/ s|^address *=.*|address = \"0.0.0.0:${GRPC_PORT}\"|" \
        "${PROJECT_DIR}/config/app.toml"
fi
if [ -d "${RPC_DOMAIN}" ]; then
  log "Patching rcp support..."
    # rpc.laddr — bind locally (nginx handles external TLS)
    sed -i \
        -e "/^\[rpc\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://127.0.0.1:${RPC_PORT}\"|" \
        "${PROJECT_DIR}/config/config.toml"

    # rpc.tls_cert_file / rpc.tls_key_file — enable native CometBFT HTTPS on RPC
    sed -i \
        -e "/^\[rpc\]$/,/^\[/ s|^tls_cert_file *=.*|tls_cert_file = \"${TLS_CERT}\"|" \
        -e "/^\[rpc\]$/,/^\[/ s|^tls_key_file *=.*|tls_key_file = \"${TLS_KEY}\"|" \
        "${PROJECT_DIR}/config/config.toml"
fi

if [ -d "${API_DOMAIN}" ]; then
  log "Patching api support..."
    # api.enabled = true
    sed -i \
        -e "/^\[api\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[api\]$/,/^\[/ s/^swagger *=.*/swagger = \"true\"/" \
        "${PROJECT_DIR}/config/app.toml"

    # api.address — bind locally (nginx handles external TLS)
    sed -i \
        -e "/^\[api\]$/,/^\[/ s|^address *=.*|address = \"tcp://127.0.0.1:${API_PORT}\"|" \
        "${PROJECT_DIR}/config/app.toml"
fi

if [ -d "${PEER_DOMAIN}" ]; then
  log "Patching p2p support..."
    # p2p.laddr — P2P always on all interfaces (not proxied by nginx)
    sed -i \
        -e "/^\[p2p\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://0.0.0.0:${P2P_PORT}\"|" \
        "${PROJECT_DIR}/config/config.toml"
fi 
