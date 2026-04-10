#!/bin/bash
log() { echo "[node-config] $*"; }

# Dump the env vars we act on so the caller can confirm they were received.
log "=== env: P2P_PEX='${P2P_PEX:-}' P2P_ADDR_BOOK_STRICT='${P2P_ADDR_BOOK_STRICT:-}' ==="

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
        -e "/^\[grpc\]$/,/^\[/ s|^address *=.*|address = \"127.0.0.1:${GRPC_PORT}\"|" \
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

# Patch persistent_peers directly into config.toml.
# terpd reads persistent_peers from config.toml at startup, not from the
# TERPD_P2P_PERSISTENT_PEERS env var, so we must write it explicitly.
# P2P_PERSISTENT_PEERS takes precedence; falls back to the namespaced var.
_PEERS="${P2P_PERSISTENT_PEERS:-${TERPD_P2P_PERSISTENT_PEERS:-}}"
if [ -n "${_PEERS}" ] && [ "${_PEERS}" != "0" ]; then
  log "Patching persistent_peers..."
  sed -i \
      -e "/^\[p2p\]$/,/^\[/ s|^persistent_peers *=.*|persistent_peers = \"${_PEERS}\"|" \
      "${PROJECT_ROOT}/config/config.toml"
fi
unset _PEERS

# private_peer_ids — IDs that won't be gossiped to other peers (e.g. validator node ID).
_PRIVATE="${TERPD_P2P_PRIVATE_PEER_IDS:-}"
if [ -n "${_PRIVATE}" ] && [ "${_PRIVATE}" != "0" ]; then
  log "Patching private_peer_ids..."
  sed -i \
      -e "/^\[p2p\]$/,/^\[/ s|^private_peer_ids *=.*|private_peer_ids = \"${_PRIVATE}\"|" \
      "${PROJECT_ROOT}/config/config.toml"
fi
unset _PRIVATE

# unconditional_peer_ids — always maintain connections to these peers even if slots are full.
_UNCONDITIONAL="${TERPD_P2P_UNCONDITIONAL_PEER_IDS:-}"
if [ -n "${_UNCONDITIONAL}" ] && [ "${_UNCONDITIONAL}" != "0" ]; then
  log "Patching unconditional_peer_ids..."
  sed -i \
      -e "/^\[p2p\]$/,/^\[/ s|^unconditional_peer_ids *=.*|unconditional_peer_ids = \"${_UNCONDITIONAL}\"|" \
      "${PROJECT_ROOT}/config/config.toml"
fi
unset _UNCONDITIONAL

# pex — disable peer exchange for isolated / private networks (e2e tests, private validators).
# Set P2P_PEX=false or P2P_PEX=0 to turn off peer gossip.
# Note: `pex` is unique to the [p2p] section in Tendermint/CometBFT config, so a
# simple global replacement is safe (no section-range needed).
_PEX="${P2P_PEX:-}"
if [ "${_PEX}" = "false" ] || [ "${_PEX}" = "0" ]; then
  log "Disabling PEX (peer exchange)..."
  sed -i 's/^pex = true/pex = false/' "${PROJECT_ROOT}/config/config.toml"
  sed -i 's/^pex=true/pex=false/' "${PROJECT_ROOT}/config/config.toml"
  # Fallback: if no existing pex line, insert one after [p2p]
  if ! grep -qE '^pex\s*=\s*false' "${PROJECT_ROOT}/config/config.toml"; then
    sed -i '/^\[p2p\]/a pex = false' "${PROJECT_ROOT}/config/config.toml"
    log "pex line not found — inserted 'pex = false' after [p2p]"
  fi
  log "pex = $(grep '^pex' ${PROJECT_ROOT}/config/config.toml | head -1)"
fi
unset _PEX

# addr_book_strict — set to false to allow peering with private/local IP addresses.
# Required when using host.docker.internal or 192.168.x.x peers (e.g. local e2e tests).
_ABS="${P2P_ADDR_BOOK_STRICT:-}"
if [ "${_ABS}" = "false" ] || [ "${_ABS}" = "0" ]; then
  log "Setting addr_book_strict = false..."
  sed -i 's/^addr_book_strict = true$/addr_book_strict = false/' "${PROJECT_ROOT}/config/config.toml"
  sed -i 's/^addr_book_strict=true$/addr_book_strict=false/' "${PROJECT_ROOT}/config/config.toml"
fi
unset _ABS
