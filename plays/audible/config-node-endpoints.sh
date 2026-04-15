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

if [ -n "${GRPC_D}" ]; then
  log "Patching grpc support..."
   sed -i \
        -e "/^\[grpc\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[grpc-web\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[grpc\]$/,/^\[/ s|^address *=.*|address = \"127.0.0.1:${GRPC_P}\"|" \
        "${PROJECT_ROOT}/config/app.toml"
fi
if [ -n "${RPC_DOMAIN}" ]; then
  log "Patching rpc support..."
    # rpc.laddr — bind locally (nginx handles external TLS termination)
    sed -i \
        -e "/^\[rpc\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://127.0.0.1:${RPC_P}\"|" \
        "${PROJECT_ROOT}/config/config.toml"
fi

if [ -n "${API_D}" ]; then
  log "Patching api support..."
    # api.enabled = true
    sed -i \
        -e "/^\[api\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[api\]$/,/^\[/ s/^swagger *=.*/swagger = \"true\"/" \
        "${PROJECT_ROOT}/config/app.toml"

    # api.address — bind locally (nginx handles external TLS termination)
    sed -i \
        -e "/^\[api\]$/,/^\[/ s|^address *=.*|address = \"tcp://127.0.0.1:${API_P}\"|" \
        "${PROJECT_ROOT}/config/app.toml"
fi

if [ -n "${P2P_D}" ]; then
  log "Patching p2p support..."
    # p2p.laddr — P2P is direct TCP (not proxied by nginx or Akash ingress).
    # Always bind on all interfaces so the NodePort can reach the container.
    sed -i \
        -e "/^\[p2p\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://0.0.0.0:${P2P_P}\"|" \
        "${PROJECT_ROOT}/config/config.toml"

  # external_address — advertise the Akash NodePort IP so remote peers and
  # statesync clients can actually reach this node for chunk downloads.
  # P2P traffic is direct TCP (no nginx/TLS), so P2P_D resolves to the
  # Akash provider host IP where the NodePort lives.
  # We resolve to an IP (not a hostname) so CometBFT doesn't try DNS at startup.
  _ext_ip=""
  for _try in $(seq 1 18); do
    _ext_ip=$(getent ahosts "${P2P_D}" 2>/dev/null | awk '/STREAM/{print $1; exit}')
    [ -z "$_ext_ip" ] && _ext_ip=$(dig +short "${P2P_D}" 2>/dev/null | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    [ -n "$_ext_ip" ] && break
    log "Waiting for P2P DNS (${P2P_D}) to resolve — attempt ${_try}/18..."
    sleep 10
  done
  if [ -n "$_ext_ip" ]; then
    log "Setting external_address = tcp://${_ext_ip}:${P2P_P} (resolved from ${P2P_D})"
    sed -i \
        -e "/^\[p2p\]$/,/^\[/ s|^external_address *=.*|external_address = \"tcp://${_ext_ip}:${P2P_P}\"|" \
        "${PROJECT_ROOT}/config/config.toml"
  else
    log "WARNING: Could not resolve ${P2P_D} after 3 min — external_address not set. Statesync chunk serving may fail."
  fi
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

# state-sync snapshot settings — patch app.toml [state-sync] section.
#
# snapshot-interval: how often to take an ABCI snapshot (in blocks).
#   Accepts STATESYNC_SNAPSHOT_INTERVAL (SDL snapshot node) or STATESYNC_SNAP_INTERVAL.
#   Cosmos SDK retains snapshot heights during creation regardless of pruning,
#   so any pruning mode is compatible. 0 = disabled (default).
#
# snapshot-keep-recent: number of recent snapshots to keep on disk.
#   Align with pruning: keep enough snapshots to cover the statesync trust window.
#   E.g. snapshot-interval=500, snapshot-keep-recent=2 → 1000 blocks of snapshots
#   available, matching the trust_height offset (latest - 1000) in oline-entrypoint.sh.
#   0 = keep all (not recommended for disk space).
_ss_interval="${STATESYNC_SNAPSHOT_INTERVAL:-${STATESYNC_SNAP_INTERVAL:-}}"
_ss_keep="${STATESYNC_SNAPSHOT_KEEP_RECENT:-}"
if [ -n "$_ss_interval" ] && [ "$_ss_interval" != "0" ] && [ -f "${PROJECT_ROOT}/config/app.toml" ]; then
  log "Patching state-sync.snapshot-interval = ${_ss_interval} in app.toml..."
  sed -i \
      -e "/^\[state-sync\]$/,/^\[/ s|^snapshot-interval *=.*|snapshot-interval = ${_ss_interval}|" \
      "${PROJECT_ROOT}/config/app.toml"
  # Set snapshot-keep-recent when explicitly configured.
  # Default cosmos-sdk value is 2 — only override when provided.
  if [ -n "$_ss_keep" ]; then
    log "Patching state-sync.snapshot-keep-recent = ${_ss_keep} in app.toml..."
    sed -i \
        -e "/^\[state-sync\]$/,/^\[/ s|^snapshot-keep-recent *=.*|snapshot-keep-recent = ${_ss_keep}|" \
        "${PROJECT_ROOT}/config/app.toml"
  fi
fi
unset _ss_interval _ss_keep
