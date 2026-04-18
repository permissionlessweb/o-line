#!/bin/bash

set -e

[ "$DEBUG" == "2" ] && set -x

die() { echo "ERROR: $*" >&2; exit 1; }

# ── Bootstrap mode (default) ──────────────────────────────────────────────────
# Installs sshd and registers the oline public key, then execs sshd as the
# container's main process. oline will SFTP the TLS certs, verify them via SSH,
# then invoke this script again with OLINE_PHASE=start to run the cosmos setup.
# No wait loops — SSH access is the synchronization point.
if [ "${OLINE_PHASE:-bootstrap}" = "bootstrap" ]; then
  # ── Fast-path restart: skip bootstrap if marker exists ──
  _MARKER="${PROJECT_ROOT:-/root/.terpd}/.oline_bootstrapped"
  if [ -f "$_MARKER" ] && [ "${OLINE_FORCE_BOOTSTRAP:-}" != "1" ]; then
    echo "[oline] Bootstrap marker found at $_MARKER — skipping to node start."
    # Ensure SSH is available for debugging
    if [ -n "${SSH_PUBKEY:-}" ]; then
      mkdir -p /root/.ssh
      echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
      chmod 600 /root/.ssh/authorized_keys
    fi
    _SSHD=$(command -v sshd 2>/dev/null || { [ -x /usr/sbin/sshd ] && echo /usr/sbin/sshd; } || true)
    if [ -n "$_SSHD" ]; then
      ssh-keygen -A 2>/dev/null || true
      mkdir -p /run/sshd 2>/dev/null || true
      sed -i "s/#PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config 2>/dev/null || true
      $_SSHD 2>/dev/null || true
      echo "[oline] sshd started (restart fast-path)"
    fi
    # Jump directly to the start phase
    OLINE_PHASE=start
  fi
fi

if [ "${OLINE_PHASE:-bootstrap}" = "bootstrap" ]; then
  # fail fast before doing any slow work
  if [[ "$SNAPSHOT_RETAIN" != "0" ]] && ! date -d "-$SNAPSHOT_RETAIN" >/dev/null 2>&1; then
    echo "ERROR: Invalid SNAPSHOT_RETAIN value '$SNAPSHOT_RETAIN'. Expected format: '<N> minutes|hours|days|weeks|months'"
    exit 1
  fi

  [ -n "$SSH_PUBKEY" ] || die "SSH_PUBKEY is required in bootstrap mode"

  mkdir -p /root/.ssh
  echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys

  if ! command -v sshd >/dev/null 2>&1 && ! [ -x /usr/sbin/sshd ] && ! [ -x /sbin/sshd ]; then
    echo "[oline] Installing openssh-server..."
    _installed=0
    for _try in 1 2 3; do
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq 2>&1 | tail -3 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server 2>&1 \
          && _installed=1 && break
      elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache openssh 2>&1 && _installed=1 && break
      else
        echo "[oline] No package manager found (not apt-get or apk)" && break
      fi
      echo "[oline] openssh install attempt $_try failed, retrying in 5s..."
      sleep 5
    done
    [ "$_installed" = "0" ] && echo "[oline] Warning: openssh-server install failed after 3 tries"
  fi

  # Check common sshd locations (command -v may miss /usr/sbin on some images)
  SSHD_BIN=$(command -v sshd 2>/dev/null \
    || { [ -x /usr/sbin/sshd ] && echo /usr/sbin/sshd; } \
    || { [ -x /sbin/sshd ]     && echo /sbin/sshd; } \
    || true)
  [ -z "$SSHD_BIN" ] && die "sshd not found — openssh-server package unavailable on this provider image"
  mkdir -p /run/sshd /var/run/sshd
  ssh-keygen -A >/dev/null 2>&1 || true
  printf '\nPermitRootLogin yes\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config

  mkdir -p /tmp/tls

  # Persist all SDL env vars so start mode (SSH session) can restore them.
  # SSH sessions begin with a minimal environment — SDL vars won't be present otherwise.
  export -p | grep -v 'OLINE_PHASE' > /tmp/oline-env.sh

  echo "Bootstrap complete — sshd started. oline will connect shortly."
  # Run sshd in background; keep the shell as PID 1 so container stdout stays
  # open for provider log streaming. The start-phase script writes to
  # /proc/1/fd/1 which is this shell's stdout — visible via lease-logs / TUI.
  "$SSHD_BIN" -D &
  wait
  exit 0
fi
# ─────────────────────────────────────────────────────────────────────────────

# ── Restart mode (OLINE_PHASE=restart) ──────────────────────────────────────
# Invoked by `oline manage restart`. Kills the running node process, restores
# environment from oline-env.sh, then falls through to start mode for a full
# re-bootstrap (TLS setup → chain metadata → snapshot → config → node launch).
if [ "${OLINE_PHASE}" = "restart" ]; then
  [ -f /tmp/oline-env.sh ] && . /tmp/oline-env.sh
  RESTART_BIN="${PROJECT_BIN:-terpd}"
  echo "=== Restart mode: killing ${RESTART_BIN} ==="
  pkill -f "${RESTART_BIN} start" 2>/dev/null || true
  sleep 2
  export OLINE_PHASE=start
  # Fall through to start mode
fi

# ── Start mode (OLINE_PHASE=start) ────────────────────────────────────────────
# Invoked by oline via SSH after cert verification. Restores the SDL environment
# saved during bootstrap, runs TLS setup, then falls through to cosmos setup.

# Trap any unexpected exit and log the line number + exit code so we can see
# exactly where the script died (set -e exits are otherwise silent).
trap 'rc=$?; [ $rc -ne 0 ] && echo "=== UNEXPECTED EXIT code=$rc at line $LINENO: $BASH_COMMAND ===" >&2' EXIT

# Ensure required tools are available — some provider base images do not include all of these.
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq coreutils file pv lz4 zstd unzip wget >/dev/null 2>&1
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache coreutils file pv lz4 zstd unzip wget >/dev/null 2>&1
fi

[ -f /tmp/oline-env.sh ] && . /tmp/oline-env.sh

# Self-override: if the oline deployer pre-uploaded a local entrypoint, exec
# into it now so iteration doesn't require a GitHub push.
# OLINE_LOCAL_ENTRYPOINT=1 is set before exec to prevent infinite re-exec.
if [ -z "${OLINE_LOCAL_ENTRYPOINT:-}" ] && [ -f /tmp/oline-entrypoint-local.sh ]; then
  echo "Using pre-uploaded oline-entrypoint-local.sh"
  export OLINE_LOCAL_ENTRYPOINT=1
  exec bash /tmp/oline-entrypoint-local.sh "$@"
fi

# -- Patch: write Alpine 3.17-compatible grpc nginx template --
# Alpine 3.17 nginx does not support standalone "http2 on;" directive --
# HTTP/2 must be on the listen line: "listen ... ssl http2;"
mkdir -p /tmp/nginx
cat > /tmp/nginx/grpc << 'GRPC_TMPL'
server {
    listen      9091 ssl http2;
    server_name ${GRPC_D};

    ssl_certificate     ${TLS_CERT};
    ssl_certificate_key ${TLS_KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        grpc_pass            grpc://127.0.0.1:${GRPC_P};
        grpc_set_header Host $host;
    }
}
GRPC_TMPL

if [ -f /tmp/tls-setup.sh ]; then
  echo "Running TLS setup (pre-uploaded)..."
  sh /tmp/tls-setup.sh
  echo "=== TLS setup complete ==="
  nginx -s reload 2>/dev/null || nginx
  echo "=== nginx started ==="
elif [ -n "$TLS_CONFIG_URL" ]; then
  echo "Running TLS setup (downloading from $TLS_CONFIG_URL)..."
  curl -fsSL "$TLS_CONFIG_URL" -o /tmp/tls-setup.sh
  sh /tmp/tls-setup.sh
  echo "=== TLS setup complete ==="
  nginx -s reload 2>/dev/null || nginx
  echo "=== nginx started ==="
fi
# ─────────────────────────────────────────────────────────────────────────────


# ── Detect native mode ─────────────────────────────────────────────────────
# If terpd binary is pre-installed AND has the bootstrap subcommand, use the
# native terp-core bootstrap path. Otherwise fall through to omnibus setup.
OLINE_NODE_MODE="${OLINE_NODE_MODE:-omnibus}"
if command -v terpd >/dev/null 2>&1 && terpd bootstrap --help >/dev/null 2>&1; then
  OLINE_NODE_MODE="native"
  echo "[oline] Native mode detected — using terpd bootstrap"
fi

if [ "$OLINE_NODE_MODE" = "native" ]; then
  # Default PROJECT_ROOT for terpd (used by config-node-endpoints.sh)
  export PROJECT_ROOT="${PROJECT_ROOT:-/terpd/.terpd}"

  # ── Build terpd bootstrap args from SDL environment ──
  BOOTSTRAP_ARGS=""

  # Network preset or explicit chain-id
  case "${CHAIN_ID:-morocco-1}" in
    morocco-1) BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --network morocco-1" ;;
    90u-4)     BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --network 90u-4" ;;
    *)         BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --chain-id ${CHAIN_ID}" ;;
  esac

  # Sync mode — driven by OLINE_SYNC_METHOD (default: snapshot)
  # When snapshot: always pass --sync-mode snapshot (even without URL — SFTP delivers data)
  # When statesync: pass --sync-mode statesync + RPC servers
  _sync="${OLINE_SYNC_METHOD:-snapshot}"
  if [ "$_sync" = "statesync" ] && [ -n "$STATESYNC_RPC_SERVERS" ]; then
    BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --sync-mode statesync"
    BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --statesync-rpcs $STATESYNC_RPC_SERVERS"
  else
    # Snapshot mode (default) — always set sync-mode to prevent terpd preset from using statesync
    BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --sync-mode snapshot"
    [ -n "$SNAPSHOT_URL" ] && BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --snapshot-url $SNAPSHOT_URL"
  fi

  # Moniker
  [ -n "$MONIKER" ] && BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --moniker $MONIKER"

  # Peers
  _peers="${TERPD_P2P_PERSISTENT_PEERS:-$P2P_PERSISTENT_PEERS}"
  [ -n "$_peers" ] && BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --bootstrap-peers $_peers"
  _seeds="${P2P_SEEDS:-}"
  [ -n "$_seeds" ] && BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --bootstrap-seeds $_seeds"

  # Public mode for sentry nodes (PEX enabled, accept inbound)
  [ "${TERPD_P2P_PEX:-true}" = "true" ] && BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --public"

  # Pruning
  [ -n "$PRUNING" ] && BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --pruning $PRUNING"

  # Genesis override
  [ -n "$GENESIS_URL" ] && BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --genesis-url $GENESIS_URL"

  echo "[oline] terpd bootstrap $BOOTSTRAP_ARGS"

  # ── SFTP snapshot delivery (Phase B/C) ──────────────────────────────────
  if [ "${SNAPSHOT_MODE:-remote}" = "sftp" ]; then
    SNAPSHOT_SFTP_PATH="${SNAPSHOT_SFTP_PATH:-/tmp/snapshot.tar.lz4}"
    SNAPSHOT_SFTP_WAIT="${SNAPSHOT_SFTP_WAIT:-3600}"
    echo "=== [snapshot] SFTP mode — waiting for ${SNAPSHOT_SFTP_PATH} ==="
    _waited=0
    while [ ! -f "$SNAPSHOT_SFTP_PATH" ]; do
      [ "$_waited" -ge "$SNAPSHOT_SFTP_WAIT" ] && { echo "ERROR: SFTP timeout"; exit 1; }
      sleep 10; _waited=$((_waited + 10))
      [ $((_waited % 60)) -eq 0 ] && echo "  [snapshot] Still waiting... (${_waited}s elapsed)"
    done
    echo "=== [snapshot] File received. Extracting to ${PROJECT_ROOT} ==="
    mkdir -p "${PROJECT_ROOT}/data"
    cd "${PROJECT_ROOT}" 
    case "${SNAPSHOT_SFTP_PATH}" in
      *.tar.lz4) lz4 -d "$SNAPSHOT_SFTP_PATH" | tar xf - ;;
      *.tar.zst) zstd -cd "$SNAPSHOT_SFTP_PATH" | tar xf - ;;
      *.tar.gz)  tar xzf "$SNAPSHOT_SFTP_PATH" ;;
      *)         tar xf  "$SNAPSHOT_SFTP_PATH" ;;
    esac
    rm -f "$SNAPSHOT_SFTP_PATH"
    echo "=== [snapshot] SFTP snapshot installed ==="
    # Data already extracted — strip sync args so bootstrap skips download.
    BOOTSTRAP_ARGS=$(echo "$BOOTSTRAP_ARGS" | sed 's/--sync-mode [a-z]*//g; s/--snapshot-url [^ ]*//g; s/--statesync-rpcs [^ ]*//g')
  fi

  # ── Snapshot export node: setup-only, then wrap with snapshot.sh ──
  if [ -n "$SNAPSHOT_PATH" ]; then
    terpd bootstrap --setup-only $BOOTSTRAP_ARGS >>/proc/1/fd/1 2>&1
    # Use pre-uploaded snapshot.sh if available, otherwise try download
    if [ -f /tmp/snapshot.sh ]; then
      cp /tmp/snapshot.sh /usr/local/bin/snapshot.sh
      chmod +x /usr/local/bin/snapshot.sh
      echo "[oline] Using pre-uploaded snapshot.sh"
    elif [ -n "$SNAPSHOT_SCRIPT_URL" ]; then
      curl -fsSL "$SNAPSHOT_SCRIPT_URL" -o /usr/local/bin/snapshot.sh 2>/dev/null &&\
        chmod +x /usr/local/bin/snapshot.sh || true
    fi
    NODE_SCRIPT=/tmp/node-config.sh
    if [ ! -f "$NODE_SCRIPT" ]; then
      NODE_CONFIG_SCRIPT="${NODE_CONFIG_SCRIPT:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/audible/config-node-endpoints.sh}"
      curl -fsSL "${NODE_CONFIG_SCRIPT}" -o "$NODE_SCRIPT" 2>/dev/null || true
    fi
    [ -f "$NODE_SCRIPT" ] && { sh "$NODE_SCRIPT" 2>&1 || echo "[oline] config-node-endpoints non-fatal"; }
    if [ -x /usr/local/bin/snapshot.sh ]; then
      echo "=== Launching: snapshot.sh terpd start ==="
      exec snapshot.sh "terpd start" >>/proc/1/fd/1 2>&1
    else
      echo "[oline] snapshot.sh not available -- starting terpd directly"
      exec terpd start >>/proc/1/fd/1 2>&1
    fi
  fi

  # ── Non-snapshot node: setup-only, patch endpoints, then start ──
  terpd bootstrap --setup-only $BOOTSTRAP_ARGS >>/proc/1/fd/1 2>&1
  NODE_SCRIPT=/tmp/node-config.sh
  if [ ! -f "$NODE_SCRIPT" ]; then
    NODE_CONFIG_SCRIPT="${NODE_CONFIG_SCRIPT:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/audible/config-node-endpoints.sh}"
    curl -fsSL "${NODE_CONFIG_SCRIPT}" -o "$NODE_SCRIPT" 2>/dev/null || true
  fi
  [ -f "$NODE_SCRIPT" ] && { sh "$NODE_SCRIPT" 2>&1 || echo "[oline] config-node-endpoints non-fatal"; }

  # Final peer patch
  if [ -f "${PROJECT_ROOT:-/root/.terpd}/config/config.toml" ]; then
    _peer_patch() {
      local _key="$1" _val="$2"
      if [ -n "$_val" ] && [ "$_val" != "0" ]; then
        sed -i "/^\[p2p\]$/,/^\[/ s|^${_key} *=.*|${_key} = \"${_val}\"|" \
            "${PROJECT_ROOT:-/root/.terpd}/config/config.toml"
      fi
    }
    _peer_patch "persistent_peers"    "${TERPD_P2P_PERSISTENT_PEERS:-}"
    _peer_patch "private_peer_ids"    "${TERPD_P2P_PRIVATE_PEER_IDS:-}"
    unset -f _peer_patch
  fi

  [ -n "$TLS_CONFIG_URL" ] && { nginx -s reload 2>/dev/null || nginx; }

  echo "=== Launching: terpd start ==="
  exec terpd start >>/proc/1/fd/1 2>&1
fi

# ── Omnibus path (existing code continues below unchanged) ──

echo "=== Cosmos node setup starting ==="

export CHAIN_JSON="${CHAIN_JSON:-$CHAIN_URL}" 
if [[ -z "$CHAIN_JSON" && -n "$PROJECT" ]]; then
  CHAIN_JSON="https://raw.githubusercontent.com/permissionlessweb/chain-registry/refs/heads/terp%40v5.1.0/${PROJECT}/chain.json"
  
fi

CHAIN_JSON_EXISTS=false
CHAIN_METADATA=""
# Use deployer-uploaded local chain.json if available (takes precedence over URL).
# The deployer writes templates/json/chain.json to /tmp/chain.json via SFTP.
if [ -f /tmp/chain.json ]; then
  echo "Using pre-uploaded chain.json"
  CHAIN_JSON_EXISTS=true
  CHAIN_METADATA=$(cat /tmp/chain.json)
elif [[ -n "$CHAIN_JSON" && "$CHAIN_JSON" != "0" ]]; then
  if curl --output /dev/null --silent --head --fail "$CHAIN_JSON"; then
    CHAIN_JSON_EXISTS=true
  else
    echo "ERROR: Chain JSON not found at $CHAIN_JSON — deploy templates/json/chain.json locally as fallback"
  fi
fi
if [[ $CHAIN_JSON_EXISTS == true ]]; then
  if [ -z "$CHAIN_METADATA" ]; then
    sleep 0.5 # avoid rate limiting
    CHAIN_METADATA=$(curl -Ls $CHAIN_JSON)
  fi
  CHAIN_SEEDS=$(echo $CHAIN_METADATA | jq -r '.peers.seeds? // [] | map(.id+"@"+.address) | join(",")')
  CHAIN_PERSISTENT_PEERS=$(echo "$CHAIN_METADATA" | jq -r '.peers.persistent_peers? // [] | map(.id+"@"+.address) | join(",")')

  export CHAIN_ID="${CHAIN_ID:-$(echo "$CHAIN_METADATA" | jq -r .chain_id)}"
  export GENESIS_URL="${GENESIS_URL:-$(echo $CHAIN_METADATA | jq -r '.codebase.genesis.genesis_url? // .genesis.genesis_url? // .genesis?')}"
  export BINARY_URL="${BINARY_URL:-$(echo "$CHAIN_METADATA" | jq -r '.codebase.binaries."linux/amd64"?')}"
  export PROJECT="${PROJECT:-$(echo $CHAIN_METADATA | jq -r '.chain_name?')}"
  export PROJECT_BIN="${PROJECT_BIN:-$(echo $CHAIN_METADATA | jq -r '.codebase.daemon_name? // .daemon_name?')}"
  if [ -z "$PROJECT_DIR" ]; then
    FULL_DIR=$(echo $CHAIN_METADATA | jq -r '.codebase.node_home? // .node_home?')
    [ -n "$FULL_DIR" ] && export PROJECT_DIR=${FULL_DIR#'$HOME/'}
  fi

  if [ -z "$MINIMUM_GAS_PRICES" ]; then
    GAS_PRICES=""
    FEE_TOKENS=$(echo $CHAIN_METADATA | jq -c '.fees.fee_tokens[]? // empty')
    if [ -n "$FEE_TOKENS" ]; then
      for TOKEN in $FEE_TOKENS; do
        FEE_TOKEN=$(echo $TOKEN | jq -r '.denom // empty')
        GAS_PRICE=$(echo $TOKEN | jq -r '.fixed_min_gas_price // .low_gas_price // empty')
        if [ -n "$FEE_TOKEN" ] && [ -n "$GAS_PRICE" ]; then
          if [ -n "$GAS_PRICES" ]; then
            GAS_PRICES="$GAS_PRICES,$GAS_PRICE$FEE_TOKEN"
          else
            GAS_PRICES="$GAS_PRICE$FEE_TOKEN"
          fi
        fi
      done
      if [ -n "$GAS_PRICES" ]; then
        export MINIMUM_GAS_PRICES=$GAS_PRICES
        echo "Minimum gas prices set to $MINIMUM_GAS_PRICES"
      fi
    fi
  fi
fi

# ── OLINE_OFFLINE mode ─────────────────────────────────────────────────────
# Phase B/C nodes receive ALL data via SFTP — no internet downloads.
# Phase A (special teams) does NOT set this variable and behaves normally.
if [ "${OLINE_OFFLINE:-0}" = "1" ]; then
  echo "[oline] OFFLINE MODE — no internet downloads permitted"

  # Validate required SFTP-delivered files
  if [ ! -f /tmp/chain.json ]; then
    die "OLINE_OFFLINE=1 but /tmp/chain.json not found — SFTP delivery failed"
  fi

  # Install genesis.json from SFTP delivery (snapshot only contains data/, not config/)
  if [ -f /tmp/genesis.json ]; then
    echo "[oline] Installed genesis.json from SFTP delivery"
  fi

  # Install addrbook.json from SFTP delivery
  if [ -f /tmp/addrbook.json ]; then
    echo "[oline] Installed addrbook.json from SFTP delivery"
  fi

  # Suppress all remote download variables — entrypoint must not fetch anything
  unset BINARY_URL WASMVM_URL WASMVM_VERSION GENESIS_URL ADDRBOOK_URL \
        SNAPSHOT_URL SNAPSHOT_BASE_URL SNAPSHOT_JSON SNAPSHOT_QUICKSYNC
  export DOWNLOAD_GENESIS=""
fi

# ── Operator snapshot override ────────────────────────────────────────────────
# OLINE_SNAPSHOT_URL is an explicit operator-supplied snapshot URL that
# takes priority over chain-registry resolution. Survives OFFLINE mode because
# the operator knows best.
if [ -n "$OLINE_SNAPSHOT_URL" ] && [ -z "$SNAPSHOT_URL" ]; then
  export SNAPSHOT_URL="$OLINE_SNAPSHOT_URL"
fi

export PROJECT_BIN="${PROJECT_BIN:-$PROJECT}"
export PROJECT_DIR="${PROJECT_DIR:-.$PROJECT_BIN}"
export CONFIG_DIR="${CONFIG_DIR:-config}"
export DATA_DIR="${DATA_DIR:-data}"
export WASM_DIR="${WASM_DIR:-wasm}"
export PROJECT_ROOT="/root/$PROJECT_DIR"
export CONFIG_PATH="${CONFIG_PATH:-$PROJECT_ROOT/$CONFIG_DIR}"
export DATA_PATH="${DATA_PATH:-$PROJECT_ROOT/$DATA_DIR}"
export WASM_PATH="${WASM_PATH:-$PROJECT_ROOT/$WASM_DIR}"
export NAMESPACE="${NAMESPACE:-$(echo ${PROJECT_BIN} | tr '[:lower:]' '[:upper:]' | tr '-' '_')}"
export VALIDATE_GENESIS="${VALIDATE_GENESIS:-0}"
export MONIKER="${MONIKER:-Cosmos Omnibus Node}"
# GCS support
export GCS_ENABLED="${GCS_ENABLED:-0}"
export GCS_BUCKET_PATH="${GCS_BUCKET_PATH}"
export GCS_KEY_FILE="${GCS_KEY_FILE}"

# ── OLINE_OFFLINE: install SFTP-delivered files now that CONFIG_PATH is set ──
if [ "${OLINE_OFFLINE:-0}" = "1" ]; then
  mkdir -p "$CONFIG_PATH"
  if [ -f /tmp/genesis.json ]; then
    cp /tmp/genesis.json "$CONFIG_PATH/genesis.json"
  fi
  if [ -f /tmp/addrbook.json ]; then
    cp /tmp/addrbook.json "$CONFIG_PATH/addrbook.json"
  fi
fi

# Validate GCS config
if [ "$GCS_ENABLED" == "1" ]; then
  if [ -z "$GCS_BUCKET_PATH" ]; then
    echo "ERROR: GCS_BUCKET_PATH must be set when GCS_ENABLED=1"
    exit 1
  fi

  if [ -z "$GCS_KEY_FILE" ]; then
    echo "ERROR: GCS_KEY_FILE must be set when GCS_ENABLED=1"
    exit 1
  fi

  if [ ! -f "$GCS_KEY_FILE" ]; then
    echo "ERROR: GCS_KEY_FILE not found at '$GCS_KEY_FILE'"
    exit 1
  fi
fi

if [ -z "$CHAIN_ID" ]; then
  echo "ERROR: CHAIN_ID not found — check CHAIN_ID or CHAIN_JSON env vars"
  echo "  CHAIN_ID='$CHAIN_ID'"
  echo "  CHAIN_JSON='$CHAIN_JSON'"
  echo "  CHAIN_JSON_EXISTS=$CHAIN_JSON_EXISTS"
  exit 1
fi

if [[ -n "$BINARY_URL" && ! -f "/bin/$PROJECT_BIN" ]]; then
  echo "Download binary $PROJECT_BIN from $BINARY_URL"
  curl -Lso /bin/$PROJECT_BIN $BINARY_URL
  file_description=$(file /bin/$PROJECT_BIN)
  case "${file_description,,}" in
    *"gzip compressed data"*)  mv /bin/$PROJECT_BIN /bin/$PROJECT_BIN.tgz && tar -xvf /bin/$PROJECT_BIN.tgz -C /bin && rm /bin/$PROJECT_BIN.tgz ;;
    *"tar archive"*)           mv /bin/$PROJECT_BIN /bin/$PROJECT_BIN.tar && tar -xf /bin/$PROJECT_BIN.tar -C /bin && rm /bin/$PROJECT_BIN.tar ;;
    *"zip archive data"*)      mv /bin/$PROJECT_BIN /bin/$PROJECT_BIN.zip && unzip /bin/$PROJECT_BIN.zip -d /bin && rm /bin/$PROJECT_BIN.zip ;;
  esac
  [ -n "$BINARY_ZIP_PATH" ] && mv /bin/${BINARY_ZIP_PATH} /bin/$PROJECT_BIN
  chmod +x /bin/$PROJECT_BIN

  if [[ -n "$WASMVM_VERSION" && -z "$WASMVM_URL" ]]; then
    WASMVM_URL="https://raw.githubusercontent.com/CosmWasm/wasmvm/${WASMVM_VERSION}/api/libwasmvm.so"
  fi

  if [ -n "$WASMVM_URL" ]; then
    WASMVM_PATH="${WASMVM_PATH:-/lib/libwasmvm.so}"
    echo "Downloading wasmvm from $WASMVM_URL..."
    curl -Ls $WASMVM_URL > $WASMVM_PATH
  fi
fi

storj_args="${STORJ_UPLINK_ARGS:--p 4 --progress=false}"

if [ -n "$STORJ_ACCESS_GRANT" ]; then
  uplink access import --force --interactive=false default "$STORJ_ACCESS_GRANT"
fi

if [ "$GCS_ENABLED" == "1" ] && [ -n "$GCS_BUCKET_PATH" ]; then
  GOOGLE_APPLICATION_CREDENTIALS="$GCS_KEY_FILE"
  echo "Activating GCS service account..."
  gcloud auth activate-service-account --key-file="$GCS_KEY_FILE"
fi

if [ -n "$KEY_PATH" ]; then
  if [ -n "$STORJ_ACCESS_GRANT" ]; then
    key_transport="uplink"
    key_get_cmd="$key_transport cp"
    key_put_cmd="$key_transport cp"
    key_uri_base="sj://${KEY_PATH%/}"
  elif [ "$GCS_ENABLED" == "1" ]; then
    key_transport="gsutil"
    key_get_cmd="gsutil -q cp"
    key_put_cmd="gsutil -q cp"
    key_uri_base="${KEY_PATH%/}"
  else
    aws_args="--host=${S3_HOST:-https://s3.filebase.com}"
    aws_args="$aws_args --host-bucket=$(echo "$KEY_PATH" | cut -d'/' -f1)"
    aws_args="$aws_args --access_key=${S3_KEY}"
    aws_args="$aws_args --secret_key=${S3_SECRET}"
    key_transport="s3cmd $aws_args"
    key_get_cmd="$key_transport get"
    key_put_cmd="$key_transport put"
    key_uri_base="s3://${KEY_PATH%/}"
  fi
  if [ -n "$KEY_PASSWORD" ]; then
    file_suffix=".gpg"
  else
    file_suffix=""
  fi
fi

restore_key () {
  existing=$($key_transport ls "${key_uri_base}/$1" | head -n 1)
  if [[ -z $existing ]]; then
    echo "$1 backup not found"
  else
    echo "Restoring $1"
    $key_get_cmd "${key_uri_base}/$1" $CONFIG_PATH/$1$file_suffix

    if [ -n "$KEY_PASSWORD" ]; then
      echo "Decrypting"
      gpg --decrypt --batch --passphrase "$KEY_PASSWORD" $CONFIG_PATH/$1$file_suffix > $CONFIG_PATH/$1
      rm $CONFIG_PATH/$1$file_suffix
    fi
  fi
}

backup_key () {
  existing=$($key_transport ls "${key_uri_base}/$1" | head -n 1)
  if [[ -z $existing ]]; then
    echo "Backing up $1"
    if [ -n "$KEY_PASSWORD" ]; then
      echo "Encrypting backup..."
      rm -f $CONFIG_PATH/$1.gpg
      gpg --symmetric --batch --passphrase "$KEY_PASSWORD" $CONFIG_PATH/$1
    fi
    $key_put_cmd $CONFIG_PATH/$1$file_suffix "${key_uri_base}/$1"
    [ -n "$KEY_PASSWORD" ] && rm $CONFIG_PATH/$1.gpg
  fi
}

# Config
export "${NAMESPACE}_RPC_LADDR"="${RPC_LADDR:-tcp://0.0.0.0:26657}"
export "${NAMESPACE}_MONIKER"="$MONIKER"
[ -n "$FASTSYNC_VERSION" ] && export "${NAMESPACE}_FASTSYNC_VERSION"=$FASTSYNC_VERSION
[ -n "$MINIMUM_GAS_PRICES" ] && export "${NAMESPACE}_MINIMUM_GAS_PRICES"=$MINIMUM_GAS_PRICES
[ -n "$PRUNING" ] && export "${NAMESPACE}_PRUNING"=$PRUNING
[ -n "$PRUNING_INTERVAL" ] && export "${NAMESPACE}_PRUNING_INTERVAL"=$PRUNING_INTERVAL
[ -n "$PRUNING_KEEP_EVERY" ] && export "${NAMESPACE}_PRUNING_KEEP_EVERY"=$PRUNING_KEEP_EVERY
[ -n "$PRUNING_KEEP_RECENT" ] && export "${NAMESPACE}_PRUNING_KEEP_RECENT"=$PRUNING_KEEP_RECENT
[ -n "$DOUBLE_SIGN_CHECK_HEIGHT" ] && export "${NAMESPACE}_CONSENSUS_DOUBLE_SIGN_CHECK_HEIGHT"=$DOUBLE_SIGN_CHECK_HEIGHT

# Polkachu
if [[ -n "$STATESYNC_POLKACHU" || -n "$P2P_POLKACHU" || -n "$P2P_SEEDS_POLKACHU" || -n "$P2P_PEERS_POLKACHU" || -n "$ADDRBOOK_POLKACHU" ]]; then
  export POLKACHU_CHAIN_ID="${POLKACHU_CHAIN_ID:-$PROJECT}"
  POLKACHU_CHAIN_URL="https://polkachu.com/api/v2/chains/$POLKACHU_CHAIN_ID"
  if ! curl --output /dev/null --silent --head --fail "$POLKACHU_CHAIN_URL"; then
    echo "ERROR: Polkachu chain API request failed"
  else
    POLKACHU_CHAIN=`curl -Ls $POLKACHU_CHAIN_URL | jq .`
    POLKACHU_SUCCESS=$(echo $POLKACHU_CHAIN | jq -r '.success')
    if [ $POLKACHU_SUCCESS = false ]; then
      echo "ERROR: Polkachu chain not recognised (POLKACHU_CHAIN_ID might need to be set)"
    else
      # Polkachu statesync
      if [ -n "$STATESYNC_POLKACHU" ]; then
        POLKACHU_STATESYNC_ENABLED=$(echo $POLKACHU_CHAIN | jq -r '.polkachu_services.state_sync.active')
        if [ $POLKACHU_STATESYNC_ENABLED = true ]; then
          export POLKACHU_RPC_SERVER=$(echo $POLKACHU_CHAIN | jq -r '.polkachu_services.state_sync.node')
          export STATESYNC_RPC_SERVERS="$POLKACHU_RPC_SERVER,$POLKACHU_RPC_SERVER"
          echo "Configured Polkachu statesync"
        else
          echo "ERROR: Polkachu statesync is not active for this chain"
        fi
      fi

      # Polkachu seed
      if [ "$P2P_POLKACHU" == "1" ]; then
        export P2P_SEEDS_POLKACHU="1"
        export P2P_PEERS_POLKACHU="1"
      fi

      if [ "$P2P_SEEDS_POLKACHU" == "1" ]; then
        POLKACHU_SEED_ENABLED=$(echo $POLKACHU_CHAIN | jq -r '.polkachu_services.seed.active')
        if [ $POLKACHU_SEED_ENABLED ]; then
          POLKACHU_SEED=$(echo $POLKACHU_CHAIN | jq -r '.polkachu_services.seed.seed')
          if [ -n "$P2P_SEEDS" ] && [ "$P2P_SEEDS" != "0" ]; then
            export P2P_SEEDS="$POLKACHU_SEED,$P2P_SEEDS"
          else
            export P2P_SEEDS="$POLKACHU_SEED"
          fi
          echo "Configured Polkachu seed"
        else
          echo "ERROR: Polkachu seed is not active for this chain"
        fi
      fi

      if [ "$P2P_PEERS_POLKACHU" == "1" ]; then
        POLKACHU_PEERS_ENABLED=$(echo $POLKACHU_CHAIN | jq -r '.polkachu_services.live_peers.active')
        if [ $POLKACHU_PEERS_ENABLED ]; then
          if ! curl --output /dev/null --silent --head --fail "$POLKACHU_CHAIN_URL/live_peers"; then
            echo "ERROR: Polkachu live peers API request failed"
          else
            POLKACHU_PEERS=`curl -Ls $POLKACHU_CHAIN_URL/live_peers | jq .`
            POLKACHU_PEER=$(echo $POLKACHU_PEERS | jq -r '.polkachu_peer')
            POLKACHU_LIVE_PEERS=$(echo $POLKACHU_PEERS | jq -r '.live_peers | join(",")')
            if [ -n "$P2P_PERSISTENT_PEERS" ] && [ "$P2P_PERSISTENT_PEERS" != "0" ]; then
              export P2P_PERSISTENT_PEERS="$POLKACHU_PEER,$POLKACHU_LIVE_PEERS,$P2P_PERSISTENT_PEERS"
            else
              export P2P_PERSISTENT_PEERS="$POLKACHU_PEER,$POLKACHU_LIVE_PEERS"
            fi
            echo "Configured Polkachu live peers"
          fi
        else
          echo "ERROR: Polkachu live peers is not active for this chain"
        fi
      fi

      if [ "$ADDRBOOK_POLKACHU" == "1" ]; then
        POLKACHU_ADDRBOOK_ENABLED=$(echo $POLKACHU_CHAIN | jq -r '.polkachu_services.addrbook.active')
        if [ $POLKACHU_ADDRBOOK_ENABLED ]; then
          POLKACHU_ADDRBOOK=$(echo $POLKACHU_CHAIN | jq -r '.polkachu_services.addrbook.download_url')
          export ADDRBOOK_URL="${ADDRBOOK_URL:-$POLKACHU_ADDRBOOK}"
        else
          echo "ERROR: Polkachu addrbook is not active for this chain"
        fi
      fi
    fi
  fi
fi

[ -z "$P2P_SEEDS" ] && [ -n "$CHAIN_SEEDS" ] && export P2P_SEEDS=$CHAIN_SEEDS
[ -z "$P2P_PERSISTENT_PEERS" ] && [ -n "$CHAIN_PERSISTENT_PEERS" ] && export P2P_PERSISTENT_PEERS=$CHAIN_PERSISTENT_PEERS

# Peers
[ -n "$P2P_SEEDS" ] && [ "$P2P_SEEDS" != '0' ] && export "${NAMESPACE}_P2P_SEEDS=${P2P_SEEDS}"
[ -n "$P2P_PERSISTENT_PEERS" ] && [ "$P2P_PERSISTENT_PEERS" != '0' ] && export "${NAMESPACE}_P2P_PERSISTENT_PEERS"=${P2P_PERSISTENT_PEERS}

# Statesync snapshot settings (app.toml: [state-sync])
# Accept both naming conventions: STATESYNC_SNAPSHOT_INTERVAL (SDL snapshot node)
# and STATESYNC_SNAP_INTERVAL (legacy). Correct viper key is
# ${NAMESPACE}_STATE_SYNC_SNAPSHOT_INTERVAL (not SNAP_INTERVAL).
# Belt-and-suspenders: config-node-endpoints.sh also patches app.toml directly.
_ss_interval="${STATESYNC_SNAPSHOT_INTERVAL:-$STATESYNC_SNAP_INTERVAL}"
if [ -n "$_ss_interval" ]; then
  export "${NAMESPACE}_STATE_SYNC_SNAPSHOT_INTERVAL=$_ss_interval"
fi
if [ -n "$STATESYNC_SNAPSHOT_KEEP_RECENT" ]; then
  export "${NAMESPACE}_STATE_SYNC_SNAPSHOT_KEEP_RECENT=$STATESYNC_SNAPSHOT_KEEP_RECENT"
fi
unset _ss_interval

if [ -n "$STATESYNC_RPC_SERVERS" ]; then
  export "${NAMESPACE}_STATESYNC_ENABLE=${STATESYNC_ENABLE:-true}"
  export "${NAMESPACE}_STATESYNC_RPC_SERVERS=$STATESYNC_RPC_SERVERS"
  IFS=',' read -ra rpc_servers <<< "$STATESYNC_RPC_SERVERS"
  STATESYNC_TRUSTED_NODE=${STATESYNC_TRUSTED_NODE:-${rpc_servers[0]}}
  if [ -n "$STATESYNC_TRUSTED_NODE" ]; then
    # Ensure HTTP scheme for bare host:port addresses (oline passes host:port without scheme)
    _rpc_url="$STATESYNC_TRUSTED_NODE"
    case "$_rpc_url" in http://*|https://*) ;; *) _rpc_url="http://$_rpc_url" ;; esac
    echo "Fetching statesync trust params from $_rpc_url..."
    LATEST_HEIGHT=$(curl -Ls "$_rpc_url/block" | jq -r .result.block.header.height)
    BLOCK_HEIGHT=$((LATEST_HEIGHT - 1000))
    TRUST_HASH=$(curl -Ls "$_rpc_url/block?height=$BLOCK_HEIGHT" | jq -r .result.block_id.hash)
    echo "  trust_height=$BLOCK_HEIGHT trust_hash=$TRUST_HASH"
    export "${NAMESPACE}_STATESYNC_TRUST_HEIGHT=${STATESYNC_TRUST_HEIGHT:-$BLOCK_HEIGHT}"
    export "${NAMESPACE}_STATESYNC_TRUST_HASH=${STATESYNC_TRUST_HASH:-$TRUST_HASH}"
    export "${NAMESPACE}_STATESYNC_TRUST_PERIOD=${STATESYNC_TRUST_PERIOD:-168h0m0s}"
  fi
fi

# Skip snapshot download when statesync is enabled — statesync fetches state directly.
if [[ -z $DOWNLOAD_SNAP && "${STATESYNC_ENABLE}" != "true" && ( -n $SNAPSHOT_URL || -n $SNAPSHOT_BASE_URL || -n $SNAPSHOT_JSON || -n $SNAPSHOT_QUICKSYNC ) && ! -f "$PROJECT_ROOT/data/priv_validator_state.json" ]]; then
  export DOWNLOAD_SNAP="1"
fi

# SFTP delivery mode: deployer pushes snapshot file to this node rather than
# the node downloading from broadband. Enables download-once, distribute-locally.
# Set SNAPSHOT_MODE=sftp in the SDL to activate this mode.
if [[ "${SNAPSHOT_MODE:-remote}" == "sftp" && ! -f "$PROJECT_ROOT/data/priv_validator_state.json" ]]; then
  export DOWNLOAD_SNAP="1"
fi

if [[ -z $DOWNLOAD_GENESIS && -n $GENESIS_URL && ! -f "$CONFIG_PATH/genesis.json" ]]; then
  export DOWNLOAD_GENESIS="1"
fi

if [[ -z $INIT_CONFIG && ! -d "$CONFIG_PATH" ]]; then
  export INIT_CONFIG="1"
fi

[ "$DEBUG" == "1" ] && printenv

# Initialise
if [ "$INIT_CONFIG" == "1" ]; then
  if [ -n "$INIT_CMD" ]; then
    $INIT_CMD "$MONIKER" --chain-id ${CHAIN_ID}
  else
    $PROJECT_BIN init "$MONIKER" --chain-id ${CHAIN_ID}
  fi
fi

# Overwrite seeds in config.toml for chains that are not using the env variable correctly
if [ "$OVERWRITE_SEEDS" == "1" ]; then
    sed -i "s/seeds = \"\"/seeds = \"$P2P_SEEDS\"/" $CONFIG_PATH/config.toml
fi

# Restore keys
if [ -n "$KEY_PATH" ]; then
  restore_key "node_key.json"
  restore_key "priv_validator_key.json"
fi

# Backup keys
if [ -n "$KEY_PATH" ]; then
  backup_key "node_key.json"
  backup_key "priv_validator_key.json"
fi

# Addressbook
if [ -n "$ADDRBOOK_URL" ]; then
  echo "Downloading addrbook from $ADDRBOOK_URL..."
  curl -sfL $ADDRBOOK_URL > $CONFIG_PATH/addrbook.json
fi

# Download genesis
if [ "$DOWNLOAD_GENESIS" == "1" ]; then
  GENESIS_FILENAME="${GENESIS_FILENAME:-genesis.json}"

  echo "Downloading genesis $GENESIS_URL"
  curl -sfL $GENESIS_URL > genesis.json
  file genesis.json | grep -q 'gzip compressed data' && mv genesis.json genesis.json.gz && gzip -d genesis.json.gz
  file genesis.json | grep -q 'tar archive' && mv genesis.json genesis.json.tar && tar -xf genesis.json.tar && rm genesis.json.tar
  file genesis.json | grep -q 'Zip archive data' && mv genesis.json genesis.json.zip && unzip -o genesis.json.zip

  mkdir -p $CONFIG_PATH
  mv $GENESIS_FILENAME $CONFIG_PATH/genesis.json
fi

# Snapshot
if [ "$DOWNLOAD_SNAP" == "1" ]; then

  # ── SFTP delivery mode ────────────────────────────────────────────────────────
  # Deployer pushes the snapshot archive via SFTP after this node's SSH comes up.
  # Node waits for the file rather than downloading from broadband.
  # env: SNAPSHOT_SFTP_PATH (default /tmp/snapshot.tar.lz4)
  #      SNAPSHOT_SFTP_WAIT (default 3600s timeout)
  if [ "${SNAPSHOT_MODE:-remote}" = "sftp" ]; then
    SNAPSHOT_SFTP_PATH="${SNAPSHOT_SFTP_PATH:-/tmp/snapshot.tar.lz4}"
    SNAPSHOT_SFTP_WAIT="${SNAPSHOT_SFTP_WAIT:-3600}"
    echo "=== [snapshot] SFTP mode — waiting for deployer to push ${SNAPSHOT_SFTP_PATH} (timeout: ${SNAPSHOT_SFTP_WAIT}s) ==="
    _waited=0
    while [ ! -f "$SNAPSHOT_SFTP_PATH" ]; do
      if [ "$_waited" -ge "$SNAPSHOT_SFTP_WAIT" ]; then
        echo "ERROR: [snapshot] Timed out after ${_waited}s — ${SNAPSHOT_SFTP_PATH} never arrived"
        exit 1
      fi
      sleep 10; _waited=$((_waited + 10))
      [ $((_waited % 60)) -eq 0 ] && echo "  [snapshot] Still waiting... (${_waited}s elapsed)"
    done
    echo "=== [snapshot] File received. Extracting ${SNAPSHOT_SFTP_PATH} ==="
    rm -rf "$PROJECT_ROOT/snapshot"; mkdir -p "$PROJECT_ROOT/snapshot"
    cd "$PROJECT_ROOT/snapshot"
    case "${SNAPSHOT_SFTP_PATH}" in
      *.tar.lz4) lz4 -d "$SNAPSHOT_SFTP_PATH" | tar xf - ;;
      *.tar.zst) zstd -cd "$SNAPSHOT_SFTP_PATH" | tar xf - ;;
      *.tar.gz)  tar xzf "$SNAPSHOT_SFTP_PATH" ;;
      *)         tar xf  "$SNAPSHOT_SFTP_PATH" ;;
    esac
    [ -z "${SNAPSHOT_DATA_PATH}" ] && [ -d "./${DATA_DIR}" ] && SNAPSHOT_DATA_PATH="${DATA_DIR}"
    [ -z "${SNAPSHOT_WASM_PATH}" ] && [ -d "./${WASM_DIR}" ] && SNAPSHOT_WASM_PATH="${WASM_DIR}"
    [ -n "${SNAPSHOT_DATA_PATH}" ] && { rm -rf "../$DATA_DIR"; mv "./${SNAPSHOT_DATA_PATH}" "../$DATA_DIR"; }
    [ -n "${SNAPSHOT_WASM_PATH}" ] && { rm -rf "../$WASM_DIR"; mv "./${SNAPSHOT_WASM_PATH}" "../$WASM_DIR"; }
    if [ -z "${SNAPSHOT_DATA_PATH}" ]; then
      rm -rf "../$DATA_DIR" && mkdir -p "../$DATA_DIR"; mv ./* "../$DATA_DIR"
    fi
    cd ../ && rm -rf ./snapshot
    rm -f "$SNAPSHOT_SFTP_PATH"
    echo "=== [snapshot] Installed from SFTP delivery ==="

  else
  # ── Remote download mode (default) ────────────────────────────────────────────

  if [ -z "${SNAPSHOT_URL}" ] && [ -n "${SNAPSHOT_BASE_URL}" ]; then
    SNAPSHOT_PATTERN="${SNAPSHOT_PATTERN:-$CHAIN_ID.*$SNAPSHOT_FORMAT}"
    SNAPSHOT_URL=$SNAPSHOT_BASE_URL/$(curl -Ls $SNAPSHOT_BASE_URL/ | egrep -o ">$SNAPSHOT_PATTERN" | tr -d ">");
  fi

  if [ -z "${SNAPSHOT_URL}" ] && [ -n "${SNAPSHOT_JSON}" ]; then
    SNAPSHOT_URL="$(curl -Ls ${SNAPSHOT_JSON}?nocache=$(date +%s) | jq -r .latest)"
  fi

  if [ -z "${SNAPSHOT_URL}" ] && [ -n "${SNAPSHOT_QUICKSYNC}" ]; then
    SNAPSHOT_PRUNING="${SNAPSHOT_PRUNING:-pruned}"
    SNAPSHOT_DATA_PATH="data"
    SNAPSHOT_URL=`curl -Ls $SNAPSHOT_QUICKSYNC | jq -r --arg FILE "$CHAIN_ID-$SNAPSHOT_PRUNING"  'first(.[] | select(.file==$FILE)) | .url'`
  fi

  # SNAPSHOT_FORMAT default value generation via SNAPSHOT_URL
  if [ -z "${SNAPSHOT_FORMAT}" ]; then
    # Follow redirect to get the actual URL for format detection
    ACTUAL_URL=$(wget $SNAPSHOT_URL --spider --max-redirect=5 --server-response -O - 2>&1 | grep -i "Location:" | tail -1 | awk '{print $2}')
    if [ -n "$ACTUAL_URL" ]; then
      SNAPSHOT_URL_TRIM="${ACTUAL_URL%?download=1}"
    else
      # DCS Storj backups adding ?download=1 part which needs to be stripped before determining the extension
      SNAPSHOT_URL_TRIM="${SNAPSHOT_URL%?download=1}"
    fi
    case "${SNAPSHOT_URL_TRIM,,}" in
      *.tar.gz)   SNAPSHOT_FORMAT="tar.gz";;
      *.tar.lz4)  SNAPSHOT_FORMAT="tar.lz4";;
      *.tar.zst)  SNAPSHOT_FORMAT="tar.zst";;
      # Catchall
      *)          SNAPSHOT_FORMAT="tar";;
    esac
  fi

  if [ -n "${SNAPSHOT_URL}" ]; then
    echo "Downloading snapshot from $SNAPSHOT_URL..."
    rm -rf $PROJECT_ROOT/snapshot;
    mkdir -p $PROJECT_ROOT/snapshot;
    cd $PROJECT_ROOT/snapshot;

    tar_cmd="tar xf -"
    # case insensitive match
    if [[ "${SNAPSHOT_FORMAT,,}" == "tar.gz" ]]; then tar_cmd="tar xzf -"; fi
    if [[ "${SNAPSHOT_FORMAT,,}" == "tar.lz4" ]]; then tar_cmd="lz4 -d | tar xf -"; fi
    if [[ "${SNAPSHOT_FORMAT,,}" == "tar.zst" ]]; then tar_cmd="zstd -cd | tar xf -"; fi

    # Detect content size via HTTP header `Content-Length`
    # Note that the server can refuse to return `Content-Length`, or the URL can be incorrect
    pv_extra_args=""
    snapshot_size_in_bytes=$(wget $SNAPSHOT_URL --spider --max-redirect=5 --server-response -O - 2>&1 | grep -i "Content-Length" | tail -1 | awk '{print $2}')
    case "$snapshot_size_in_bytes" in
      # Value cannot be started with `0`, and must be integer
      [1-9]*[0-9]) pv_extra_args="-s $snapshot_size_in_bytes";;
    esac

    # use DCS Storj uplink for the Storj backups (much faster)
    if [[ "${SNAPSHOT_URL}" == *"link.storjshare.io"* ]] && [ -n "$STORJ_ACCESS_GRANT" ]; then
      STORJ_SNAP_URL=${SNAPSHOT_URL#*link.storjshare.io/s/}
      STORJ_SNAP_URL=${STORJ_SNAP_URL#*/}
      STORJ_SNAP_URL=${STORJ_SNAP_URL%%\?*}
      if [ -n "$pv_extra_args" ]; then
        (set -o pipefail; uplink cp $storj_args sj://${STORJ_SNAP_URL} - | pv -petrafb -i 5 $pv_extra_args | eval $tar_cmd) 2>&1 | stdbuf -o0 tr '\r' '\n'
      else
        (set -o pipefail; uplink cp $storj_args sj://${STORJ_SNAP_URL} - | pv -petrafb -i 5 | eval $tar_cmd) 2>&1 | stdbuf -o0 tr '\r' '\n'
      fi
    else
      if [ -n "$pv_extra_args" ]; then
        (set -o pipefail; wget -nv --max-redirect=5 -O - $SNAPSHOT_URL | pv -petrafb -i 5 $pv_extra_args | eval $tar_cmd) 2>&1 | stdbuf -o0 tr '\r' '\n'
      else
        (set -o pipefail; wget -nv --max-redirect=5 -O - $SNAPSHOT_URL | pv -petrafb -i 5 | eval $tar_cmd) 2>&1 | stdbuf -o0 tr '\r' '\n'
      fi
    fi
    # PIPESTATUS[0] captures the subshell's exit code — tr always returns 0,
    # so the old `|| exit 1` on the outer pipeline never triggered on download
    # failures. This was the root cause of nodes starting at block 0.
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
      echo "ERROR: Snapshot download/extraction failed for $SNAPSHOT_URL"
      exit 1
    fi

    [ -z "${SNAPSHOT_DATA_PATH}" ] && [ -d "./${DATA_DIR}" ] && SNAPSHOT_DATA_PATH="${DATA_DIR}"
    [ -z "${SNAPSHOT_WASM_PATH}" ] && [ -d "./${WASM_DIR}" ] && SNAPSHOT_WASM_PATH="${WASM_DIR}"

    if [ -n "${SNAPSHOT_DATA_PATH}" ]; then
      rm -rf ../$DATA_DIR
      mv ./${SNAPSHOT_DATA_PATH} ../$DATA_DIR
    fi

    if [ -n "${SNAPSHOT_WASM_PATH}" ]; then
      rm -rf ../$WASM_DIR
      mv ./${SNAPSHOT_WASM_PATH} ../$WASM_DIR
    fi

    if [ -z "${SNAPSHOT_DATA_PATH}" ]; then
      rm -rf ../$DATA_DIR && mkdir -p ../$DATA_DIR
      mv ./* ../$DATA_DIR
    fi

    cd ../ && rm -rf ./snapshot
  else
    echo "ERROR: Snapshot URL not found"
    exit 1
  fi

  fi # end SNAPSHOT_MODE=remote block
fi

# ── Post-snapshot validation ─────────────────────────────────────────────────
# If we expected to download a snapshot, verify the data directory exists and
# is non-empty. Catches silent download failures that would otherwise cause the
# node to start at block 0 with an empty store.
if [ "$DOWNLOAD_SNAP" == "1" ]; then
  if [ ! -d "$PROJECT_ROOT/$DATA_DIR" ] || [ -z "$(ls -A "$PROJECT_ROOT/$DATA_DIR" 2>/dev/null)" ]; then
    echo "ERROR: Snapshot was expected (DOWNLOAD_SNAP=1) but $PROJECT_ROOT/$DATA_DIR is missing or empty."
    echo "  SNAPSHOT_URL=$SNAPSHOT_URL"
    echo "  SNAPSHOT_MODE=${SNAPSHOT_MODE:-remote}"
    echo "  The node cannot start without snapshot data — it would begin at block 0."
    exit 1
  fi
  echo "=== Snapshot data verified at $PROJECT_ROOT/$DATA_DIR ==="
fi

# Validate genesis
[ "$VALIDATE_GENESIS" == "1" ] && $PROJECT_BIN validate-genesis

# Cosmovisor
if [ "$COSMOVISOR_ENABLED" == "1" ]; then
  export COSMOVISOR_VERSION="${COSMOVISOR_VERSION:-"1.6.0"}"
  export COSMOVISOR_URL="${COSMOVISOR_URL:-"https://github.com/cosmos/cosmos-sdk/releases/download/cosmovisor%2Fv$COSMOVISOR_VERSION/cosmovisor-v$COSMOVISOR_VERSION-$(uname -s)-$(uname -m | sed "s|x86_64|amd64|").tar.gz"}"

  # Download Binary
  if [ ! -f "/bin/cosmovisor" ]; then
    echo "Downloading Cosmovisor from $COSMOVISOR_URL..."
    mkdir -p cosmovisor_temp
    cd cosmovisor_temp
    curl -Ls $COSMOVISOR_URL | tar zx
    cp cosmovisor /bin/cosmovisor
    cd ..
    rm -r cosmovisor_temp
  fi

  # Set up the environment variables
  export DAEMON_NAME=$PROJECT_BIN
  export DAEMON_HOME=$PROJECT_ROOT
  export DAEMON_SHUTDOWN_GRACE="${DAEMON_SHUTDOWN_GRACE:-15s}"

  # Setup Folder Structure
  mkdir -p $PROJECT_ROOT/cosmovisor/upgrades
  mkdir -p $PROJECT_ROOT/cosmovisor/genesis/bin
  cp "/bin/$PROJECT_BIN" $PROJECT_ROOT/cosmovisor/genesis/bin/
fi

# preseed priv_validator_state.json if missing
# ref. https://github.com/tendermint/tendermint/issues/8389
if [[ ! -f "$PROJECT_ROOT/data/priv_validator_state.json" ]]; then
  mkdir -p "$PROJECT_ROOT/data" 2>/dev/null || :
  echo '{"height":"0","round":0,"step":0}' > "$PROJECT_ROOT/data/priv_validator_state.json"
fi

# ── 7. patch config.toml ──────────────────────────────────────────────────────
NODE_SCRIPT=/tmp/node-config.sh
if [ ! -f "$NODE_SCRIPT" ]; then
  NODE_CONFIG_SCRIPT="${NODE_CONFIG_SCRIPT:-https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/audible/config-node-endpoints.sh}"
  echo "Downloading node config script from $NODE_CONFIG_SCRIPT..."
  curl -fsSL "${NODE_CONFIG_SCRIPT}" -o "$NODE_SCRIPT" || die "Download failed"
else
  echo "Using pre-uploaded node config script."
fi
sh "$NODE_SCRIPT"

if [ "$#" -ne 0 ]; then
  export START_CMD="$@"
fi

if [ -z "$START_CMD" ]; then
  if [ "$COSMOVISOR_ENABLED" == "1" ]; then
    export START_CMD="cosmovisor run start"
  else
    export START_CMD="$PROJECT_BIN start"
  fi
fi

echo "=== Cosmos node setup complete ==="

# Write bootstrap marker so restarts skip init/download
BOOTSTRAP_MARKER="${PROJECT_ROOT:-.terpd}/.oline_bootstrapped"
touch "$BOOTSTRAP_MARKER"
echo "[oline] Bootstrap marker written: $BOOTSTRAP_MARKER"

# ── Final guaranteed peer patch ───────────────────────────────────────────────
# Belt-and-suspenders: apply p2p peer settings directly to config.toml right
# before launch. Runs after terpd init so config.toml is guaranteed to exist.
# Complements node-config.sh — ensures peers are set regardless of script
# version or upload success.
if [ -f "${PROJECT_ROOT}/config/config.toml" ]; then
  _peer_patch() {
    local _key="$1" _val="$2"
    if [ -n "$_val" ] && [ "$_val" != "0" ]; then
      sed -i "/^\[p2p\]$/,/^\[/ s|^${_key} *=.*|${_key} = \"${_val}\"|" \
          "${PROJECT_ROOT}/config/config.toml"
      echo "[oline] ${_key} = ${_val}"
    fi
  }
  _peer_patch "persistent_peers"    "${TERPD_P2P_PERSISTENT_PEERS:-}"
  _peer_patch "private_peer_ids"    "${TERPD_P2P_PRIVATE_PEER_IDS:-}"
  _peer_patch "unconditional_peer_ids" "${TERPD_P2P_UNCONDITIONAL_PEER_IDS:-}"
  unset -f _peer_patch
fi

# Ensure nginx is still running with TLS config (guards against any crash
# during the long cosmos setup phase; no-op if already running correctly).
if [ -n "$TLS_CONFIG_URL" ]; then
  nginx -s reload 2>/dev/null || nginx
fi

echo "=== Launching: $START_CMD ==="
# ── Supervisor loop ───────────────────────────────────────────────────────────
# Run the node under a restart loop instead of exec-ing it as PID 1.
# This keeps the shell alive so:
#   - SSH stays accessible for debugging
#   - Container does not restart on node crash (preserves persistent storage state)
#   - Bootstrap phase is not re-executed on restart
while true; do
  echo "[supervisor] Starting: $START_CMD"
  if [ -n "$SNAPSHOT_PATH" ]; then
    snapshot.sh "$START_CMD" >>/proc/1/fd/1 2>&1 || true
  else
    $START_CMD >>/proc/1/fd/1 2>&1 || true
  fi
  echo "[supervisor] Process exited ($?), restarting in 5s..."
  sleep 5
done