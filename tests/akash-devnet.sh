#!/usr/bin/env bash
#
# Akash local dev cluster lifecycle for o-line e2e tests.
#
# Wraps the Akash provider repository's Kind-based dev environment.
# All diagnostic output → stderr.  Only 'wait' and 'info' write JSON → stdout.
#
# Components managed:
#   - Kind Kubernetes cluster
#   - Akash node (RPC :26657 / gRPC :9090 / REST :1317 / P2P :26656)
#   - test-provider (Rust binary — no Kubernetes required, HTTPS :8443)
#
# Usage:
#   ./tests/akash-devnet.sh setup     # clone repo, build Akash node bins, create Kind cluster (idempotent)
#   ./tests/akash-devnet.sh start     # start node + test-provider in background
#   ./tests/akash-devnet.sh wait      # start + block until ready, print JSON endpoints to stdout
#   ./tests/akash-devnet.sh stop      # kill node + test-provider processes
#   ./tests/akash-devnet.sh clean     # stop + delete Kind cluster
#   ./tests/akash-devnet.sh status    # print running state to stderr
#   ./tests/akash-devnet.sh info      # print JSON endpoints to stdout (cluster must be running)
#   ./tests/akash-devnet.sh faucet    # print faucet mnemonic to stdout
#
# Environment:
#   AKASH_PROVIDER_DIR        Provider repo path (default: ~/go/src/github.com/akash-network/provider)
#   AKASH_PROVIDERURL   Repo to clone if absent (default: permissionlessweb/provider fork)
#   AKASH_PROVIDERBRANCH  Branch to clone (default: feat/local-dev)
#   AKASH_CLUSTER_NAME        Kind cluster name (default: akash-dev)
#   GORELEASER_IMAGE          goreleaser-cross image (default: v1.22, required — v2 breaks Akash Makefiles)
#   AKASH_NODE_READY_TIMEOUT  Seconds to wait for node RPC (default: 60)
#   AKASH_PROVIDER_READY_TIMEOUT  Seconds to wait for provider (default: 60)
#
# Prerequisites (macOS):
#   brew install kind kubectl jq make
#   cargo (for building test-provider)
#   Docker Desktop running

set -euo pipefail

# ── Repo root (resolved from script location) ─────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Configuration ──────────────────────────────────────────────────────────────

PROVIDER_DIR="${AKASH_PROVIDER_DIR:-${HOME}/go/src/github.com/akash-network/provider}"
PROVIDERURL="${AKASH_PROVIDERURL:-https://github.com/permissionlessweb/provider.git}"
PROVIDERBRANCH="${AKASH_PROVIDERBRANCH:-feat/local-dev}"
# The Akash provider Makefile derives the Kind cluster name as `basename $PWD`
# when run from _run/kube/, which resolves to "kube".  Default to that so our
# kind-get-clusters check stays in sync with what the Makefile actually creates.
# Override with AKASH_CLUSTER_NAME if using a different _run/ subdirectory.
CLUSTER_NAME="${AKASH_CLUSTER_NAME:-kube}"
GORELEASER_IMAGE="${GORELEASER_IMAGE:-ghcr.io/goreleaser/goreleaser-cross:v1.22}"

KUBE_DIR="${PROVIDER_DIR}/_run/kube"
CACHE_DIR="${PROVIDER_DIR}/.cache"
BIN_DIR="${CACHE_DIR}/bin"
# AP_RUN_DIR is where the dev environment writes key-secrets after kube-cluster-setup.
AP_RUN_DIR="${CACHE_DIR}/run/kube"

AKASH_BIN="${BIN_DIR}/akash"
PROVIDER_BIN="${BIN_DIR}/provider-services"

NODE_PID_FILE="/tmp/akash-devnet-node.pid"
PROVIDER_PID_FILE="/tmp/akash-devnet-provider.pid"
NODE_LOG="/tmp/akash-devnet-node.log"
PROVIDER_LOG="/tmp/akash-devnet-provider.log"

# Rust test-provider binary (built from src/bin/test_provider.rs).
TEST_PROVIDER_BIN="${REPO_ROOT}/target/debug/test-provider"

NODE_RPC_P=26657
NODE_P2P_P=26656
NODE_GRPC_P=9090
NODE_REST_P=1317
PROVIDER_P=8443

NODE_READY_TIMEOUT="${AKASH_NODE_READY_TIMEOUT:-60}"
PROVIDER_READY_TIMEOUT="${AKASH_PROVIDER_READY_TIMEOUT:-60}"

# ── Platform detection ─────────────────────────────────────────────────────────

MAKE_CMD="make"

_detect_make() {
    if [[ "$(uname)" == "Darwin" ]]; then
        # Prepend the GNU make gnubin directory to PATH so that *all* recursive
        # make calls inside the Akash Makefile also resolve to GNU make 4+.
        # Simply setting MAKE_CMD to the full path is not enough because the
        # Akash Makefiles call `make -C ...` and `$(MAKE)` which use PATH.
        if [[ -d "/opt/homebrew/opt/make/libexec/gnubin" ]]; then
            export PATH="/opt/homebrew/opt/make/libexec/gnubin:${PATH}"
            MAKE_CMD="make"   # now resolves to GNU make via PATH
        elif [[ -d "/usr/local/opt/make/libexec/gnubin" ]]; then
            export PATH="/usr/local/opt/make/libexec/gnubin:${PATH}"
            MAKE_CMD="make"
        elif command -v gmake >/dev/null 2>&1; then
            # gmake is in PATH but sub-makes still call `make`; add a symlink shim.
            _log "WARNING: gmake found but recursive make calls may still hit system make."
            _log "  Fix: brew install make  (adds gnubin to PATH)"
            MAKE_CMD="gmake"
        else
            _die "GNU Make 4+ required on macOS. Install: brew install make"
        fi
    fi
}

# ── Helpers ────────────────────────────────────────────────────────────────────

_log()  { echo "[akash-devnet] $*" >&2; }
_die()  { echo "[akash-devnet] ERROR: $*" >&2; exit 1; }

# Run a make target inside KUBE_DIR with the Akash dev env loaded.
# All output goes to stderr so stdout remains clean for JSON.
_make() {
    local target="$1"; shift
    cd "${KUBE_DIR}"
    # Always override AKASH_NODE to use 127.0.0.1 rather than localhost.
    # On macOS (and some Linux systems) 'localhost' resolves to ::1 (IPv6),
    # but the Akash node only binds to 127.0.0.1 (IPv4).  Connecting to the
    # wrong address causes silent account-lookup failures, which causes the
    # akash CLI to sign TXs with the default account_number=0 instead of the
    # real on-chain value → "signature verification failed, account number (0)".
    #
    # NOTE: must pass as a make command-line variable (highest priority) because
    # the Akash Makefile sets `export AKASH_NODE = http://localhost:26657` which
    # overrides inherited environment variables.
    local node_url="http://127.0.0.1:${NODE_RPC_P}"

    if command -v direnv >/dev/null 2>&1; then
        direnv allow . >/dev/null 2>&1 || true
        direnv exec . "${MAKE_CMD}" "${target}" \
            "AKASH_NODE=${node_url}" \
            "GORELEASER_IMAGE=${GORELEASER_IMAGE}" \
            "AP_RUN_NAME=${CLUSTER_NAME}" \
            "KIND_NAME=${CLUSTER_NAME}" \
            "$@" >&2
    else
        # Fallback: set the env vars that direnv would normally provide.
        AP_ROOT="${PROVIDER_DIR}" \
        AP_DEVCACHE="${CACHE_DIR}" \
        AP_DEVCACHE_BIN="${BIN_DIR}" \
        AP_RUN_DIR="${AP_RUN_DIR}" \
        "${MAKE_CMD}" "${target}" \
            "AKASH_NODE=${node_url}" \
            "GORELEASER_IMAGE=${GORELEASER_IMAGE}" \
            "AP_RUN_NAME=${CLUSTER_NAME}" \
            "KIND_NAME=${CLUSTER_NAME}" \
            "$@" >&2
    fi
}

# Poll host:port until connectable or timeout (seconds). Dots to stderr.
_wait_port() {
    local host="$1" port="$2" timeout="$3" label="$4"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if nc -z "$host" "$port" 2>/dev/null; then
            echo "" >&2
            _log "  ${label} ready on ${host}:${port}."
            return 0
        fi
        printf "." >&2
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo "" >&2
    return 1
}

# Kill all processes listening on a port.
_kill_port() {
    local port="$1"
    local pids
    pids=$(lsof -ti ":${port}" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs kill 2>/dev/null || true
    fi
}

# Kill the process recorded in a PID file and remove the file.
_kill_pid_file() {
    local pid_file="$1"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        kill "$pid" 2>/dev/null || true
        rm -f "$pid_file"
    fi
}

# Read a mnemonic from a key-secrets JSON file by name (e.g. "faucet").
_read_mnemonic() {
    local name="$1"
    local json_file="${AP_RUN_DIR}/.akash/key-secrets/${name}.json"
    if [[ -f "$json_file" ]] && command -v jq >/dev/null 2>&1; then
        jq -r '.mnemonic // .phrase // .seed // empty' "$json_file" 2>/dev/null || true
    fi
}

# Try deployer → main → validator → faucet key names in order.
_read_deployer_mnemonic() {
    for name in deployer main validator faucet; do
        local m
        m=$(_read_mnemonic "$name")
        if [[ -n "$m" ]]; then
            echo "$m"
            return 0
        fi
    done
    echo ""
}

# ── Commands ───────────────────────────────────────────────────────────────────

cmd_check() {
    _detect_make
    local missing=()
    for tool in kind kubectl docker jq nc; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [[ "${#missing[@]}" -gt 0 ]]; then
        _die "Missing prerequisites: ${missing[*]}\n  macOS: brew install kind kubectl jq"
    fi
    _log "Prerequisites OK (make=${MAKE_CMD})"
}

cmd_setup() {
    cmd_check

    # Clone repo if not present.
    if [[ ! -d "${PROVIDER_DIR}" ]]; then
        _log "Cloning ${PROVIDERURL} (branch: ${PROVIDERBRANCH}) → ${PROVIDER_DIR}"
        mkdir -p "$(dirname "${PROVIDER_DIR}")"
        git clone -b "${PROVIDERBRANCH}" "${PROVIDERURL}" "${PROVIDER_DIR}" >&2
    else
        _log "Provider repo found at ${PROVIDER_DIR}"
    fi

    if [[ ! -d "${KUBE_DIR}" ]]; then
        _die "_run/kube/ not found in provider repo at ${PROVIDER_DIR}. Wrong branch?"
    fi

    # Build binaries if absent.
    if [[ ! -f "${AKASH_BIN}" ]] || [[ ! -f "${PROVIDER_BIN}" ]]; then
        _log "Building Akash binaries (this takes several minutes)..."
        cd "${PROVIDER_DIR}"
        if command -v direnv >/dev/null 2>&1; then
            direnv allow . >/dev/null 2>&1 || true
            direnv exec . "${MAKE_CMD}" bins "GORELEASER_IMAGE=${GORELEASER_IMAGE}" >&2
        else
            "${MAKE_CMD}" bins "GORELEASER_IMAGE=${GORELEASER_IMAGE}" >&2
        fi
        _log "Binaries built."
    else
        _log "Akash binaries already present."
    fi

    # Delete existing cluster under our name.
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        _log "Deleting existing Kind cluster '${CLUSTER_NAME}'..."
        kind delete cluster --name "${CLUSTER_NAME}" >&2 2>/dev/null || true
    fi

    # Remove any pre-existing Akash home so kube-cluster-setup can initialize
    # genesis fresh.  'genesis init node0' fails if genesis.json already exists,
    # so we must wipe it before re-running setup.
    if [[ -f "${AP_RUN_DIR}/.akash/config/genesis.json" ]]; then
        _log "Existing genesis found — removing Akash home for fresh initialization…"
        rm -rf "${AP_RUN_DIR}/.akash"
    fi

    # kube-prepare-image-provider-services (part of kube-cluster-setup) tries
    # to build the provider-services Docker image via goreleaser.  goreleaser v2
    # removed the --id flag that Akash's Makefile uses, so the build fails.
    # The target skips the build if the image already exists locally — pre-pull
    # the official pre-built image to trigger that fast path.
    local arch
    arch=$(uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')
    local provider_image="ghcr.io/akash-network/provider:latest-${arch}"
    if ! docker inspect --type=image "${provider_image}" >/dev/null 2>&1; then
        _log "Pre-pulling provider image ${provider_image} (skips goreleaser build)..."
        docker pull "${provider_image}" >&2
    else
        _log "Provider image ${provider_image} already present locally."
    fi

    _log "Creating Kind cluster and installing Akash components (2–5 min)..."
    _make kube-cluster-setup
    _log "Kind cluster '${CLUSTER_NAME}' ready."
}

cmd_start() {
    _detect_make

    # Run setup if the Akash binary or the chain genesis are missing.
    #
    # NOTE: We no longer require the Kind cluster to be running at this point.
    # test-provider replaced provider-services (which needed Kubernetes).
    # The Akash chain node (make node-run) runs standalone — it only needs the
    # genesis/keys that kube-cluster-setup wrote to ${AP_RUN_DIR}/.akash/ once.
    # Kind is only needed during the one-time 'akash-setup' step.
    local akash_home="${AP_RUN_DIR}/.akash"
    if [[ ! -f "${AKASH_BIN}" ]]; then
        _log "Akash binary not found — running setup first..."
        cmd_setup
    elif [[ ! -f "${akash_home}/config/genesis.json" ]]; then
        _log "Akash chain not initialized — running setup first..."
        cmd_setup
    fi

    # Kill any leftover processes on our ports.
    for port in "${NODE_RPC_P}" "${NODE_P2P_P}" "${NODE_GRPC_P}" \
                "${NODE_REST_P}" "${PROVIDER_P}"; do
        _kill_port "$port"
    done
    rm -f "${NODE_PID_FILE}" "${PROVIDER_PID_FILE}"

    # Start Akash node in background, output captured to log file.
    # NOTE: The redirect must be on the ( ) group itself, not on the inner command.
    # If you redirect only the inner command (e.g. "make node-run >file 2>&1"), the
    # subshell process still holds the caller's stdout fd open (e.g. the write-end of
    # a $() pipe), causing "CLUSTER_JSON=$(just akash-wait)" to hang forever because
    # $() waits until ALL processes that inherited the pipe fd have exited.
    _log "Starting Akash node → ${NODE_LOG}"
    (
        cd "${KUBE_DIR}"
        if command -v direnv >/dev/null 2>&1; then
            direnv allow . >/dev/null 2>&1 || true
            direnv exec . "${MAKE_CMD}" node-run \
                "GORELEASER_IMAGE=${GORELEASER_IMAGE}" \
                "AP_RUN_NAME=kube"
        else
            AP_ROOT="${PROVIDER_DIR}" AP_DEVCACHE="${CACHE_DIR}" \
            AP_DEVCACHE_BIN="${BIN_DIR}" AP_RUN_DIR="${AP_RUN_DIR}" \
            "${MAKE_CMD}" node-run \
                "GORELEASER_IMAGE=${GORELEASER_IMAGE}" \
                "AP_RUN_NAME=kube"
        fi
    ) >"${NODE_LOG}" 2>&1 &
    echo "$!" >"${NODE_PID_FILE}"
    _log "  Node PID: $(cat "${NODE_PID_FILE}")"

    # Wait for node RPC before registering the provider.
    _log "Waiting for Akash node RPC on 127.0.0.1:${NODE_RPC_P} (up to ${NODE_READY_TIMEOUT}s)..."
    if ! _wait_port "127.0.0.1" "${NODE_RPC_P}" "${NODE_READY_TIMEOUT}" "Akash node RPC"; then
        _log "Node log (last 30 lines):"
        tail -30 "${NODE_LOG}" >&2
        _die "Akash node RPC did not come up within ${NODE_READY_TIMEOUT}s."
    fi

    # Wait for the first committed block so genesis state (accounts, balances) is
    # fully queryable.  The node accepts TCP connections before genesis state is
    # applied, causing `tx provider create` to sign with account_number=0 (not found).
    _log "Waiting for first committed block..."
    local block_height=0 block_elapsed=0
    while [[ $block_elapsed -lt 30 ]]; do
        block_height=$(curl -sf "http://127.0.0.1:${NODE_RPC_P}/status" 2>/dev/null \
            | jq -r '.result.sync_info.latest_block_height // "0"' 2>/dev/null || echo "0")
        if [[ "${block_height}" -ge 1 ]]; then
            _log "  Block ${block_height} committed."
            break
        fi
        printf "." >&2
        sleep 2
        block_elapsed=$((block_elapsed + 2))
    done
    echo "" >&2

    # Always rebuild test-provider to pick up any path-dep changes in akash-deploy-rs.
    _log "Building test-provider binary..."
    rm -f "${REPO_ROOT}/target/debug/deps/libakash_deploy_rs"*.rlib
    cargo build --bin test-provider --features testing -q --manifest-path "${REPO_ROOT}/Cargo.toml" >&2
    _log "  test-provider built."

    # Read provider mnemonic: prefer a dedicated 'provider' key; fall back to faucet.
    local provider_mnemonic deployer_mnemonic
    provider_mnemonic=$(_read_mnemonic "provider" || true)
    if [[ -z "${provider_mnemonic}" ]]; then
        provider_mnemonic=$(_read_mnemonic "faucet" || true)
    fi
    deployer_mnemonic=$(_read_deployer_mnemonic)

    if [[ -z "${provider_mnemonic}" ]]; then
        _die "Could not read provider mnemonic from key-secrets — run 'just akash-setup' first."
    fi

    # Start the Rust test-provider in background.
    # It self-registers on-chain (MsgCreateProvider, idempotent) and then
    # polls for open orders to bid on (MsgCreateBid).
    _log "Starting Rust test-provider → ${PROVIDER_LOG}"
    (
        PROVIDER_RPC="http://127.0.0.1:${NODE_RPC_P}" \
        PROVIDER_GRPC="http://127.0.0.1:${NODE_GRPC_P}" \
        PROVIDER_REST="http://127.0.0.1:${NODE_REST_P}" \
        PROVIDER_MNEMONIC="${provider_mnemonic}" \
        PROVIDER_DEPLOYER_ADDR="" \
        PROVIDER_P="${PROVIDER_P}" \
        PROVIDER_HOST_URI="https://127.0.0.1:${PROVIDER_P}" \
        PROVIDER_BID_PRICE="1" \
        PROVIDER_BID_DEPOSIT="5000000" \
        RUST_LOG="${RUST_LOG:-akash_deploy_rs=debug,test_provider=info,info}" \
        "${TEST_PROVIDER_BIN}"
    ) >>"${PROVIDER_LOG}" 2>&1 &
    echo "$!" >"${PROVIDER_PID_FILE}"
    _log "  test-provider PID: $(cat "${PROVIDER_PID_FILE}")"
}

cmd_wait() {
    cmd_start

    _log "Waiting for Akash provider on 127.0.0.1:${PROVIDER_P} (up to ${PROVIDER_READY_TIMEOUT}s)..."
    if ! _wait_port "127.0.0.1" "${PROVIDER_P}" "${PROVIDER_READY_TIMEOUT}" "Akash provider"; then
        _log "Provider log (last 30 lines):"
        tail -30 "${PROVIDER_LOG}" >&2
        _die "Akash provider did not come up within ${PROVIDER_READY_TIMEOUT}s."
    fi

    # Output JSON to stdout — this is what the Rust test captures.
    cmd_info
}

cmd_stop() {
    _log "Stopping Akash node and provider..."
    _kill_pid_file "${NODE_PID_FILE}"
    _kill_pid_file "${PROVIDER_PID_FILE}"

    # Belt-and-suspenders: kill by port in case PID files are stale.
    for port in "${NODE_RPC_P}" "${NODE_P2P_P}" "${NODE_GRPC_P}" \
                "${NODE_REST_P}" "${PROVIDER_P}"; do
        _kill_port "$port"
    done

    # Clean up kubectl port-forward processes if any were created.
    pkill -f "kubectl.*port-forward" 2>/dev/null || true

    rm -f "${NODE_PID_FILE}" "${PROVIDER_PID_FILE}"
    _log "Stopped."
}

cmd_clean() {
    cmd_stop

    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        _log "Deleting Kind cluster '${CLUSTER_NAME}'..."
        kind delete cluster --name "${CLUSTER_NAME}" >&2 2>/dev/null || true
    fi

    if [[ -d "${KUBE_DIR}" ]]; then
        _log "Running make clean..."
        _make clean 2>/dev/null || true
    fi

    # Remove the Akash home directory so the next 'setup' re-initializes
    # genesis, validator keys, and key-secrets from scratch.
    # (make clean does not remove .cache/run/kube/.akash — genesis survives.)
    if [[ -d "${AP_RUN_DIR}/.akash" ]]; then
        _log "Removing Akash home (${AP_RUN_DIR}/.akash)…"
        rm -rf "${AP_RUN_DIR}/.akash"
    fi

    _log "Cleanup complete."
}

cmd_status() {
    local node_ok=false provider_ok=false genesis_ok=false

    nc -z 127.0.0.1 "${NODE_RPC_P}" 2>/dev/null && node_ok=true || true
    nc -z 127.0.0.1 "${PROVIDER_P}" 2>/dev/null && provider_ok=true || true
    [[ -f "${AP_RUN_DIR}/.akash/config/genesis.json" ]] && genesis_ok=true || true

    _log "=== Akash Dev Cluster Status ==="
    _log "  Chain initialized (genesis.json): ${genesis_ok}"
    _log "  Akash node   RPC :${NODE_RPC_P}:  ${node_ok}"
    _log "  Akash node   gRPC :${NODE_GRPC_P}: (inferred)"
    _log "  Akash node   REST :${NODE_REST_P}: (inferred)"
    _log "  test-provider HTTPS :${PROVIDER_P}: ${provider_ok}"
    if $node_ok; then
        _log "  Logs: ${NODE_LOG}  ${PROVIDER_LOG}"
    fi
}

cmd_faucet() {
    local m
    m=$(_read_mnemonic "faucet")
    if [[ -z "$m" ]]; then
        _die "Faucet mnemonic not found at ${AP_RUN_DIR}/.akash/key-secrets/faucet.json\n  Run: ./tests/akash-devnet.sh setup"
    fi
    # Faucet mnemonic goes to stdout (callers may capture it).
    echo "$m"
}

cmd_info() {
    local faucet_mnemonic deployer_mnemonic provider_mnemonic chain_id

    faucet_mnemonic=$(_read_mnemonic "faucet" || echo "")
    deployer_mnemonic=$(_read_deployer_mnemonic || echo "")
    [[ -z "$deployer_mnemonic" ]] && deployer_mnemonic="$faucet_mnemonic"

    # Provider uses dedicated key if present, else falls back to faucet.
    provider_mnemonic=$(_read_mnemonic "provider" || true)
    [[ -z "${provider_mnemonic}" ]] && provider_mnemonic="${faucet_mnemonic}"

    # Read chain-id from the running node.
    chain_id=$(curl -sf --max-time 5 "http://127.0.0.1:${NODE_RPC_P}/status" 2>/dev/null \
        | jq -r '.result.node_info.network // "local"' 2>/dev/null \
        || echo "local")

    # JSON to stdout — all other output was to stderr.
    jq -n \
        --arg rpc      "http://127.0.0.1:${NODE_RPC_P}"   \
        --arg grpc     "http://127.0.0.1:${NODE_GRPC_P}"  \
        --arg rest     "http://127.0.0.1:${NODE_REST_P}"  \
        --arg provider "https://127.0.0.1:${PROVIDER_P}"  \
        --arg chain_id "${chain_id}"                          \
        --arg faucet   "${faucet_mnemonic}"                   \
        --arg deployer "${deployer_mnemonic}"                 \
        --arg provmnem "${provider_mnemonic}"                 \
        '{
            rpc:               $rpc,
            grpc:              $grpc,
            rest:              $rest,
            provider:          $provider,
            chain_id:          $chain_id,
            faucet_mnemonic:   $faucet,
            deployer_mnemonic: $deployer,
            provider_mnemonic: $provmnem
        }'
}

# Reset chain state to genesis and restart.
#
# Stops the node, wipes block data (preserves keys, genesis, and config),
# then starts fresh via `cmd_wait`.
#
# We directly remove the data/ directory rather than using `akash unsafe-reset-all`
# because the command name varies across Akash binary versions
# (unsafe-reset-all vs comet unsafe-reset-all vs cometbft unsafe-reset-all)
# and a silent failure would leave the chain un-reset.
#
# Use this before e2e tests to guarantee a clean ledger with sequence=0.
cmd_reset() {
    local akash_home="${AP_RUN_DIR}/.akash"
    cmd_stop

    if [[ -d "${akash_home}/data" ]]; then
        _log "Removing chain data directory (${akash_home}/data)…"
        rm -rf "${akash_home}/data"
        mkdir -p "${akash_home}/data"
        # CometBFT requires priv_validator_state.json to exist in data/ before node start.
        # unsafe-reset-all preserves this file; replicate that behaviour.
        printf '{\n  "height": "0",\n  "round": 0,\n  "step": 0\n}\n' \
            > "${akash_home}/data/priv_validator_state.json"
        _log "Chain data removed. Genesis, keys, and validator state preserved."
    elif [[ -d "${akash_home}" ]]; then
        _log "Chain data directory not found — nothing to reset."
    else
        _log "Akash home not found — nothing to reset."
    fi

    cmd_wait
}

# ── Main ───────────────────────────────────────────────────────────────────────

CMD="${1:-help}"

case "$CMD" in
    setup)   cmd_setup  ;;
    start)   cmd_start  ;;
    wait)    cmd_wait   ;;
    stop)    cmd_stop   ;;
    clean)   cmd_clean  ;;
    reset)   cmd_reset  ;;
    status)  cmd_status ;;
    info)    cmd_info   ;;
    faucet)  cmd_faucet ;;
    check)   cmd_check  ;;
    help|--help|-h)
        sed -n '/^#$/,/^[^#]/{ /^#/p }' "$0" | sed 's/^# \?//'
        ;;
    *)
        echo "[akash-devnet] Unknown command: ${CMD}" >&2
        echo "Usage: $0 [setup|start|wait|stop|clean|reset|status|info|faucet|check]" >&2
        exit 1
        ;;
esac
