# ── Relayer Management ────────────────────────────────────────────────────────
# Manage a Cosmos IBC relayer running in a Docker container (Akash or any host).
# The container exposes SSH/SFTP for live management — no restart needed.
#
# Required env vars:
#   RLY_SSH_HOST   — relayer container SSH host (NodePort IP/hostname)
#   RLY_SSH_KEY    — path to SSH private key
#
# Optional env vars (with defaults):
#   RLY_SSH_P   — SSH port           [22]
#   RLY_SSH_USER   — SSH user           [relayer]

# Show relayer process status and rly API health.
relayer-status:
    oline relayer status \
        --host "${RLY_SSH_HOST:?RLY_SSH_HOST required}" \
        --key  "${RLY_SSH_KEY:?RLY_SSH_KEY required}" \
        ${RLY_SSH_P:+--port $RLY_SSH_P} \
        ${RLY_SSH_USER:+--user $RLY_SSH_USER}

# Tail relayer logs.
#
# Usage:
#   just relayer-logs           # last 50 lines
#   LINES=100 just relayer-logs # last 100 lines
relayer-logs:
    oline relayer logs \
        --host  "${RLY_SSH_HOST:?RLY_SSH_HOST required}" \
        --key   "${RLY_SSH_KEY:?RLY_SSH_KEY required}" \
        --lines "${LINES:-50}" \
        ${RLY_SSH_P:+--port $RLY_SSH_P} \
        ${RLY_SSH_USER:+--user $RLY_SSH_USER}

# Hot-swap the rly binary without restarting the container.
#
# Required: RLY_BINARY — local path to the new rly binary.
#
# Example:
#   RLY_BINARY=./bin/rly just relayer-update-binary
relayer-update-binary:
    oline relayer update-binary \
        --host "${RLY_SSH_HOST:?RLY_SSH_HOST required}" \
        --key  "${RLY_SSH_KEY:?RLY_SSH_KEY required}" \
        ${RLY_SSH_P:+--port $RLY_SSH_P} \
        ${RLY_SSH_USER:+--user $RLY_SSH_USER} \
        "${RLY_BINARY:?RLY_BINARY required (path to new rly binary)}"

# Upload a new config.yaml and signal a relayer restart.
#
# Required: RLY_CONFIG — local path to the new config.yaml.
#
# Example:
#   RLY_CONFIG=./config.yaml just relayer-update-config
relayer-update-config:
    oline relayer update-config \
        --host "${RLY_SSH_HOST:?RLY_SSH_HOST required}" \
        --key  "${RLY_SSH_KEY:?RLY_SSH_KEY required}" \
        ${RLY_SSH_P:+--port $RLY_SSH_P} \
        ${RLY_SSH_USER:+--user $RLY_SSH_USER} \
        "${RLY_CONFIG:?RLY_CONFIG required (path to config.yaml)}"

# Install a relayer key mnemonic into the container's key directory.
#
# Required:
#   RLY_CHAIN_ID      — chain ID (determines filename under /home/relayer/.keys/)
#   RLY_MNEMONIC_FILE — local path to file containing the mnemonic
#
# Example:
#   RLY_CHAIN_ID=cosmoshub-4 RLY_MNEMONIC_FILE=./mnemonic.txt just relayer-keys
relayer-keys:
    oline relayer keys \
        --host          "${RLY_SSH_HOST:?RLY_SSH_HOST required}" \
        --key           "${RLY_SSH_KEY:?RLY_SSH_KEY required}" \
        --chain-id      "${RLY_CHAIN_ID:?RLY_CHAIN_ID required}" \
        --mnemonic-file "${RLY_MNEMONIC_FILE:?RLY_MNEMONIC_FILE required}" \
        ${RLY_SSH_P:+--port $RLY_SSH_P} \
        ${RLY_SSH_USER:+--user $RLY_SSH_USER}
