# ── Remote & Sync ────────────────────────────────────────────────────────────

# Sync the repo to a remote amd64 workstation and open an SSH session.
# Useful for running e2e tests on the correct architecture.
# Usage:
#   just remote user@host             # default port 22
#   just remote user@host:21212       # custom port
remote dest:
    #!/usr/bin/env bash
    set -euo pipefail
    # Split user@host:port — port is optional, defaults to 22
    DEST="{{dest}}"
    if [[ "$DEST" =~ :[0-9]+$ ]]; then
        HOST="${DEST%:*}"
        PORT="${DEST##*:}"
    else
        HOST="$DEST"
        PORT="22"
    fi
    echo "=== Syncing repo to $HOST (port $PORT) ..."
    rsync -az --progress \
        --exclude='.git' \
        --exclude='target/' \
        --exclude='vendor/' \
        -e "ssh -p $PORT -o StrictHostKeyChecking=accept-new" \
        "./" \
        "$HOST:~/o-line/"
    echo "=== Running e2e on $HOST ..."
    exec ssh -p "$PORT" -t "$HOST" 'bash -lc "cd ~/o-line && just e2e"'

# Sync src/ and plays/audible/ to a remote node via rsync over SSH.
# Pass src + remote_path to override the default paths.
# Usage:
#   just push user@host                                        # src + scripts, port 22
#   just push user@host:2222                                   # custom SSH port
#   just push user@host:2222 ./plays/audible/ ~/o-line/plays/audible/  # specific path
push dest src="" remote_path="":
    #!/usr/bin/env bash
    set -euo pipefail
    DEST="{{dest}}"
    if [[ "$DEST" =~ :[0-9]+$ ]]; then
        HOST="${DEST%:*}"
        PORT="${DEST##*:}"
    else
        HOST="$DEST"
        PORT="22"
    fi
    SSH_OPTS="-p $PORT -o StrictHostKeyChecking=accept-new"
    RSYNC_OPTS=(-az --progress --exclude='target' --exclude='.git' --exclude='vendor')
    SRC="{{src}}"
    if [[ -n "$SRC" ]]; then
        REMOTE="{{remote_path}}"
        [[ -z "$REMOTE" ]] && { echo "remote_path required when src is set"; exit 1; }
        echo "=== Syncing $SRC → $HOST:$REMOTE (port $PORT) ..."
        rsync "${RSYNC_OPTS[@]}" -e "ssh $SSH_OPTS" "$SRC" "$HOST:$REMOTE"
    else
        echo "=== Syncing src/ → $HOST:~/o-line/src/ (port $PORT) ..."
        rsync "${RSYNC_OPTS[@]}" -e "ssh $SSH_OPTS" \
            "./src/" "$HOST:~/o-line/src/"
        echo "=== Syncing plays/audible/ → $HOST:~/o-line/plays/audible/ (port $PORT) ..."
        rsync "${RSYNC_OPTS[@]}" -e "ssh $SSH_OPTS" \
            "./plays/audible/" "$HOST:~/o-line/plays/audible/"
    fi
    echo "=== Sync complete."

# Sync oline repo to a remote device and install the binary.
# First ensures SSH key access via ssh-copy-id, then rsyncs the repo,
# then builds + installs oline on the remote.
# Usage:
#   just sync-client user@host              # default port 22
#   just sync-client user@host:2210         # custom port
#   just sync-client user@host -i ~/.ssh/id_ed25519   # specific key
sync-client dest *args="":
    #!/usr/bin/env bash
    set -euo pipefail
    DEST="{{dest}}"
    ARGS="{{args}}"
    # Parse -i <key> from extra args
    KEY=""
    while [[ $# -gt 0 || -n "$ARGS" ]]; do
        set -- $ARGS; ARGS=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -i) KEY="$2"; shift 2 ;;
                *)  shift ;;
            esac
        done
    done
    # Parse user@host:port
    if [[ "$DEST" =~ :[0-9]+$ ]]; then
        HOST="${DEST%:*}"
        PORT="${DEST##*:}"
    else
        HOST="$DEST"
        PORT="22"
    fi

    # SSH multiplexing — one connection, reuse for all steps.
    # Password entered once (if needed); socket shared by rsync + ssh.
    CTRL_PATH="/tmp/oline-sync-$$-%r@%h:%p"
    SSH_OPTS="-p $PORT -o StrictHostKeyChecking=accept-new"
    SSH_OPTS="$SSH_OPTS -o ControlMaster=auto -o ControlPath=$CTRL_PATH -o ControlPersist=300"
    [[ -n "$KEY" ]] && SSH_OPTS="$SSH_OPTS -i $KEY"

    cleanup() { ssh -O exit -o ControlPath="$CTRL_PATH" "$HOST" 2>/dev/null || true; }
    trap cleanup EXIT

    # 1. Ensure SSH key access (opens master connection)
    echo "=== [1/3] Ensuring SSH key access to $HOST (port $PORT) ..."
    if ssh $SSH_OPTS "$HOST" "echo ok" &>/dev/null; then
        echo "  Key access already works."
    else
        echo "  Installing SSH key via ssh-copy-id ..."
        ssh-copy-id -p "$PORT" ${KEY:+-i "$KEY"} "$HOST"
        # Open master connection now that key is installed
        ssh $SSH_OPTS "$HOST" "echo ok" &>/dev/null
    fi

    # 2. Rsync the repo (reuses master connection — no password prompt)
    echo "=== [2/3] Syncing repo to $HOST:~/o-line/ (port $PORT) ..."
    rsync -az --progress --delete \
        --exclude='.git' \
        --exclude='target/' \
        --exclude='vendor/' \
        --exclude='*.env' \
        --exclude='*.lz4' \
        --exclude='*.tar.gz' \
        --exclude='*.tar.*' \
        --exclude='*.zst' \
        --exclude='node-data' \
        --exclude='node_modules' \
        --exclude='secrets' \
        --exclude='.DS_Store' \
        --exclude='deploy-config.json' \
        --exclude='build/' \
        --exclude='dist/' \
        -e "ssh $SSH_OPTS" \
        "./" \
        "$HOST:~/o-line/"

    # 3. Update rustc + install oline on the remote (reuses master connection)
    echo "=== [3/3] Updating rustc and installing oline on $HOST ..."
    ssh $SSH_OPTS -t "$HOST" 'bash -lc "rustup update stable && cd ~/o-line && cargo install --path ."'
    echo "=== Done. oline installed on $HOST."
