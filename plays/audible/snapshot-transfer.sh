#!/usr/bin/env bash
# plays/audible/snapshot-transfer.sh
#
# Reusable snapshot transfer helper for o-line deployments.
#
# Modes (set SNAPSHOT_TRANSFER_MODE or pass as first argument):
#
#   fetch-url   Download snapshot from URL to local cache file.
#               Skips download if local file already exists and is non-empty.
#
#   fetch-node  SSH into a running cosmos node and stream its data directory
#               as a compressed tar archive to a local cache file.
#               Uses SSH piping — handles arbitrarily large files without
#               buffering in memory.
#
#   push-node   Pipe a local snapshot archive to a waiting remote node via SSH.
#               The node must be started with SNAPSHOT_MODE=sftp so
#               oline-entrypoint.sh waits at SNAPSHOT_SFTP_PATH.
#
# ─────────────────────────────────────────────────────────────────────────────
# Required env vars per mode:
#
#   fetch-url:
#     SNAPSHOT_URL          — direct download URL (tar.lz4 / tar.zst / tar.gz)
#     SNAPSHOT_LOCAL_PATH   — local destination path
#
#   fetch-node:
#     SSH_HOST              — hostname or IP of the source node
#     SSH_PORT              — SSH port (default 22)
#     SSH_KEY               — path to SSH private key file
#     REMOTE_DATA_DIR       — path on remote node (e.g. /root/.terpd/data)
#     SNAPSHOT_LOCAL_PATH   — local destination path
#     SNAPSHOT_FORMAT       — tar.lz4 (default) | tar.zst | tar.gz
#
#   push-node:
#     SSH_HOST              — hostname or IP of the destination node
#     SSH_PORT              — SSH port (default 22)
#     SSH_KEY               — path to SSH private key file
#     SNAPSHOT_LOCAL_PATH   — local snapshot archive to push
#     SNAPSHOT_REMOTE_PATH  — remote path to write (default /tmp/snapshot.tar.lz4)
#
# ─────────────────────────────────────────────────────────────────────────────
# Examples:
#
#   # Download snapshot from URL (skip if cached):
#   SNAPSHOT_URL=https://snapshots.example.com/morocco-1.tar.lz4 \
#   SNAPSHOT_LOCAL_PATH=/var/oline/cache/morocco-1.tar.lz4 \
#   plays/audible/snapshot-transfer.sh fetch-url
#
#   # Fetch data dir from snapshot node after Phase A sync:
#   SSH_HOST=provider.akash.example.com SSH_PORT=32123 \
#   SSH_KEY=~/.oline/ssh-key \
#   REMOTE_DATA_DIR=/root/.terpd/data \
#   SNAPSHOT_LOCAL_PATH=/var/oline/cache/morocco-1.tar.lz4 \
#   SNAPSHOT_FORMAT=tar.lz4 \
#   plays/audible/snapshot-transfer.sh fetch-node
#
#   # Push cached snapshot to seed node waiting for SFTP delivery:
#   SSH_HOST=provider.akash.example.com SSH_PORT=32456 \
#   SSH_KEY=~/.oline/ssh-key \
#   SNAPSHOT_LOCAL_PATH=/var/oline/cache/morocco-1.tar.lz4 \
#   plays/audible/snapshot-transfer.sh push-node

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

# ── Mode selection ────────────────────────────────────────────────────────────
MODE="${1:-${SNAPSHOT_TRANSFER_MODE:-}}"
[ -z "$MODE" ] && die "MODE required: fetch-url | fetch-node | push-node"

# ── Common defaults ───────────────────────────────────────────────────────────
SSH_PORT="${SSH_PORT:-22}"
SNAPSHOT_FORMAT="${SNAPSHOT_FORMAT:-tar.lz4}"
SNAPSHOT_REMOTE_PATH="${SNAPSHOT_REMOTE_PATH:-/tmp/snapshot.tar.lz4}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)

# ── fetch-url ─────────────────────────────────────────────────────────────────
if [ "$MODE" = "fetch-url" ]; then
    [ -n "${SNAPSHOT_URL:-}" ]        || die "SNAPSHOT_URL required for fetch-url"
    [ -n "${SNAPSHOT_LOCAL_PATH:-}" ] || die "SNAPSHOT_LOCAL_PATH required for fetch-url"

    if [ -s "$SNAPSHOT_LOCAL_PATH" ]; then
        echo "[snapshot-transfer] Cached: ${SNAPSHOT_LOCAL_PATH} — skipping download."
        exit 0
    fi

    mkdir -p "$(dirname "$SNAPSHOT_LOCAL_PATH")"
    echo "[snapshot-transfer] Downloading ${SNAPSHOT_URL}"
    echo "[snapshot-transfer] → ${SNAPSHOT_LOCAL_PATH}"
    # -c resumes a partial download; --max-redirect follows S3 pre-signed redirects
    wget -c --progress=bar:force --max-redirect=5 -O "$SNAPSHOT_LOCAL_PATH" "$SNAPSHOT_URL"
    echo "[snapshot-transfer] Download complete: $(du -sh "$SNAPSHOT_LOCAL_PATH" | cut -f1)"
    exit 0
fi

# ── fetch-node ────────────────────────────────────────────────────────────────
if [ "$MODE" = "fetch-node" ]; then
    [ -n "${SSH_HOST:-}" ]            || die "SSH_HOST required for fetch-node"
    [ -n "${SSH_KEY:-}" ]             || die "SSH_KEY required for fetch-node"
    [ -n "${REMOTE_DATA_DIR:-}" ]     || die "REMOTE_DATA_DIR required for fetch-node"
    [ -n "${SNAPSHOT_LOCAL_PATH:-}" ] || die "SNAPSHOT_LOCAL_PATH required for fetch-node"

    if [ -s "$SNAPSHOT_LOCAL_PATH" ]; then
        echo "[snapshot-transfer] Cached: ${SNAPSHOT_LOCAL_PATH} — skipping fetch."
        exit 0
    fi

    mkdir -p "$(dirname "$SNAPSHOT_LOCAL_PATH")"

    # Build the remote compress command — exclude WAL files (change-prone, not needed for snapshot)
    case "${SNAPSHOT_FORMAT}" in
        tar.lz4) COMPRESS_CMD="lz4 -c" ;;
        tar.zst) COMPRESS_CMD="zstd -c --fast" ;;
        tar.gz)  COMPRESS_CMD="gzip -c" ;;
        *)       COMPRESS_CMD="cat" ;;
    esac

    REMOTE_CMD="tar c --exclude='*.wal' -C '${REMOTE_DATA_DIR}' . | ${COMPRESS_CMD}"

    echo "[snapshot-transfer] Fetching data dir from ${SSH_HOST}:${SSH_PORT}"
    echo "[snapshot-transfer] Remote: ${REMOTE_DATA_DIR}"
    echo "[snapshot-transfer] Format: ${SNAPSHOT_FORMAT}"
    echo "[snapshot-transfer] → ${SNAPSHOT_LOCAL_PATH}"

    ssh "${SSH_OPTS[@]}" -i "$SSH_KEY" -p "$SSH_PORT" \
        "root@${SSH_HOST}" "$REMOTE_CMD" > "$SNAPSHOT_LOCAL_PATH"

    echo "[snapshot-transfer] Fetched: $(du -sh "$SNAPSHOT_LOCAL_PATH" | cut -f1)"
    exit 0
fi

# ── push-node ─────────────────────────────────────────────────────────────────
if [ "$MODE" = "push-node" ]; then
    [ -n "${SSH_HOST:-}" ]            || die "SSH_HOST required for push-node"
    [ -n "${SSH_KEY:-}" ]             || die "SSH_KEY required for push-node"
    [ -n "${SNAPSHOT_LOCAL_PATH:-}" ] || die "SNAPSHOT_LOCAL_PATH required for push-node"
    [ -s "$SNAPSHOT_LOCAL_PATH" ]     || die "SNAPSHOT_LOCAL_PATH not found or empty: ${SNAPSHOT_LOCAL_PATH}"

    echo "[snapshot-transfer] Pushing ${SNAPSHOT_LOCAL_PATH}"
    echo "[snapshot-transfer] → ${SSH_HOST}:${SSH_PORT}:${SNAPSHOT_REMOTE_PATH}"
    echo "[snapshot-transfer] Size: $(du -sh "$SNAPSHOT_LOCAL_PATH" | cut -f1)"

    # Ensure remote directory exists, then stream the file via SSH pipe
    # Using cat > remote_path is more portable than scp for non-interactive sessions
    ssh "${SSH_OPTS[@]}" -i "$SSH_KEY" -p "$SSH_PORT" \
        "root@${SSH_HOST}" "mkdir -p '$(dirname "$SNAPSHOT_REMOTE_PATH")'"

    cat "$SNAPSHOT_LOCAL_PATH" | ssh "${SSH_OPTS[@]}" -i "$SSH_KEY" -p "$SSH_PORT" \
        "root@${SSH_HOST}" "cat > '${SNAPSHOT_REMOTE_PATH}'"

    echo "[snapshot-transfer] Push complete."
    exit 0
fi

die "Unknown mode '${MODE}'. Valid: fetch-url | fetch-node | push-node"
