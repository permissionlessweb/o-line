#!/bin/bash
# pin-html.sh — Pin HTML files from the site bucket to IPFS
#
# Usage:
#   ./pin-html.sh [files...]
#   ./pin-html.sh index.html pins.terp.network/index.html
#
# If no files specified, pins all HTML files in the bucket.
#
# Environment:
#   MEDIA_CENTER_HOST  — Hostname/IP of instant-replay instance (default: localhost)
#   MEDIA_CENTER_S3_PORT — MinIO S3 port (default: 9000)
#   MINIO_USER            — S3 access key
#   MINIO_KEY             — S3 secret key

set -euo pipefail

MEDIA_CENTER_HOST="${MEDIA_CENTER_HOST:-localhost}"

BUCKET="static"

# ─── Functions ─────────────────────────────────────────

function ensure_alias() {
  mc alias set media "http://$MEDIA_CENTER_HOST:$MEDIA_CENTER_S3_PORT" "$MINIO_USER" "$MINIO_KEY" >/dev/null 2>&1 || true
}

function pin_file_via_docker() {
  local object_path="$1"
  local container_name="minio-ipfs"
  
  # Method 1: Try docker exec (if running locally with docker compose)
  if docker inspect "$container_name" >/dev/null 2>&1; then
    docker exec "$container_name" /usr/local/bin/ipfs-pin "/data/minio/$object_path" 2>/dev/null || return 1
    return 0
  fi
  
  # Method 2: SSH to media center and execute
  if [ -n "${SSH_USER:-}" ]; then
    ssh -o ConnectTimeout=5 "$SSH_USER@$MEDIA_CENTER_HOST" \
      "docker exec minio-ipfs /usr/local/bin/ipfs-pin /data/minio/$object_path" 2>/dev/null || return 1
    return 0
  fi
  
  return 1
}

function discover_html_files() {
  mc ls "$BUCKET" --recursive --human-readable 2>/dev/null | grep '\.html$' | awk '{print $NF}'
}

# ─── Parse args ────────────────────────────────────────
FILES=("$@")

if [ ${#FILES[@]} -eq 0 ]; then
  echo "No files specified, discovering all HTML files in bucket..."
  mapfile -t FILES < <(discover_html_files)
fi
echo "Pinning ${#FILES[@]} HTML file(s) to IPFS..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ensure_alias
SUCCESS=0
FAILED=0
for file in "${FILES[@]}"; do
  if [ -n "$file" ]; then
    if pin_file_via_docker "$file"; then
      # Get and display the CID
      cid=$(docker exec minio-ipfs ipfs cat "/data/minio/$file" 2>/dev/null | sha256sum | cut -d' ' -f1 | tail -c
