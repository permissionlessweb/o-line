#!/usr/bin/env bash
# Do NOT use set -e — we handle errors per-test so all tests run
set -uo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
IMAGE="${E2E_IMAGE:-ghcr.io/permissionlessweb/minio-ipfs:v0.0.7}"
CONTAINER_NAME="minio-ipfs-e2e"
IPFS_GW_PORT=18081
MINIO_PORT=19000
MINIO_CONSOLE_PORT=19001
MINIO_URL="http://localhost:${MINIO_PORT}"
MINIO_CONSOLE_URL="http://localhost:${MINIO_CONSOLE_PORT}"
IPFS_GW_URL="http://localhost:${IPFS_GW_PORT}"
TMPDIR="$(mktemp -d)"
PASSED=0
FAILED=0
SKIPPED=0
PINNED_CID=""
VERBOSE="${VERBOSE:-1}"
OLINE_BIN="${OLINE_BIN:-}"

# ── Helpers ──────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ "$VERBOSE" = "1" ]; then
        echo "  Dumping container logs before cleanup..."
        echo "  ---- container logs ----"
        docker logs "$CONTAINER_NAME" 2>&1 | tail -80 || true
        echo "  ---- end logs ----"
    fi
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    rm -rf "$TMPDIR"
    echo ""
    echo "========================================"
    echo "  Results: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"
    echo "========================================"
    if [ "$FAILED" -gt 0 ]; then
        exit 1
    fi
}
trap cleanup EXIT

log() {
    if [ "$VERBOSE" = "1" ]; then
        echo "  [verbose] $*"
    fi
}

pass() {
    PASSED=$((PASSED + 1))
    echo "  PASS: $1"
}

fail() {
    FAILED=$((FAILED + 1))
    echo "  FAIL: $1"
    [ -n "${2:-}" ] && echo "        $2"
}

skip() {
    SKIPPED=$((SKIPPED + 1))
    echo "  SKIP: $1"
}

wait_for() {
    local url="$1"
    local desc="$2"
    local max_attempts="${3:-30}"
    local attempt=0

    printf "  Waiting for %s " "$desc"
    while [ $attempt -lt "$max_attempts" ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo " ready (${attempt}s)"
            return 0
        fi
        printf "."
        attempt=$((attempt + 1))
        sleep 2
    done
    echo " timeout after $((attempt * 2))s"
    return 1
}

checksum() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
}

# ── Create test snapshot ─────────────────────────────────────────────────────
create_test_snapshot() {
    local name="$1"
    local staging="$TMPDIR/staging"
    mkdir -p "$staging"

    # Simulate a chain snapshot: some dirs with data files
    mkdir -p "$staging/data/application.db" "$staging/data/blockstore.db"
    dd if=/dev/urandom of="$staging/data/application.db/MANIFEST" bs=1024 count=64 2>/dev/null
    dd if=/dev/urandom of="$staging/data/application.db/000001.sst" bs=1024 count=256 2>/dev/null
    dd if=/dev/urandom of="$staging/data/blockstore.db/000001.sst" bs=1024 count=128 2>/dev/null
    echo '{"height":"12345678","hash":"AABBCCDD"}' > "$staging/data/priv_validator_state.json"

    tar -czf "$TMPDIR/$name" -C "$staging" .
    rm -rf "$staging"
    echo "$TMPDIR/$name"
}

# ── Tests ────────────────────────────────────────────────────────────────────

test_container_start() {
    echo ""
    echo "=== 1. Container Startup ==="
    log "Image: ${IMAGE}"

    # Remove any leftover container
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

    log "Starting container..."
    local run_output
    run_output=$(docker run -d \
        --name "$CONTAINER_NAME" \
        -p "${IPFS_GW_PORT}:8081" \
        -p "${MINIO_PORT}:9000" \
        -p "${MINIO_CONSOLE_PORT}:9001" \
        -e MINIO_ENABLED=true \
        -e MINIO_ROOT_USER=minioadmin \
        -e MINIO_ROOT_PASSWORD=minioadmin \
        -e MINIO_BUCKET=snapshots \
        -e AUTOPIN_INTERVAL=10 \
        -e "AUTOPIN_PATTERNS=*.tar.gz,*.tar.zst,*.tar.lz4,*.tar.xz,snapshot.json" \
        "$IMAGE" 2>&1)
    local rc=$?

    log "docker run exit code: ${rc}"
    log "docker run output: ${run_output}"

    if [ $rc -eq 0 ]; then
        pass "Container started"
    else
        fail "Container failed to start" "$run_output"
        return 1
    fi

    # Give it a moment to initialize
    sleep 3

    # Check container is actually running
    local state
    state=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>&1 || echo "not found")
    log "Container state: ${state}"

    if [ "$state" != "running" ]; then
        fail "Container is not running (state: ${state})"
        log "Container logs:"
        docker logs "$CONTAINER_NAME" 2>&1 || true
        return 1
    fi
    pass "Container is running"

    # Wait for MinIO
    if wait_for "${MINIO_URL}/minio/health/live" "MinIO S3 API" 30; then
        pass "MinIO S3 API responding"
    else
        fail "MinIO S3 API not responding after 60s"
        log "Container logs:"
        docker logs "$CONTAINER_NAME" 2>&1 | tail -30 || true
        return 1
    fi

    # Wait for IPFS gateway
    if wait_for "${IPFS_GW_URL}/ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn" "IPFS gateway" 60; then
        pass "IPFS gateway responding"
    else
        fail "IPFS gateway not responding after 120s"
        log "Container logs:"
        docker logs "$CONTAINER_NAME" 2>&1 | tail -30 || true
        return 1
    fi
}

test_minio_console() {
    echo ""
    echo "=== 2. MinIO Console UI ==="

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${MINIO_CONSOLE_URL}" 2>&1)
    log "MinIO Console HTTP ${status}"

    if [ "$status" = "200" ] || [ "$status" = "301" ] || [ "$status" = "303" ]; then
        pass "MinIO Console UI reachable (HTTP ${status})"
    else
        fail "MinIO Console UI not reachable (HTTP ${status})"
    fi
}

test_minio_health() {
    echo ""
    echo "=== 3. MinIO S3 API Health Check ==="

    # Verify health returns 200
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${MINIO_URL}/minio/health/live" 2>&1)
    if [ "$status" = "200" ]; then
        pass "MinIO health returns HTTP 200"
    else
        fail "MinIO health returned HTTP ${status}"
    fi
}

test_s3_upload_download() {
    echo ""
    echo "=== 4. S3 Upload/Download (oline test-s3) ==="

    if [ -z "$OLINE_BIN" ] || [ ! -x "$OLINE_BIN" ]; then
        skip "oline binary not available — set OLINE_BIN or build plays/oline-sdl"
        return
    fi

    log "Running: S3_KEY=minioadmin S3_SECRET=*** S3_HOST=${MINIO_URL} SNAPSHOT_PATH=snapshots $OLINE_BIN test-s3"
    local oline_output
    oline_output=$(S3_KEY=minioadmin \
        S3_SECRET=minioadmin \
        S3_HOST="${MINIO_URL}" \
        SNAPSHOT_PATH=snapshots \
        "$OLINE_BIN" test-s3 2>&1)
    local rc=$?
    log "oline test-s3 exit code: ${rc}"
    log "oline test-s3 output:"
    if [ "$VERBOSE" = "1" ]; then
        echo "$oline_output" | while IFS= read -r line; do log "  $line"; done
    fi

    if [ $rc -eq 0 ]; then
        # Check for pass/fail indicators in output
        if echo "$oline_output" | grep -qi "failed"; then
            fail "oline test-s3 reported failures" "$(echo "$oline_output" | grep -i 'failed' | head -3)"
        else
            pass "oline test-s3 passed (S3v4-signed requests validated against MinIO)"
        fi
    else
        fail "oline test-s3 exited with code ${rc}" "$(echo "$oline_output" | tail -5)"
    fi
}

test_s3_to_ipfs_pipeline() {
    echo ""
    echo "=== 5. S3 to IPFS Autopin Pipeline ==="

    # Upload a snapshot via mc and verify it gets auto-pinned to IPFS
    local snapshot_path
    snapshot_path=$(create_test_snapshot "s3-pipeline-snapshot.tar.gz")
    local upload_checksum
    upload_checksum=$(checksum "$snapshot_path")
    echo "  Created test snapshot: $(basename "$snapshot_path") ($(wc -c < "$snapshot_path" | tr -d ' ') bytes)"
    echo "  SHA256: ${upload_checksum}"

    # Upload via mc inside the container
    log "Uploading snapshot to MinIO bucket via mc..."
    docker cp "$snapshot_path" "${CONTAINER_NAME}:/tmp/s3-pipeline-snapshot.tar.gz" 2>&1
    local mc_output
    mc_output=$(docker exec "$CONTAINER_NAME" sh -c "mc alias set local http://localhost:9000 minioadmin minioadmin --api S3v4 > /dev/null 2>&1 && mc cp /tmp/s3-pipeline-snapshot.tar.gz local/snapshots/s3-pipeline-snapshot.tar.gz" 2>&1)
    local rc=$?
    log "mc upload exit code: ${rc}"

    if [ $rc -eq 0 ]; then
        pass "Snapshot uploaded to MinIO bucket via mc"
    else
        fail "Snapshot upload to MinIO failed" "$mc_output"
        return 1
    fi

    # Wait for autopin to pick it up (interval is set to 10s in the container)
    echo "  Waiting for autopin to detect S3-uploaded snapshot (up to 45s)..."
    local attempt=0
    local max_attempts=22
    local pipeline_cid=""

    while [ $attempt -lt $max_attempts ]; do
        local logs
        logs=$(docker logs "$CONTAINER_NAME" 2>&1)
        if echo "$logs" | grep -q "\[autopin\].*Pinned.*s3-pipeline-snapshot"; then
            pipeline_cid=$(echo "$logs" | grep "\[autopin\].*Pinned.*s3-pipeline-snapshot" | grep -oE "Qm[a-zA-Z0-9]{44,}|bafy[a-zA-Z0-9]{50,}" | head -1)
            break
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    if [ -n "$pipeline_cid" ]; then
        pass "S3→autopin→IPFS pipeline works (CID: ${pipeline_cid})"
        PINNED_CID="$pipeline_cid"
    else
        fail "S3→IPFS pipeline: autopin did not detect file within timeout"
        log "Autopin logs:"
        docker logs "$CONTAINER_NAME" 2>&1 | grep -i "autopin" | tail -10 | while read -r line; do log "  $line"; done
        return 1
    fi

    # Verify the auto-pinned file is downloadable from IPFS gateway
    if [ -n "$pipeline_cid" ]; then
        local dl_path="$TMPDIR/pipeline-download.tar.gz"
        log "GET ${IPFS_GW_URL}/ipfs/${pipeline_cid}"
        local status
        status=$(curl -sL -o "$dl_path" -w "%{http_code}" \
            --max-time 30 \
            "${IPFS_GW_URL}/ipfs/${pipeline_cid}" 2>&1)
        log "IPFS gateway download HTTP ${status}"

        if [ "$status" = "200" ]; then
            pass "Auto-pinned file downloadable via IPFS gateway"
        else
            fail "Auto-pinned file not downloadable via IPFS gateway (HTTP ${status})"
            return 1
        fi

        # Verify checksum matches original upload
        local dl_checksum
        dl_checksum=$(checksum "$dl_path")
        log "Download SHA256: ${dl_checksum}"

        if [ "$dl_checksum" = "$upload_checksum" ]; then
            pass "IPFS download checksum matches original"
        else
            fail "IPFS download checksum mismatch" "Expected: ${upload_checksum}, Got: ${dl_checksum}"
        fi

        # Verify it's a valid tar.gz with correct structure
        if tar -tzf "$dl_path" 2>/dev/null | grep -q "data/application.db/000001.sst"; then
            pass "IPFS-served archive has correct snapshot structure"
        else
            fail "IPFS-served archive has wrong structure"
        fi
    fi
}

test_metadata_json() {
    echo ""
    echo "=== 6. Snapshot Metadata JSON ==="

    # metadata.json is written after pinning, which happens in the same autopin cycle.
    # Poll briefly in case the upload is still in-flight.
    local attempt=0
    local meta_json=""
    echo "  Polling ${MINIO_URL}/snapshots/metadata.json..."
    while [ $attempt -lt 10 ]; do
        meta_json=$(curl -sf "${MINIO_URL}/snapshots/metadata.json" 2>/dev/null || true)
        [ -n "$meta_json" ] && break
        attempt=$((attempt + 1))
        sleep 2
    done

    if [ -z "$meta_json" ]; then
        fail "metadata.json not present in MinIO bucket after ${attempt}s"
        return 1
    fi

    # Must be valid JSON
    if ! echo "$meta_json" | jq empty 2>/dev/null; then
        fail "metadata.json is not valid JSON" "$meta_json"
        return 1
    fi
    pass "metadata.json present and valid JSON at ${MINIO_URL}/snapshots/metadata.json"
    log "metadata.json: $(echo "$meta_json" | jq -c .)"

    # Entry for the snapshot we uploaded must exist
    local entry_cid
    entry_cid=$(echo "$meta_json" | jq -r '.snapshots["s3-pipeline-snapshot.tar.gz"].ipfs_cid // empty')
    if [ -n "$entry_cid" ]; then
        pass "metadata.json contains entry for s3-pipeline-snapshot.tar.gz (CID: ${entry_cid})"
    else
        fail "metadata.json missing entry for s3-pipeline-snapshot.tar.gz"
        log "Full metadata: $meta_json"
        return 1
    fi

    # CID in metadata must match what autopin logged
    if [ -n "${PINNED_CID:-}" ]; then
        if [ "$entry_cid" = "$PINNED_CID" ]; then
            pass "Metadata CID matches auto-pinned snapshot CID"
        else
            fail "Metadata CID mismatch" "Expected: ${PINNED_CID}, Got: ${entry_cid}"
        fi
    fi

    # metadata.json itself must have been pinned to IPFS
    local meta_cid
    meta_cid=$(docker logs "$CONTAINER_NAME" 2>&1 \
        | grep "\[autopin\] Metadata pinned" \
        | grep -oE "Qm[a-zA-Z0-9]{44,}|bafy[a-zA-Z0-9]{50,}" \
        | tail -1 || true)
    if [ -n "$meta_cid" ]; then
        pass "metadata.json pinned to IPFS (CID: ${meta_cid})"
        local status
        status=$(curl -sfL -o /dev/null -w "%{http_code}" --max-time 15 \
            "${IPFS_GW_URL}/ipfs/${meta_cid}" 2>&1 || true)
        if [ "$status" = "200" ]; then
            pass "metadata.json retrievable via IPFS gateway"
        else
            fail "metadata.json not retrievable via IPFS gateway (HTTP ${status})"
        fi
    else
        fail "metadata.json was not pinned to IPFS (no log entry found)"
        log "autopin logs:"
        docker logs "$CONTAINER_NAME" 2>&1 | grep "\[autopin\]" | tail -10 | while read -r line; do log "  $line"; done
    fi
}

test_snapshot_json_in_metadata() {
    echo ""
    echo "=== 7. Node snapshot.json → IPFS CID recorded in metadata.json ==="
    # What this test verifies:
    #   Nodes upload snapshot.json: { chain_id, snapshots: [S3-url,...], latest: S3-url }
    #   autopin must (a) pin snapshot.json to IPFS and (b) write its ipfs_cid + ipfs_url
    #   into metadata.json under .snapshots["snapshot.json"].
    #   Success is confirmed by reading metadata.json from the public MinIO URL.

    local snap_url="http://localhost:${MINIO_PORT}/snapshots/s3-pipeline-snapshot.tar.gz"
    local snap_json
    snap_json=$(printf '{"chain_id":"test-chain-1","snapshots":["%s"],"latest":"%s"}' \
        "$snap_url" "$snap_url")
    local snap_json_path="${TMPDIR}/snapshot.json"
    printf '%s\n' "$snap_json" > "$snap_json_path"
    log "Uploading node-format snapshot.json: $snap_json"

    # Upload snapshot.json to the MinIO bucket
    docker cp "$snap_json_path" "${CONTAINER_NAME}:/tmp/snapshot.json" 2>&1
    local mc_output
    mc_output=$(docker exec "$CONTAINER_NAME" sh -c \
        "mc alias set local http://localhost:9000 minioadmin minioadmin --api S3v4 > /dev/null 2>&1 \
         && mc cp /tmp/snapshot.json local/snapshots/snapshot.json" 2>&1)
    if [ $? -eq 0 ]; then
        pass "snapshot.json (node format) uploaded to MinIO bucket"
    else
        fail "Failed to upload snapshot.json to MinIO" "$mc_output"
        return 1
    fi

    # Poll metadata.json directly until snapshot.json's entry (with ipfs_cid) appears.
    # This waits for the full autopin cycle to complete: pin → update_metadata → MinIO upload.
    # Avoids the race of checking metadata.json the moment "Pinned" appears in logs.
    echo "  Waiting for snapshot.json CID in metadata.json (up to 60s)..."
    local attempt=0
    local entry_cid="" meta_json=""
    while [ $attempt -lt 30 ]; do
        meta_json=$(curl -sf "${MINIO_URL}/snapshots/metadata.json" 2>/dev/null || true)
        entry_cid=$(echo "$meta_json" | jq -r '.snapshots["snapshot.json"].ipfs_cid // empty' 2>/dev/null || true)
        [ -n "$entry_cid" ] && break
        attempt=$((attempt + 1))
        sleep 2
    done

    if [ -z "$entry_cid" ]; then
        fail "snapshot.json CID did not appear in metadata.json within timeout"
        log "autopin logs:"
        docker logs "$CONTAINER_NAME" 2>&1 | grep "\[autopin\]" | tail -15 \
            | while IFS= read -r line; do log "  $line"; done
        log "metadata.json: $(echo "$meta_json" | jq -c . 2>/dev/null || echo "$meta_json")"
        return 1
    fi
    pass "metadata.json has ipfs_cid for snapshot.json: ${entry_cid}"

    # Cross-verify CID against what autopin logged
    local log_cid
    log_cid=$(docker logs "$CONTAINER_NAME" 2>&1 \
        | grep "\[autopin\] Pinned snapshot\.json ->" \
        | grep -oE "Qm[a-zA-Z0-9]{44,}|bafy[a-zA-Z0-9]{50,}" \
        | tail -1 || true)
    if [ -n "$log_cid" ] && [ "$entry_cid" = "$log_cid" ]; then
        pass "metadata.json CID matches autopin log"
    elif [ -n "$log_cid" ]; then
        fail "CID mismatch" "Log: ${log_cid}, Metadata: ${entry_cid}"
    fi

    # Fetch snapshot.json back via IPFS gateway and verify node-format structure
    local dl_json gw_chain_id
    dl_json=$(curl -sfL --max-time 15 "${IPFS_GW_URL}/ipfs/${entry_cid}" 2>/dev/null || true)
    gw_chain_id=$(echo "$dl_json" | jq -r '.chain_id // empty' 2>/dev/null || true)
    if [ "$gw_chain_id" = "test-chain-1" ]; then
        pass "snapshot.json retrievable via IPFS gateway with correct node-format structure"
    else
        fail "snapshot.json not retrievable via IPFS gateway or structure wrong" \
            "chain_id: '${gw_chain_id}'"
    fi
}

# ── Build / locate oline binary ──────────────────────────────────────────────
if [ -z "$OLINE_BIN" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    OLINE_PROJECT="${SCRIPT_DIR}/../oline-sdl"
    OLINE_RELEASE="${OLINE_PROJECT}/target/release/oline"

    if [ -x "$OLINE_RELEASE" ]; then
        OLINE_BIN="$OLINE_RELEASE"
    else
        echo "  Building oline from source (${OLINE_PROJECT})..."
        if (cd "$OLINE_PROJECT" && cargo build --release 2>&1); then
            OLINE_BIN="$OLINE_RELEASE"
        else
            echo "  WARNING: Failed to build oline — S3 tests will be skipped"
            OLINE_BIN=""
        fi
    fi
fi

# ── Run Tests ────────────────────────────────────────────────────────────────
echo "========================================"
echo "  minio-ipfs E2E Tests"
echo "========================================"
echo "  Image:         ${IMAGE}"
echo "  MinIO S3:      ${MINIO_URL}"
echo "  MinIO Console: ${MINIO_CONSOLE_URL}"
echo "  IPFS GW:       ${IPFS_GW_URL}"
echo "  oline bin:     ${OLINE_BIN:-"(not found — S3 tests will skip)"}"
echo "  Temp dir:      ${TMPDIR}"
echo "  Verbose:       ${VERBOSE}"

test_container_start
test_minio_console
test_minio_health
test_s3_upload_download
test_s3_to_ipfs_pipeline
test_metadata_json
test_snapshot_json_in_metadata
