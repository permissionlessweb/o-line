#!/bin/bash
set -euo pipefail


## todo
# - improve naming convesntions of wasm addr books and snapshot files (justshould alwasy have a set of latest , with metadata file tag with datals )
# ========================= CONFIGURATION =========================
CHAIN_HOME="${CHAIN_HOME:-$HOME/.terpd-mainnet}"
CHAIN_ID="${CHAIN_ID:-morocco-1}"
BIND="${BIND:-terpd}"
SERVICE_NAME="${SERVICE_NAME:-terpd}"          # systemd service name
NETWORK_TYPE="${NETWORK_TYPE:-mainnet}"        # mainnet or test

OUTPUT_DIR="${OUTPUT_DIR:-$HOME/snapshots}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://127.0.0.1:9000}"
RPC_ENDPOINT="${RPC_ENDPOINT:-http://192.168.1.101:26657}"
S3_PROFILE="${S3_PROFILE:-minio}"
MINIO_ALIAS="${MINIO_ALIAS:-usb1}"
MINIO_BUCKET="${MINIO_BUCKET:-snapshots}"

WASM_PATH="${WASM_PATH:-wasm}"
IBC_WASM_PATH="${IBC_WASM_PATH:-ibc_08-wasm}"
# ================================================================

# Default behavior
CREATE_FULL=true
CREATE_WASM=false
CREATE_ADDRBOOK=false



print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --testnet              Use testnet paths/folders"
    echo "  --wasm-only            Create only WASM snapshot"
    echo "  --full                 Create full data snapshot (default)"
    echo "  --no-addrbook          Skip addrbook upload"
    echo "  --prune                Run pruning before snapshot"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --testnet)      NETWORK_TYPE="test" ;;
        --wasm-only)    CREATE_FULL=false; CREATE_WASM=true ;;
        --full)         CREATE_FULL=true ;;
        --no-addrbook)  CREATE_ADDRBOOK=false ;;
        --prune)        DO_PRUNE=true ;;
        -h|--help)      print_usage ;;
        *)              echo "Unknown option: $1"; print_usage ;;
    esac
    shift
done

# Set folders based on network type
if [[ "$NETWORK_TYPE" == "test" ]]; then
    SNAPSHOT_FOLDER="testnet"
    WASM_FOLDER="testnet"
    ADDRBOOK_FOLDER="testnet"
else
    SNAPSHOT_FOLDER="mainnet"
    WASM_FOLDER="mainnet"
    ADDRBOOK_FOLDER="mainnet"
fi

echo "=== Snapshot Creator for $CHAIN_ID ($NETWORK_TYPE) ==="

# ====================== SNAPSHOT METADATA ======================
create_snapshot_metadata() {
    local filename="$1"
    local snapshot_type="$2"          # "full", "wasm", or "addrbook"
    local size_mb

    size_mb=$(du -sm "$OUTPUT_DIR/$filename" 2>/dev/null | cut -f1 || echo "0")

    cat > "$OUTPUT_DIR/snapshot_${snapshot_type}.json" << EOF
{
  "chain_id": "$CHAIN_ID",
  "network_type": "$NETWORK_TYPE",
  "filename": "$filename",
  "block_height": "$BLOCK_HEIGHT",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "size_mb": $size_mb,
  "type": "$snapshot_type",
  "compression": "lz4"
}
EOF

    echo "✅ Metadata created: $OUTPUT_DIR/snapshot_${snapshot_type}.json"
    mc put "$OUTPUT_DIR/snapshot_${snapshot_type}.json" "$MINIO_ALIAS/$MINIO_BUCKET/$SNAPSHOT_FOLDER/$CHAIN_ID/"|| true
}

# ====================== 1. PRUNING ======================
if [[ "${DO_PRUNE:-false}" == true ]]; then
    echo "Pruning node..."
    pkill -f $BIND
    $BIND prune "$CHAIN_HOME" || echo "Warning: cosmprund failed or not found"
    sleep 5
    $BIND start --home $CHAIN_HOME
    echo "Service restarted successfully after pruning."
fi
# ====================== 2. GET BLOCK HEIGHT ======================
echo "Getting current block height..."
echo "$RPC_ENDPOINT"
BLOCK_HEIGHT=$(curl -s $RPC_ENDPOINT/status | jq -r '.result.sync_info.latest_block_height' || echo "unknown")
TIMESTAMP=$(date +%Y-%m-%d)
echo "Block height: $BLOCK_HEIGHT"
# ====================== 3. STOP NODE ======================
echo "Stopping node for consistent snapshot..."
pkill -f $BIND
sleep 3
cd "$CHAIN_HOME"
mkdir -p "$OUTPUT_DIR"
# ====================== 4. CREATE SNAPSHOTS ======================
if [[ "$CREATE_FULL" == true ]]; then
    echo "Creating full snapshot..."
    FILENAME="${CHAIN_ID}_${BLOCK_HEIGHT}_${TIMESTAMP}.tar.lz4"

    tar -C "$CHAIN_HOME" -c \
        --exclude="config/priv_validator_key.json" \
        --exclude="config/node_key.json" \
        --exclude="data/priv_validator_state.json" \
        . | lz4 -9 > "$OUTPUT_DIR/$FILENAME"

    echo "Uploading full snapshot to MinIO..."
    mc put "$OUTPUT_DIR/$FILENAME" "$MINIO_ALIAS/$MINIO_BUCKET/$SNAPSHOT_FOLDER/$CHAIN_ID/"
    rm -f "$OUTPUT_DIR/$FILENAME"
fi

if [[ $CREATE_WASM == true ]] && [[ $CREATE_FULL == true ]]; then
    echo "Creating wasm-only snapshot..."
    wasm_filename="${chain_id}_wasmonly_${block_height}_${timestamp}.tar.lz4"
    
    # Include both $wasm_path and $ibc_wasm_path in the single archive
    tar -cf - "$chain_home" "$wasm_path" "$ibc_wasm_path" | lz4 -9 -c > "$output_dir/$wasm_filename"
    echo "Uploading WASM snapshot..."
    mc put "$OUTPUT_DIR/$WASM_FILENAME" "$MINIO_ALIAS/$MINIO_BUCKET/$WASM_FOLDER/$CHAIN_ID/"
    rm -f "$OUTPUT_DIR/$WASM_FILENAME"
fi

# ====================== 5. ADDRBOOK ======================
if [[ "$CREATE_ADDRBOOK" == true ]]; then
    echo "Uploading addrbook.json..."
    mc put "$CHAIN_HOME/config/addrbook.json" "$MINIO_ALIAS/$MINIO_BUCKET/$ADDRBOOK_FOLDER/$CHAIN_ID/addrbook.json"
fi

create_snapshot_metadata "$FILENAME" "full"

# ====================== 6. RESTART NODE ======================
echo "Restarting node..."
echo "✅ Snapshot process completed successfully!"
echo "Chain      : $CHAIN_ID"
echo "Height     : $BLOCK_HEIGHT"
echo "Type       : ${CREATE_WASM:+WASM }${CREATE_FULL:+Full }${CREATE_ADDRBOOK:+Addrbook}"
#echo "Addrbookurl       : $MINIO_ALIAS/$MINIO_BUCKET/$WASM_FOLDER/$CHAIN_ID/"
#echo "Snapshot Url       : $MINIO_ALIAS/$MINIO_BUCKET/$WASM_FOLDER/$CHAIN_ID/"
#echo "Wasm Url       : $MINIO_ALIAS/$MINIO_BUCKET/$WASM_FOLDER/$CHAIN_ID/"