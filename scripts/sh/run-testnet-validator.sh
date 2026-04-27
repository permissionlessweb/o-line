#!/bin/bash
# Run a local testnet validator. The validator is private — it dials OUT to
# the Akash sentries as persistent_peers. No public ports are exposed.
#
# Usage:
#   ./scripts/sh/run-testnet-validator.sh [chain-id]
#
# After the validator starts, export the genesis, pin it to IPFS, set
# CHAIN_GENESIS_URL in config.toml, then deploy the sentries:
#
#   oline testnet-deploy --profile testnet --chain-id 120u-1
#
# After sentries are up, get their node IDs and add them as persistent_peers
# in config.toml before starting the validator for real (see step 3 below).

set -euo pipefail

CHAIN_ID="${1:-120u-1}"
VALIDATOR_CONTAINER="testnet-validator"
LOCALTERP_IMAGE="${LOCALTERP_IMAGE:-ghcr.io/terpnetwork/terp-core:v5.2.0-testnet-localterp}"

echo "=== Starting local testnet validator ==="
echo "  Chain ID: $CHAIN_ID"
echo "  Image:    $LOCALTERP_IMAGE"
echo ""

docker rm -f "$VALIDATOR_CONTAINER" 2>/dev/null || true

docker run -d \
  --name "$VALIDATOR_CONTAINER" \
  --restart unless-stopped \
  -p "127.0.0.1:36656:26656" \
  -p "127.0.0.1:36657:26657" \
  -p "127.0.0.1:31317:1317" \
  -p "127.0.0.1:39090:9090" \
  -p "127.0.0.1:35000:5000" \
  -e "CHAINID=${CHAIN_ID}" \
  -e "FAST_BLOCKS=true" \
  -e "ENABLE_FAUCET=true" \
  "$LOCALTERP_IMAGE"

echo "Container started. Waiting for terpd to initialize (up to 60s)..."

MAX_WAIT=60
WAITED=0
while ! curl -sf "http://127.0.0.1:36657/status" >/dev/null 2>&1; do
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo "ERROR: terpd did not start within ${MAX_WAIT}s"
    docker logs --tail 50 "$VALIDATOR_CONTAINER"
    exit 1
  fi
  sleep 3
  WAITED=$((WAITED + 3))
  echo "  ... ${WAITED}s"
done

NODE_ID=$(docker exec "$VALIDATOR_CONTAINER" terpd tendermint show-node-id 2>/dev/null)

docker exec "$VALIDATOR_CONTAINER" sh -c "
  sed -i 's/^pex = true/pex = false/' ~/.terpd/config/config.toml
"

docker restart "$VALIDATOR_CONTAINER"
sleep 3

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  LOCAL TESTNET VALIDATOR RUNNING"
echo "════════════════════════════════════════════════════════════"
echo "  Chain ID:    $CHAIN_ID"
echo "  Node ID:     $NODE_ID"
echo "  RPC (local): http://127.0.0.1:36657"
echo "  API (local): http://127.0.0.1:31317"
echo "  Faucet:      http://127.0.0.1:35000/faucet?address=<addr>"
echo ""
echo "  1. Export genesis and pin to IPFS:"
echo "     curl -s http://127.0.0.1:36657/genesis | jq .result.genesis > /tmp/genesis-${CHAIN_ID}.json"
echo "     ipfs add /tmp/genesis-${CHAIN_ID}.json"
echo "     # Set CHAIN_GENESIS_URL = https://ipfs.io/ipfs/<CID> in config.toml"
echo ""
echo "  2. Deploy sentries (they start with pex, no validator peer needed):"
echo "     oline testnet-deploy --profile testnet --chain-id ${CHAIN_ID}"
echo ""
echo "  3. After sentries are up, get sentry node IDs (printed by oline on deploy),"
echo "     then wire the validator to dial out to them:"
echo "     docker exec $VALIDATOR_CONTAINER sh -c \\"
echo "       \"sed -i 's/persistent_peers = .*/persistent_peers = \\\"<A_ID>@<A_HOST>:<A_P2P_PORT>,<B_ID>@<B_HOST>:<B_P2P_PORT>\\\"/' ~/.terpd/config/config.toml\""
echo "     docker restart $VALIDATOR_CONTAINER"
echo "════════════════════════════════════════════════════════════"
