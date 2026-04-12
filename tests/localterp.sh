#!/usr/bin/env bash
# Start / stop / check local-terp for o-line e2e testing.
#
# local-terp is a single-validator Terp Network testnet that runs entirely in
# Docker.  It produces blocks every 200 ms and exposes the standard Cosmos ports
# on localhost.  The o-line e2e tests use it as the "base chain" — oline nodes
# sync from its genesis and P2P peer.
#
# Usage:
#   ./tests/localterp.sh              # start in background (default)
#   ./tests/localterp.sh start        # same
#   ./tests/localterp.sh wait         # start and block until RPC is ready
#   ./tests/localterp.sh stop         # force-remove the container
#   ./tests/localterp.sh status       # print whether container is running
#   ./tests/localterp.sh peer         # print the persistent_peer string

set -euo pipefail

CONTAINER="local-terp"
IMAGE="terpnetwork/terp-core:localterp"
RPC_P=26657
P2P_P=26656

cmd="${1:-start}"

case "$cmd" in
  stop)
    docker rm -f "$CONTAINER" 2>/dev/null || true
    echo "local-terp stopped."
    exit 0
    ;;

  status)
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
      echo "local-terp is running (container: $CONTAINER)"
      echo "  RPC: http://localhost:$RPC_P"
      echo "  P2P: localhost:$P2P_P"
    else
      echo "local-terp is NOT running. Start with: ./tests/localterp.sh start"
    fi
    exit 0
    ;;

  peer)
    NODE_ID=$(curl -sf "http://localhost:$RPC_P/status" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['result']['node_info']['id'])" 2>/dev/null \
      || jq -r '.result.node_info.id' <(curl -sf "http://localhost:$RPC_P/status") 2>/dev/null \
      || "")
    if [ -z "$NODE_ID" ]; then
      echo "ERROR: local-terp RPC not responding at http://localhost:$RPC_P" >&2
      exit 1
    fi
    echo "${NODE_ID}@host.docker.internal:${P2P_P}"
    exit 0
    ;;

  start|wait)
    ;;

  *)
    echo "Usage: $0 [start|wait|stop|status|peer]" >&2
    exit 1
    ;;
esac

# Stop any existing container (idempotent restart)
docker rm -f "$CONTAINER" 2>/dev/null || true

echo "=== Starting local-terp ($IMAGE) ==="
docker run -d \
  --name "$CONTAINER" \
  -p "${RPC_P}:26657" \
  -p "${P2P_P}:26656" \
  -p "1317:1317" \
  -p "9090:9090" \
  -p "5000:5000" \
  "$IMAGE"

echo "  Container: $CONTAINER"
echo "  RPC:       http://localhost:$RPC_P"
echo "  P2P:       localhost:$P2P_P"

if [ "$cmd" = "wait" ]; then
  echo ""
  echo "=== Waiting for RPC on localhost:$RPC_P ==="
  for i in $(seq 1 60); do
    if curl -sf "http://localhost:$RPC_P/status" >/dev/null 2>&1; then
      NODE_ID=$(curl -sf "http://localhost:$RPC_P/status" | jq -r '.result.node_info.id' 2>/dev/null || echo "unknown")
      echo ""
      echo "=== local-terp ready (attempt $i/60) ==="
      echo "  Node ID: $NODE_ID"
      echo "  Peer:    ${NODE_ID}@host.docker.internal:${P2P_P}"
      echo ""
      echo "Set in .env for e2e-network test:"
      echo "  OMNIBUS_IMAGE=oline-omnibus:local"
      exit 0
    fi
    printf "."
    sleep 2
  done
  echo ""
  echo "ERROR: local-terp RPC never came up after 120s." >&2
  echo "  Container logs:" >&2
  docker logs --tail 30 "$CONTAINER" >&2
  exit 1
fi

echo ""
echo "=== local-terp started (background) ==="
echo "  Verify: curl http://localhost:$RPC_P/status | jq .result.node_info"
echo "  Stop:   ./tests/localterp.sh stop"
