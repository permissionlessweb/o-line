# ── Provider Proxy + Akash Light Node ────────────────────────────────────────
# Multi-stage build producing a single container that runs:
#   1. Console provider-proxy (TypeScript/Hono) — mTLS to Akash providers
#   2. Akash full node (pruned) — RPC/REST/gRPC for cert validation
#
# The proxy validates provider certificates against the co-located node's
# REST API, so o-line clients never connect directly to providers.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build provider-proxy from Akash Console source ─────────────────
FROM node:24-alpine AS proxy-builder

WORKDIR /build

# Clone the console repo (provider-proxy app only)
RUN apk add --no-cache git && \
    git clone --depth 1 --filter=blob:none --sparse \
      https://github.com/akash-network/console.git /build && \
    cd /build && \
    git sparse-checkout set apps/provider-proxy packages/http-sdk

# Install dependencies and build
RUN cd /build && \
    npm install --workspace=apps/provider-proxy --include-workspace-root && \
    npm run build --workspace=apps/provider-proxy

# ── Stage 2: Akash node binary ──────────────────────────────────────────────
FROM ghcr.io/akash-network/node:latest AS akash-node

# ── Stage 3: Runtime ────────────────────────────────────────────────────────
FROM node:24-alpine

RUN apk add --no-cache wget bash

# Copy Akash node binary
COPY --from=akash-node /bin/akash /usr/bin/akash

# Copy built provider-proxy
COPY --from=proxy-builder /build/apps/provider-proxy /app/provider-proxy
COPY --from=proxy-builder /build/node_modules /app/node_modules

# Initialize Akash node config (will be overridden by env vars at runtime)
RUN akash init oline-proxy-node --chain-id akashnet-2 --home /root/.akash 2>/dev/null || true

EXPOSE 3000 26657 1317 9090

# Default: both services managed by the SDL entrypoint script
CMD ["sh", "-c", "echo 'Use SDL entrypoint or docker-compose to start services'"]
