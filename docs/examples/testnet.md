---
title: testnet-deploy
---

# oline testnet-deploy

Bootstrap a fresh testnet on Akash Network. Deploys a single Akash
deployment containing an nginx load balancer and two sentry nodes.
DNS endpoints are unified behind the LB — scaling sentries requires
no DNS changes.

## Quick start

```bash
# Pass 1 — create deployment, collect provider bids, exit
OLINE_PASSWORD=<password> RUST_LOG=info oline testnet-deploy \
  --chain-id 120u-1 \
  --profile testnet \
  --validator-rpc https://rpc-validator-testnet.terp.network \
  --validator-peer <node_id>@<host>:<port> \
  --non-interactive

# Pass 2 — accept lease from chosen provider, send manifest, bootstrap nodes
OLINE_PASSWORD=<password> RUST_LOG=info oline testnet-deploy \
  --chain-id 120u-1 \
  --profile testnet \
  --validator-rpc https://rpc-validator-testnet.terp.network \
  --validator-peer <node_id>@<host>:<port> \
  --non-interactive --resume \
  --provider-a <akash_provider_address>
```

## Architecture

A **single Akash deployment** (one DSEQ, one provider, one lease) contains
three services that communicate via Akash inter-service DNS:

```
                 Internet
                    │
               port 80 (global)
                    │
            ┌───────────────┐
            │   nginx LB    │  testnet-lb
            │               │  0.5 CPU / 512Mi
            └───────────────┘
              │           │
    ┌─────────┘           └─────────┐
    │ internal ports only           │ internal ports only
    │ 26657 / 1317 / 9090           │ 26657 / 1317 / 9090
    │                               │
┌───────────────┐         ┌───────────────┐
│  Sentry A     │◄───────►│  Sentry B     │
│ testnet-      │  26656  │ testnet-      │
│ sentry-a      │         │ sentry-b      │
│ 2 CPU / 8Gi   │         │ 2 CPU / 8Gi   │
└───────────────┘         └───────────────┘
        │                         │
        └──────────┬──────────────┘
                   │ persistent_peers
             ┌─────────────┐
             │  Validator  │  external or Phase V
             │  (private)  │
             └─────────────┘
```

**Key properties:**
- LB routes by `Host` header — `rpc-testnet.terp.network`, `api-testnet.terp.network`, `grpc-testnet.terp.network` each map to a separate nginx upstream pool
- Sentry RPC/API/gRPC ports are **not** globally exposed — only reachable through the LB service
- Both sentries expose P2P (port 26656) to each other and to the LB service only
- SSH ports for each service are exposed globally for operator access
- The validator is configured as a private peer (`private_peer_ids`, `unconditional_peer_ids`) — never gossiped

## Two-pass deployment flow

**Why two passes?** Akash requires you to review provider bids (price, host,
location) before committing. Pass 1 creates the deployment on-chain and waits
for bids. Pass 2 accepts one bid, creates the lease, and sends the manifest.

```
Pass 1:                                Pass 2 (--resume):
  1. Verify external validator RPC       1. Load saved deployment state
  2. Build lb_vars from config           2. Accept bid from --provider-a
  3. Render testnet-lb.yml SDL           3. Batch MsgCreateLease tx
  4. MsgCreateDeployment on Akash        4. Send manifest to provider
  5. Collect provider bids               5. Get service endpoints
  6. Save state to disk                  6. SFTP lb-init.sh → LB container
  7. Print bids + resume command         7. SFTP scripts → sentry-a, sentry-b
  8. Exit                                8. Signal OLINE_PHASE=start
                                         9. Print endpoint summary
```

## Before you start

**Prerequisites:**
- `oline` built and installed on groot2 (`just install` in the o-line repo)
- Funded Akash wallet configured in the `testnet` profile
- SSH key at `secrets/oline-testnet-key` (auto-generated on first run)
- External validator running and reachable (or omit `--validator-rpc` to deploy one)

**Close any stale deployments first:**
```bash
OLINE_PASSWORD=<password> oline manage sync
# If any testnet DSEQs appear:
OLINE_PASSWORD=<password> oline manage close <DSEQ_1> <DSEQ_2>
```

## Step-by-step: local validator (120u-1)

When the validator is already running locally (e.g. via Docker), the sentries
deploy on Akash and sync from genesis independently. After they're up, the
validator dials OUT to the sentries as `persistent_peers` — no inbound ports
needed on the validator machine.

### Step 0 — Verify local validator is running

```bash
# Start the validator if not already running
./scripts/sh/run-testnet-validator.sh 120u-1

# Confirm it's synced and producing blocks
curl -s http://127.0.0.1:36657/status | jq '.result.sync_info.catching_up'
# → false

# Get the validator node ID (needed later for peering)
docker exec testnet-validator terpd tendermint show-node-id
# → 1e93e6926530871e9480ec1b2c430c40a28ce9e8
```

### Step 1 — Pass 1: create deployment

```bash
OLINE_PASSWORD=welcometest RUST_LOG=info oline testnet-deploy \
  --chain-id 120u-1 \
  --profile testnet \
  --validator-rpc http://127.0.0.1:36657 \
  --non-interactive
```

This creates the Akash deployment (LB + 2 sentries), waits for provider bids,
saves state, and exits with a resume command. No `--validator-peer` needed —
the sentries sync from genesis with `pex=true`.

### Step 2 — Review bids and choose a provider

Pick a provider from the printed bid list. Prefer providers with low latency
and known uptime. The `host:` URL tells you who operates the provider.

### Step 3 — Pass 2: accept lease, bootstrap nodes

```bash
OLINE_PASSWORD=welcometest RUST_LOG=info oline testnet-deploy \
  --chain-id 120u-1 \
  --profile testnet \
  --validator-rpc http://127.0.0.1:36657 \
  --non-interactive --resume \
  --provider-a <PROVIDER_ADDRESS>
```

After the lease is created, oline sends the manifest and bootstraps the
sentries via SFTP. Output includes all service endpoints.

### Step 4 — Wire the local validator to sentries

After sentries are deployed, get their node IDs and wire the validator:

```bash
# Get sentry node IDs from the SSH endpoints printed by oline
ssh -i ~/.oline/oline-testnet-key root@<PROVIDER_HOST> -p <SENTRY_A_SSH_PORT> \
  terpd tendermint show-node-id
ssh -i ~/.oline/oline-testnet-key root@<PROVIDER_HOST> -p <SENTRY_B_SSH_PORT> \
  terpd tendermint show-node-id

# Wire validator to dial out to both sentries
docker exec testnet-validator sh -c \
  "sed -i 's/persistent_peers = .*/persistent_peers = \"<A_ID>@<A_HOST>:<A_P2P_PORT>,<B_ID>@<B_HOST>:<B_P2P_PORT>\"/' ~/.terpd/config/config.toml"
docker restart testnet-validator
```

The validator connects outbound — no firewall changes needed.

### Step 5 — Set up DNS (Cloudflare)

Point DNS A records to the provider's IP (from lease endpoints):

```bash
# Use oline's DNS command or set manually in Cloudflare:
#   rpc-testnet.terp.network → <PROVIDER_IP> (proxied)
#   api-testnet.terp.network → <PROVIDER_IP> (proxied)

oline dns set --profile testnet
```

### Step 6 — Verify RPC DNS endpoints

```bash
# Check DNS resolution
dig +short rpc-testnet.terp.network
dig +short api-testnet.terp.network

# Verify end-to-end: chain ID matches
curl -s https://rpc-testnet.terp.network/status | jq '.result.node_info.network'
# → "120u-1"

# Verify block height advancing
curl -s https://api-testnet.terp.network/cosmos/base/tendermint/v1beta1/blocks/latest \
  | jq '.block.header.height'
```

### Step 7 — SSH access

Each service gets a globally-exposed SSH port. Use the SSH key generated
during deployment:

```bash
# LB container
ssh -i ~/.oline/oline-testnet-key root@<PROVIDER_HOST> -p <LB_SSH_PORT>

# Sentry A
ssh -i ~/.oline/oline-testnet-key root@<PROVIDER_HOST> -p <SENTRY_A_SSH_PORT>

# Sentry B
ssh -i ~/.oline/oline-testnet-key root@<PROVIDER_HOST> -p <SENTRY_B_SSH_PORT>
```

## Step-by-step: remote validator

If the validator is hosted externally (not localhost), use `--validator-rpc`
and `--validator-peer` to point the sentries at it:

```bash
OLINE_PASSWORD=<password> RUST_LOG=info oline testnet-deploy \
  --chain-id 120u-1 \
  --profile testnet \
  --validator-rpc https://rpc-validator-testnet.terp.network \
  --validator-peer <node_id>@<host>:<port> \
  --non-interactive
```

The rest of the flow (Pass 2, DNS, verification) is the same as above.

## Scaling sentries

To add a third sentry, edit `templates/sdls/oline/testnet-lb.yml`:
1. Add a `testnet-sentry-c` service (copy sentry-b, change moniker)
2. Add `:26656` expose to `testnet-sentry-c` in sentry-a and sentry-b blocks
3. Add `testnet-sentry-c:26657`, `:1317`, `:9090` to `UPSTREAM_*` env vars on the LB
4. Add `testnet-sentry-c` compute + placement + deployment profiles

No DNS changes needed — the LB upstream pool expands automatically on redeploy.

## What changed from the 3-phase architecture

Previously `testnet-deploy` created three separate Akash deployments (Phase A
snapshot+seed, Phase B tackles, Phase C forwards) across up to three different
providers, requiring three provider selections and complex inter-phase peer
coordination. The new architecture:

| Old (3-phase) | New (LB) |
|---|---|
| 3 DSEQs, 3 providers | 1 DSEQ, 1 provider |
| Phase A: snapshot + seed nodes | Sentry A: pruning=nothing |
| Phase B: tackles (statesync relay) | Sentry B: pruning=default |
| Phase C: forwards (public RPC) | LB: nginx upstream pool |
| DNS → individual sentry IPs | DNS → LB (stable endpoint) |
| 3 `--provider-*` flags required | 1 `--provider-a` flag |
| Complex peer ID extraction between phases | No cross-phase coordination |
| Sentries run cloudflared for P2P tunnel | Sentries connect to validator directly via peer string |

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `OLINE_PASSWORD` | Wallet keystore password | `oline-test` |
| `OLINE_MNEMONIC` | Akash account mnemonic (non-interactive) | required if non-interactive |
| `OLINE_NON_INTERACTIVE` | Skip all interactive prompts | unset |
| `OLINE_SCRIPTS_PATH` | Path to entrypoint scripts dir | `plays/audible` |
| `SECRETS_PATH` | Directory for SSH key and cached files | `.` |
| `RUST_LOG` | Log verbosity (`info`, `debug`) | unset |

## Files involved

| File | Role |
|---|---|
| `templates/sdls/oline/testnet-lb.yml` | Akash SDL — LB + 2 sentries |
| `plays/audible/lb-init.sh` | nginx entrypoint — generates upstream configs from env vars |
| `plays/audible/oline-entrypoint.sh` | Sentry entrypoint — skips cloudflared when behind LB |
| `src/cmd/testnet.rs` | `testnet-deploy` command implementation |
| `secrets/oline-testnet-key` | SSH keypair (auto-generated, gitignored) |
