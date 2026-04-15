# Plan: Deploy Terp Network Sentry Array + Testnet via oline on Akash

**Goal**: Deploy the full Terp Network validator sentry topology (mainnet array) AND a fresh testnet onto Akash Network containers, with robust error handling, log monitoring, and retry management throughout.

**Binary**: `oline` (Rust CLI at `~/abstract/bme/o-line/`)
**Target**: Akash Network containers (decentralized compute)
**Phases**: A (Special Teams) → B (Tackles) → C (Forwards) → E (Relayer) + Testnet variant

---

## 0. Prerequisites — What You Need Before Starting

### Environment setup on groot2

```bash
# Ensure oline is built and installed
cd ~/abstract/bme/o-line
just install  # cargo install --path .
```

### Required secrets (must be set in .env or entered interactively)

| Secret | How to set | Purpose |
|--------|-----------|---------|
| Mnemonic (24 words) | `oline encrypt` → writes `OLINE_ENCRYPTED_MNEMONIC` to `.env` | Akash account signing + HD child derivation |
| Cloudflare API token | `OLINE_CF_API_TOKEN` in `.env` | DNS CNAME management |
| Cloudflare zone ID | `OLINE_CF_ZONE_ID` in `.env` | DNS zone targeting |

### Required config (set via `oline init` or `.env`)

Run `oline init` interactively, or `oline init --template terp-mainnet` for defaults. This writes `deploy-config.json` which you can review before deploying.

Key config values to verify:
- `OLINE_CHAIN_ID` = `morocco-1` (mainnet) or your testnet chain ID
- `OMNIBUS_IMAGE` = `ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic`
- `OLINE_BINARY` = `terpd`
- Domain assignments for each phase (RPC_D_SNAP, P2P_D_SNAP, RPC_D_FL, etc.)
- Snapshot storage config (OLINE_SNAP_PATH, OLINE_SNAP_DOWNLOAD_DOMAIN)

### Verify Akash connectivity

```bash
# Probe endpoints — picks fastest RPC/gRPC and saves to .env
oline endpoints save

# Quick health check on saved endpoints
oline endpoints check

# Optional: verify S3/MinIO bucket access
oline test-s3

# Optional: test gRPC-Web
oline test-grpc grpc.terp.network
```

**If `oline endpoints` fails**: The endpoint prober queries the Cosmos Chain Registry. If the network is unreachable, it falls back to a hardcoded list. If ALL endpoints are dead, check your internet connectivity and Akash network status.

---

## 1. Mainnet Sentry Array Deployment

### Architecture overview

```
Phase A (1 Akash deployment, 3 services):
  [oline-a-snapshot]    ← syncs chain, serves snapshots
  [oline-a-seed]        ← P2P seed node
  [oline-a-minio-ipfs]  ← S3 snapshot storage + IPFS pinning

Phase B (1 Akash deployment, 2 services):
  [oline-b-left-tackle]   ← private sentry (validator-facing)
  [oline-b-right-tackle]  ← private sentry (validator-facing)

Phase C (1 Akash deployment, 2 services):
  [oline-c-left-forward]   ← public RPC/API (rpc.terp.network)
  [oline-c-right-forward]  ← public RPC/API (rpc2.terp.network)

Phase E (1 Akash deployment, 1 service):
  [oline-e-relayer]  ← IBC relayer

Data flow: Validator ↔ Tackles ↔ Snapshot/Seed ↔ Forwards ↔ Public
```

### 1.1. Start the deployment

**Parallel mode (default, recommended)**:
```bash
oline deploy
```

**What this does internally — step by step:**
1. **FundChildAccounts** — Derives 4 HD child accounts (BIP44 m/44'/118'/0'/0/{1..4}), funds each from master wallet
2. **DeployAllUnits** — Renders SDL templates (a.yml, b.yml, c.yml, e.yml) with config vars, broadcasts `MsgCreateDeployment` for all phases
3. **SelectAllProviders** — You interactively pick providers for each deployment (or `OLINE_AUTO_SELECT=1` picks cheapest)
4. **UpdateAllDns** — Cloudflare CNAME records for all accept domains
5. **WaitSnapshotReady** — Polls snapshot node `/status` until `catching_up=false`
6. **DistributeSnapshot** — SSH-streams snapshot archive from snapshot node to all waiting nodes simultaneously
7. **SignalAllNodes** — Pushes TLS certs + fires `OLINE_PHASE=start` on all nodes concurrently
8. **InjectPeers** — SSH-pushes updated peer lists to all nodes
9. **WaitAllPeers** — Polls all node RPCs concurrently until each reports ≥1 connected peer
10. **Summary** — Prints final topology with DSEQs, hostnames, and endpoints

**Sequential mode (if parallel has issues)**:
```bash
oline deploy --sequential
```
Deploys one phase at a time: A → B → C → E. Slower (~60 min more) but simpler state machine.

**Non-interactive / CI mode**:
```bash
OLINE_NON_INTERACTIVE=1 \
OLINE_MNEMONIC="word1 word2 ... word24" \
OLINE_PASSWORD=mypassword \
OLINE_AUTO_SELECT=1 \
  oline deploy
```

### 1.2. Monitoring during deployment

**The TUI activates automatically** after provider selection in parallel mode. It shows split-pane live logs from each deployed unit via WebSocket streams to Akash providers. You do NOT need to set this up — it's built in.

**If the TUI disconnects or you close the terminal**:
```bash
# Reconnect to the TUI log viewer
oline manage tui --session <session-id>

# Find your session ID
ls ~/.oline/sessions/
```

**Check deployment status from another terminal**:
```bash
# On-chain status of session deployments
oline manage status --session <session-id>

# Or list all active deployments
oline manage sync
```

**Stream logs for a specific deployment**:
```bash
# WebSocket log stream from Akash provider
oline manage logs <dseq> --tail 100
oline manage logs <dseq> --service oline-a-snapshot --tail 200
```

### 1.3. Error recovery during deployment

**General principle**: oline's parallel workflow is NOT idempotent from the start, but individual steps have retries built in:

| Operation | Retry behavior | Max wait |
|-----------|---------------|----------|
| SSH connect | Exponential backoff: 2s→4s→8s→16s→30s | 5-8 attempts (~90s) |
| File delivery (SFTP) | Fixed 5s interval | 30 attempts (150s) |
| File delivery (SSH pipe, large) | Fixed 10s interval | 30 attempts (300s) |
| MinIO SFTP delivery | Fixed 10s interval | 60 attempts (600s) |
| Peer ID polling (snapshot) | 120s boot wait, then 30s interval | 10 retries (420s total) |
| Peer ID polling (seed) | 300s boot wait, then 60s interval | 20 retries (1500s total) |
| Peer ID polling (tackles) | 300s boot wait, then 60s interval | 20 retries (1500s total) |
| Akash bid wait | ~12s per check | 10 iterations (120s) |

**If a phase fails (B, C, or E)**: The pipeline continues to the next phase. Only Phase A failure is fatal (it provides the snapshot that everything else depends on). Check the summary at the end for which phases succeeded/failed.

**If the whole deploy crashes mid-way**: You can manage the partial deployment:
```bash
# Sync local records with chain state (finds orphaned deployments)
oline manage sync

# Close a failed/stuck deployment
oline manage  # interactive — select deployment, choose "close"

# Drain leftover funds from HD child accounts back to master
oline manage drain --execute
```

**If a node is stuck / needs restart**:
```bash
# SSH restart (kills process, re-runs entrypoint)
oline manage restart "Phase A - Snapshot"

# Or via refresh (more control over env vars)
oline refresh run "oline-a-snapshot"
```

### 1.4. Post-deployment health checks

```bash
# Check RPC health of all registered nodes
oline refresh status

# Output:
#   oline-a-snapshot: terp-snap @ height 8234567  ✓
#   oline-a-seed:     terp-seed @ height 8234560  ✓
#   oline-b-left-tackle:  lt-abc123 @ height 8234565  ✓
#   ...

# Check the dedicated Akash node (if deployed)
oline node status

# Test a specific gRPC endpoint
oline test-grpc grpc.terp.network

# Verify DNS is resolving
dig rpc.terp.network
dig api.terp.network
```

### 1.5. Day-2 operations (after deploy is running)

**Push updated env vars without redeploying**:
```bash
# Push new config to a specific node
oline refresh run "oline-a-snapshot"

# Push to all nodes of a phase (conceptually — run for each label)
oline refresh list  # see all labels
oline refresh run "oline-b-left-tackle"
oline refresh run "oline-b-right-tackle"
```

**Restart a node** (re-runs the bootstrap entrypoint):
```bash
oline manage restart "Phase B - Left Tackle"
```

**Update DNS records manually**:
```bash
oline dns  # interactive CNAME/A record upsert
```

**Prune stale SSH keys** (after closing old deployments):
```bash
oline manage prune-keys
```

**Return unused funds from child accounts**:
```bash
# Dry run — shows what would be drained
oline manage drain

# Execute the drain
oline manage drain --execute
```

---

## 2. Testnet Deployment

The testnet uses a separate command that deploys a localterp validator + faucet alongside the sentry array.

### 2.1. Testnet-specific prerequisites

You need a pre-built `localterp` Docker image pushed to a registry:
```bash
# The image must be accessible from Akash providers
# Default: ghcr.io/permissionlessweb/localterp:latest
```

### 2.2. Deploy the testnet

```bash
oline testnet-deploy --chain-id testnet-1 --fast-blocks
```

**Flags**:
- `--chain-id <ID>` — testnet chain ID (default: `testnet-1`)
- `--fast-blocks` — 200ms block timeouts (for rapid testing)
- `--localterp-image <IMAGE>` — Docker image for the validator (env: `LOCALTERP_IMAGE`)
- `--raw` — enter mnemonic interactively
- `--non-interactive` — use env vars only

**Testnet architecture** (same sentry topology but with genesis bootstrapping):
```
Phase A (testnet):
  [Validator+Faucet (localterp)]  ← generates genesis, never publicly exposed
  [Snapshot node (omnibus)]       ← OLINE_OFFLINE=1, genesis delivered via SFTP
  [Seed node (omnibus)]           ← OLINE_OFFLINE=1, genesis delivered via SFTP

Phase B (testnet):
  [Left Tackle]  ← OLINE_OFFLINE=1, genesis via SFTP
  [Right Tackle]  ← OLINE_OFFLINE=1, genesis via SFTP

Phase C (testnet):
  [Left Forward]  ← OLINE_OFFLINE=1, genesis via SFTP
  [Right Forward]  ← OLINE_OFFLINE=1, genesis via SFTP
```

Key difference from mainnet: all sentry nodes start with `OLINE_OFFLINE=1` and receive genesis from the validator via SFTP after it generates the chain. The validator is configured as a private peer on all sentries (never gossiped publicly).

SDL templates used: `testnet-a.yml`, `testnet-b.yml`, `testnet-c.yml`

### 2.3. Testnet monitoring

Same monitoring commands as mainnet — `oline refresh status`, `oline manage logs`, `oline manage tui`.

The faucet runs on port 5000 of the validator service, accessible via the accept domain configured in the SDL.

---

## 3. Logging and Tracing Reference

### Log levels (set via RUST_LOG env var)

```bash
# Default: info level
oline deploy

# Debug level (verbose SSH/RPC details)
RUST_LOG=debug oline deploy

# Trace level (everything including retry sleeps)
RUST_LOG=trace oline deploy

# Target-specific
RUST_LOG=oline=debug,akash_deploy_rs=info oline deploy
```

### Log output destinations

| Mode | Where logs go |
|------|--------------|
| Normal CLI | stdout (formatted via tracing-subscriber) |
| Parallel deploy (post-provider-selection) | TUI split panes (via mpsc channel) |
| TUI reconnect | `oline manage tui` — WebSocket streams from providers |
| Per-deployment logs | `oline manage logs <dseq>` — WebSocket from provider |

### Key log prefixes to watch for

| Prefix | Meaning |
|--------|---------|
| `[deploy]` | Akash deployment state machine progress |
| `[dns]` | Cloudflare DNS operations |
| `[ssh]` | SSH/SFTP operations (file push, signal start) |
| `[snapshot]` | Snapshot fetch/push progress |
| `[peer]` | Peer ID polling progress |
| `[fund]` | HD child account funding |
| `[rpc]` | RPC health check results |
| `WARN` | Non-fatal issue (phase skip, DNS skip, peer timeout) |
| `ERROR` | Fatal issue (phase A failure, SSH key missing) |

---

## 4. Retry Tuning Reference

These environment variables control retry behavior. Set them in `.env` or export before running `oline deploy`:

| Variable | Default | Controls |
|----------|---------|----------|
| `OLINE_RPC_INITIAL_WAIT` | 120 (snapshot), 300 (seed/tackles) | Seconds to wait before first RPC poll |
| `OLINE_MAX_BID_WAIT` | 10 | Akash bid wait iterations (×12s each) |
| `MINIO_SFTP_RETRIES` | 60 | MinIO file delivery retry count |
| `RUST_LOG` | `info` | Log verbosity |

The source code constant `MAX_RETRIES = 30` (in `src/lib.rs`) governs most SSH/SFTP retry loops. It is not configurable via env — to change it, edit the source and rebuild.

### Retry architecture summary

```
SSH connect     → exponential backoff: 2^n seconds, capped at 30s, 5-8 attempts
File push       → fixed interval: 5s (SFTP small files), 10s (SSH pipe large files)
Peer ID poll    → boot wait (configurable) + fixed interval retries
Akash bids      → fixed ~12s interval, OLINE_MAX_BID_WAIT attempts
RPC health      → single-shot 5s timeout (callers loop manually)
Phase B/C/E     → graceful skip on failure (logs warning, continues pipeline)
```

---

## 5. Troubleshooting Decision Tree

### "Deployment created but no bids received"
1. Check if the account has sufficient uAKT: the deployer needs ~5 AKT per deployment
2. Try `OLINE_AUTO_SELECT=1` to auto-pick cheapest provider
3. Check provider availability: `oline providers` (manage trusted provider list)
4. Increase `OLINE_MAX_BID_WAIT` if bids are slow

### "SSH connect failed after retries"
1. Verify the deployment is actually running: `oline manage sync`
2. Check the provider's SSH port is exposed in the SDL
3. Try `oline manage logs <dseq>` to see container logs
4. The SSH key is at `$SECRETS_PATH/<dseq>` — verify it exists

### "Peer ID not found after polling"
1. The node might still be syncing — increase `OLINE_RPC_INITIAL_WAIT`
2. Check RPC health: `oline test-grpc <domain>` or `curl <rpc_url>/status`
3. The pipeline continues with an empty peer string — you can inject peers later:
   ```bash
   oline refresh run "<label>"  # re-pushes env vars including peer config
   ```

### "Snapshot node stuck on catching_up=true"
1. This is the longest wait (~60-90 min for full chain sync)
2. Check progress: `curl <snapshot_rpc>/status | jq .result.sync_info`
3. If statesync is failing, you can restart with snapshot mode:
   ```bash
   # Set OLINE_SYNC_METHOD=snapshot in .env, then:
   oline manage restart "Phase A - Snapshot"
   ```

### "DNS update failed"
1. Verify `OLINE_CF_API_TOKEN` and `OLINE_CF_ZONE_ID` are set
2. oline logs "configure manually" and continues — DNS is non-fatal
3. Update manually: `oline dns`

### "Phase B/C/E deployment failed"
1. These are graceful failures — the pipeline continues
2. Check the summary output for which phases failed and why
3. You can deploy individual phases manually later using `oline sdl` + the Akash deploy flow

---

## 6. Testing Before Production

### Dry run — render SDLs without deploying
```bash
oline sdl --output ./rendered/
# Inspect rendered SDLs:
cat ./rendered/a.yml
cat ./rendered/b.yml
```

### Load a config file for reproducible renders
```bash
oline init -o deploy-config.json
# Edit deploy-config.json as needed, then:
oline sdl --load-config deploy-config.json --output ./rendered/
```

### Run the test suite
```bash
# Unit tests (no infrastructure needed)
just test unit

# SDL template validation
just test testnet render

# Full E2E (requires Docker + Akash devnet)
just test full
```

---

## 7. Quick Reference — Command Cheatsheet

```bash
# ─── Setup ───────────────────────────────────────────────────────────────
oline encrypt                          # encrypt mnemonic to .env
oline init --template terp-mainnet     # generate deploy-config.json
oline endpoints save                   # probe + save fastest Akash endpoints

# ─── Deploy ──────────────────────────────────────────────────────────────
oline deploy                           # parallel (default)
oline deploy --sequential              # one phase at a time
oline testnet-deploy --chain-id test-1 # fresh testnet

# ─── Monitor ─────────────────────────────────────────────────────────────
oline refresh status                   # RPC health of all nodes
oline manage logs <dseq>               # stream container logs
oline manage tui --session <id>        # reconnect TUI viewer
oline manage status --session <id>     # on-chain deployment status
oline manage sync                      # reconcile local store with chain

# ─── Operate ─────────────────────────────────────────────────────────────
oline refresh run "<label>"            # push env vars + restart
oline manage restart "<label>"         # kill + re-bootstrap a node
oline dns                              # manual DNS upsert
oline manage prune-keys                # clean up old SSH keys
oline manage drain --execute           # return child funds to master

# ─── Test/Verify ─────────────────────────────────────────────────────────
oline test-grpc <domain>               # gRPC-Web health check
oline test-s3                          # S3/MinIO connectivity
oline endpoints check                  # RPC/gRPC latency table
oline sdl --output ./check/            # dry-run SDL render
```

---

## 8. File Reference

| Path | Purpose |
|------|---------|
| `.env` | Encrypted mnemonic + all config vars |
| `deploy-config.json` | Portable non-secret config snapshot |
| `~/.oline/sessions/` | Session state files (DSEQs, accounts, deployments) |
| `$SECRETS_PATH/nodes.enc` | Encrypted node records (AES-256-GCM) |
| `$SECRETS_PATH/<dseq>` | SSH private keys per deployment |
| `~/.config/oline/trusted-providers.json` | Trusted Akash providers |
| `templates/sdls/oline/` | SDL templates: a.yml, b.yml, c.yml, e.yml, f.yml, testnet-*.yml |
| `plays/audible/` | Bootstrap entrypoint scripts (pushed to nodes via SFTP) |
| `plays/flea-flicker/nginx/` | Nginx TLS config scripts |
| `recipes/sdl-vars.toml` | Full SDL variable schema with source/default metadata |
| `recipes/containers.toml` | Container image versions and port standards |
| `recipes/episodes/full-deploy.md` | LLM-consumable episode reference for full deploy |
| `recipes/episodes/refresh.md` | LLM-consumable episode reference for day-2 ops |
