# E2E & Integration Tests

All end-to-end and integration tests for o-line. Tests are organized by infrastructure requirement — from zero-dependency shell tests to full Akash devnet deployments.

## Quick Reference

| Recipe | What it tests | Infra needed | Time |
|--------|--------------|--------------|------|
| `just test-unit` | Unit tests only | None | <30s |
| `just test-nginx` | Nginx template rendering | None | <10s |
| `just e2e-bootstrap` | pfSense bootstrap script | Docker | ~1min |
| `just e2e-firewall` | `oline firewall bootstrap` CLI | Docker | ~1min |
| `just test-firewall-integration` | Firewall SSH key ops (Rust) | Docker | ~1min |
| `just sentry-ssh` | Parallel SSH/SFTP delivery | Docker (6 containers) | ~5min |
| `just e2e` | Single-node TLS workflow | Docker + OMNIBUS_IMAGE | ~2min |
| `just e2e-multi` | Phase A multi-node | Docker + OMNIBUS_IMAGE | ~15min |
| `just e2e-network` | Full local network | Docker + local-terp + OMNIBUS_IMAGE | ~20min |
| `just test-akash` | All Akash devnet tests | Akash devnet | ~10min |
| `just test akash-shell` | Full parallel deploy (ict-rs) | Docker | ~5min |

---

## No Infrastructure Required

### Nginx Template Test (`test-tls-nginx.sh`)

Validates nginx config rendering in `tls-setup.sh` without Docker or network access.

```bash
just test-nginx
# or: bash tests/test-tls-nginx.sh
```

**What it checks:**
- Main template uses glob include (no fragile sed)
- Per-service templates (rpc, api, grpc) render with correct values
- No `ssl` directive leaks into listen lines
- `nginx -t` passes on assembled config

---

## Docker Only (No Chain Node)

### pfSense Bootstrap E2E (`pfsense_bootstrap.sh`)

Tests `plays/audible/pfsense-bootstrap.sh` against a Docker mock pfSense with dual-network topology (WAN + LAN).

```bash
just e2e-bootstrap
```

**Infrastructure:** `docker/pfsense-e2e/docker-compose.yml` — three containers:
- `pfsense-mock` (10.99.1.2 LAN, 10.99.2.168 WAN) — mock pfSsh.php, easyrule, ifconfig
- `internal-server` (10.99.1.10 LAN) — target for NAT rules
- `wan-client` (10.99.2.161 WAN) — simulates external client

**Phases tested (15 assertions):**
1. SSH access verification + config read (WAN/LAN IPs)
2. `blockpriv` removal on WAN interface
3. `sshdkeyonly` enforcement
4. `easyrule` WAN SSH rule for client IP
5. NAT port forward (WAN:2210 -> 10.99.1.10:22) with `oline:` prefix
6. `--reset` removes all `oline:` prefixed rules, keeps manual rules
7. `--resubnet 10.99.3.1` updates LAN IP and DHCP range

**Mock details:** The mock `pfSsh.php` is a bash script using `jq` to read/write a JSON config at `/conf/config.json`. It interprets the PHP-like commands that `pfsense-bootstrap.sh` pipes over SSH — assignments, unset, foreach, isset/strpos filtering, array append.

### pfSense SSH Setup E2E (`pfsense_ssh_setup.sh`)

Tests the `oline firewall bootstrap` Rust CLI command — SSH key generation, installation, verification, and encrypted store persistence.

```bash
just e2e-firewall
# or: PFSENSE_E2E_MODE=live PFSENSE_LIVE_HOST=192.168.1.1 PFSENSE_LIVE_PASSWORD=secret tests/e2e/tests/pfsense_ssh_setup.sh
```

**Modes:**
- `local` (default) — Docker mock pfSense on port 2222
- `live` — Real pfSense box (requires `PFSENSE_LIVE_HOST` + `PFSENSE_LIVE_PASSWORD`)

**Phases:**
1. Setup — start Docker or connect to live device
2. Bootstrap — run `oline firewall bootstrap --label e2e-test`
3. Verify SSH — key file exists, key-based auth works
4. Verify store — encrypted `firewalls.enc` persists
5. Cleanup

### Firewall Integration Tests (`firewall_bootstrap.rs`)

Rust integration tests for SSH key operations against the Docker mock.

```bash
just test-firewall-integration
```

**Tests:**
- `test_bootstrap_installs_key_and_verifies` — full key lifecycle
- `test_bootstrap_idempotent` — `sort -u` dedup on double install
- `test_bootstrap_with_existing_pubkey` — install from existing key file

### Sentry SSH Workflow (`oline_ssh_workflow_test.rs`)

Tests parallel SSH/SFTP file delivery across 6 Alpine+SSH containers simulating the full sentry node topology (snapshot, seed, left/right tackle, left/right forward).

```bash
just sentry-ssh
```

**Ports:** snapshot:2250, seed:2251, lt:2252, rt:2253, lf:2254, rf:2255

**What it checks:**
- Push scripts to all 6 nodes
- Push pre-start files to snapshot
- Signal start with refresh vars
- Peer injection across nodes
- APPEND mode behavior

---

## Docker + Cosmos Image

These tests require a cosmos-omnibus Docker image. Set `OMNIBUS_IMAGE` or `E2E_OMNIBUS_IMAGE` (for arm64-compatible local builds on Apple Silicon).

### Single-Node TLS Workflow (`e2e_workflow.rs`)

Tests the pre-start file delivery -> tls-setup.sh -> cosmos node start workflow in a single container.

```bash
just e2e
# or: E2E_OMNIBUS_IMAGE=cosmos-omnibus-terpnetwork:local cargo test -p o-line-sdl --test e2e_workflow -- --nocapture --test-threads=1
```

**What it checks:**
- TLS cert upload via SFTP
- Script delivery and execution
- Node startup verification via log markers
- `/tmp/oline-env.sh` service variables

### Multi-Node Phase A (`local_phase_a.rs`)

Phase A deployment simulation with snapshot + seed containers. Tests the full Phase A step sequence without a real chain.

```bash
just e2e-multi
# or: OMNIBUS_IMAGE=... cargo test --test local_phase_a -- --nocapture --test-threads=1
```

**Ports:** snapshot SSH:2232/RPC:9626, seed SSH:2233/RPC:9727

**Steps:**
1. Start snapshot + seed containers
2. Push pre-start files to snapshot, signal start
3. Wait for snapshot peer ID via RPC `/status`
4. Inject snapshot peer into seed, signal start
5. Validate both peer IDs

### Full Local Network (`local_network_e2e.rs`)

Full multi-node test using local-terp as the base chain. Proves containers can sync blocks from a running chain.

```bash
just start-localterp
just e2e-network
```

**Prerequisites:** local-terp running (`just start-localterp`)

**What it checks:**
- Genesis extraction from running chain
- Two cosmos-omnibus containers sync from local-terp
- SSH delivery + peer reconnection after env update
- Block height >= 1 on both nodes after restart

---

## Akash Devnet

These tests require a local Akash dev cluster. One-time setup:

```bash
just akash-setup    # clone + build Akash, init Kind cluster + genesis
```

Then for each test session:

```bash
just akash-wait     # start cluster, print connection JSON
```

### Parallel Deploy (`akash_parallel.rs`)

Full end-to-end parallel deployment workflow. The primary integration test for the step machine.

```bash
just test akash-shell
```

**What it tests:**
- `FundChildAccounts` — HD child account derivation + multi-send funding
- `DeployAllUnits` — Phase A + B + C deployment broadcast
- `SelectAllProviders` — automatic cheapest bid selection
- `SendManifest` — manifest upload to test-provider
- On-chain order/bid/lease lifecycle via WebSocket events

**Event-driven:** Uses `WsEventStream` subscribed before `oline` spawns. Events are buffered and asserted — no fixed sleeps.

### Concurrent Deploy (`concurrent_child_deploy.rs`)

Proves HD key isolation prevents sequence mismatches when N child accounts broadcast `MsgCreateDeployment` simultaneously.

```bash
just test-concurrent-deploy
```

<!-- ### HD Funding (`hd_funding.rs`)

Tests HD child account derivation and funding flow — derive N children from master mnemonic, fund each via `bank_send`, verify balances.

```bash
just test-hd-funding
``` -->

### Query API (`akash_query_api.rs`)

Verifies every Akash query API endpoint (REST + gRPC) against the local devnet — bank balances, certificates, providers, bids, leases, escrow accounts.

```bash
just test-akash-query
```

### Shell Parallel Deploy (REMOVED)

The shell script `e2e-akash-parallel.sh` has been retired. Its coverage (on-chain
deployment list verification) is now included in `akash_parallel.rs` via REST queries.
Use `just test akash-shell` instead.

---

## Test Infrastructure

### Docker Mock pfSense (`docker/pfsense-e2e/`)

Three-container Docker Compose setup simulating a pfSense firewall with WAN/LAN split:

```
┌─────────────────────────────────────────────────┐
│ WAN Network (10.99.2.0/24)                      │
│   wan-client (10.99.2.161)                      │
│   pfsense-mock WAN (10.99.2.168)                │
├─────────────────────────────────────────────────┤
│ LAN Network (10.99.1.0/24)                      │
│   pfsense-mock LAN (10.99.1.2) ← SSH port 2222 │
│   internal-server (10.99.1.10)                  │
└─────────────────────────────────────────────────┘
```

Mock components:
- **pfSsh.php** — bash/jq interpreter for PHP-like pfSense config commands
- **easyrule** — logs firewall rule additions
- **ifconfig** — returns mock WAN IP
- **rc.reload_interfaces** — updates container IP on resubnet
- **config.json** — JSON config file (initial: WAN=10.99.2.168, LAN=10.99.1.2)

### Local-Terp (`tests/localterp.sh`)

Single-validator Cosmos testnet in Docker. Chain: `120u-1`, denoms: `uterp`/`uthiol`.

```bash
just start-localterp    # start + wait
just stop-localterp     # cleanup
```

Ports: RPC 26657, P2P 26656, REST 1317, gRPC 9090, faucet 5000

### Akash Dev Cluster (`data/akash-devnet.sh`)

Local Akash blockchain + test-provider (Rust binary replacing Kind-based provider-services).

```bash
just akash-setup    # one-time: Kind cluster + genesis
just akash-wait     # start + print JSON config
just akash-stop     # stop
just akash-clean    # remove all artifacts
```

### Test Fixtures (`tests/fixtures/`)

- `sdls/` — Minimal SDLs for CI (nginx:alpine, no signedBy constraints)
- `scenarios/` — JSON fixtures capturing expected vs observed Akash events (update with `UPDATE_FIXTURES=1`)
