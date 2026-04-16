# O-Line Bootstrap Courier

Ephemeral, zero-dependency Rust binary that fetches all public resources needed to bootstrap Cosmos nodes, serves them over HTTP to internal Akash nodes, then shuts down. **The o-line nodes never touch the public internet.**

## Why

Standard Cosmos node deployments require each node to independently fetch from public sources: GitHub (chain.json, addrbook, genesis), snapshot servers (itrocket, quicksync), and CosmWasm release CDNs. This creates problems:

| Problem | Courier Solution |
|---------|-----------------|
| Each node leaks metadata to public servers | Single ephemeral egress point |
| Multiple redundant downloads of same data | Fetch once, distribute internally |
| Node bootstrap depends on public server availability | Courier pre-validates all resources |
| Validator IP addresses visible to public CDNs | Only courier IP is exposed, then discarded |

## Architecture

### Unified Single-Deployment Model

All services deploy in **one Akash SDL** — one lease, one bid, one provider. The courier and all nodes start simultaneously. Synchronization happens via entrypoint wait loops:

```
┌─────────────────── Single Akash Deployment ───────────────────┐
│                                                               │
│  ┌─────────────┐                                              │
│  │   Courier   │◄── Public Internet (only egress point)       │
│  │ fetch once  │                                              │
│  │ serve many  │                                              │
│  └──────┬──────┘                                              │
│         │ internal Akash service network                      │
│    ┌────┴─────┬────────────┬───────────┐                      │
│    ▼          ▼            ▼           ▼                      │
│  Snapshot    Seed       MinIO/IPFS   (idle, waiting)          │
│  (waits for courier,    (waits for   Left Tackle              │
│   then bootstraps)       courier)    Right Tackle             │
│    │                                   │                      │
│    │ RPC ready ─────────────────────►  │ (discovers peer ID   │
│    │                                   │  via internal RPC)   │
│    │                                   │                      │
│    │                                   ▼                      │
│    │                              Left Forward                │
│    │                              Right Forward               │
│    │                              (waits for tackles,         │
│    │                               discovers all peers)       │
│                                                               │
│  Courier shuts down after all peers confirm ✓                 │
└───────────────────────────────────────────────────────────────┘
```

### Boot Sequence (all containers start at once)

1. **Courier** fetches all public resources (chain.json, addrbook, snapshot, wasmvm, entrypoint)
2. **Snapshot + Seed + MinIO** poll `courier:8080/ready`, then pull data from courier internally
3. **Left/Right Tackles** poll `courier:8080/ready` AND `oline-snapshot:26657/status`, discover peer IDs via internal RPC, then statesync
4. **Left/Right Forwards** poll tackles' RPC, discover all peer IDs internally, then sync
5. **Courier** receives `/confirm` from all peers, begins graceful shutdown

Peer discovery is fully internal — no CLI-side extraction over public endpoints needed.

## Image Size

The courier is a statically-linked Rust binary in a `scratch` Docker image.
Expected image size: **~8-12MB** (binary + CA certs). No shell, no package manager, no OS.

## Configuration

All configuration via environment variables:

### Resource URLs (what to fetch)

| Variable | Description | Required |
|----------|-------------|----------|
| `CHAIN_JSON_URL` | Chain registry JSON | Yes |
| `ADDRBOOK_URL` | Address book JSON | No |
| `GENESIS_URL` | Genesis JSON | No |
| `SNAPSHOT_URL` | Snapshot tarball | Yes |
| `WASMVM_URL` | WasmVM shared library | No |
| `ENTRYPOINT_URL` | Node entrypoint script | No |

### Numbered Resources

For resources beyond the well-known shortcuts, use pipe-delimited env vars:

```
COURIER_RESOURCE_0=cosmovisor-terpd|https://github.com/.../terpd|true|<sha256>
COURIER_RESOURCE_1=custom-config.toml|https://...|false|
```

Format: `name|url|required|sha256` (sha256 is optional).

### JSON Manifest

For complex manifests, pass JSON directly:

```
COURIER_MANIFEST='{"resources":[{"name":"chain.json","url":"https://...","required":true,"sha256":""}]}'
```

Or from a file:

```
COURIER_MANIFEST_FILE=/path/to/manifest.json
```

### Courier Behavior

| Variable | Default | Description |
|----------|---------|-------------|
| `COURIER_PORT` | `8080` | HTTP server port |
| `COURIER_DATA_DIR` | `/srv/bootstrap` | Download destination |
| `COURIER_EXPECTED_PEERS` | `0` | Peers that must confirm before shutdown (0 = timeout only) |
| `COURIER_SHUTDOWN_TIMEOUT` | `3600` | Max lifetime in seconds |

## HTTP API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ready` | GET | `200` if all required resources fetched, `503` otherwise |
| `/manifest` | GET | JSON array of fetch results with SHA-256 digests |
| `/files/<name>` | GET | Stream a fetched file (streaming, not buffered) |
| `/confirm/<peer>` | POST | Peer confirms receipt of all data |
| `/status` | GET | JSON status: uptime, bytes served, confirmed peers |

## Integration with O-Line

### Unified SDL (recommended)

The courier deploys alongside all o-line nodes in a single Akash lease:

```yaml
# unified.oline.yml — one deployment, all services
services:
  oline-courier:
    image: ghcr.io/permissionlessweb/oline-courier:latest
    expose:
      - port: 8080
        to:
          - global: false    # ← internal only, nodes fetch from here

  oline-snapshot:
    image: ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic
    env:
      # All URLs point to courier, not the public internet
      - CHAIN_JSON=http://oline-courier:8080/files/chain.json
      - SNAPSHOT_URL=http://oline-courier:8080/files/snapshot.tar.lz4
    command: ["sh"]
    args:
      - -c
      - |
        # Wait for courier, then bootstrap
        until wget -qO- http://oline-courier:8080/ready | grep -q ready; do sleep 10; done
        wget -qO /tmp/wrapper.sh http://oline-courier:8080/files/entrypoint.sh
        wget -qO- http://oline-courier:8080/confirm/oline-snapshot || true
        bash /tmp/wrapper.sh

  oline-left-tackle:
    # ...waits for courier AND snapshot node RPC, discovers peers internally
  oline-left-forward:
    # ...waits for tackles, discovers ALL peer IDs via internal RPC
```

See `sdls/unified.oline.yml` for the complete template.

### Node Entrypoint Wait Pattern

Every node's `command` block follows the same pattern:

1. **Poll courier** `GET /ready` until `200`
2. **Fetch entrypoint** from `courier:8080/files/entrypoint.sh`
3. **Confirm receipt** via `POST /confirm/<node-id>`
4. **For tackles**: also poll `oline-snapshot:26657/status` to discover peer IDs
5. **For forwards**: also poll tackles' RPC to discover their peer IDs
6. **Run entrypoint** with all env vars set to internal courier URLs

Peer discovery happens entirely over the internal Akash network — the CLI never needs to extract peer IDs over public endpoints.

### Peer Confirmation Flow

1. All containers start simultaneously (one Akash lease)
2. Courier fetches all public resources, starts HTTP server
3. Nodes poll `/ready`, then pull data from courier
4. Each node calls `POST /confirm/<node-id>` after fetching entrypoint
5. Once `COURIER_EXPECTED_PEERS` confirmations received, courier begins graceful shutdown
6. Courier process exits but container stays (Akash keeps the lease alive for other services)

### Standalone SDL (alternative)

For testing or when you only need the courier without the full node stack:

```yaml
# 0.prefetch-courier.yml — courier-only deployment
```

### Local Prefetch Mode

For fully offline deployments, run the courier locally to pre-download everything:

```bash
# Using Docker
docker run --rm \
  -e CHAIN_JSON_URL=https://... \
  -e SNAPSHOT_URL=https://... \
  -v ./bootstrap-data:/srv/bootstrap \
  ghcr.io/permissionlessweb/oline-courier:latest

# Or build and run natively
cargo build --release
CHAIN_JSON_URL=https://... \
SNAPSHOT_URL=https://... \
COURIER_DATA_DIR=./bootstrap-data \
./target/release/courier
```

The downloaded files can then be served from MinIO, mounted into containers, or bundled into a custom image.

## Build

```bash
# Debug
cargo build

# Release (optimized, stripped)
cargo build --release

# Docker (multi-stage, scratch-based)
docker build -t oline-courier .
```

## Security Properties

- **Zero runtime dependencies** — no shell, no package manager, no OS in the container
- **Read-only after fetch** — once resources are downloaded, the data directory is never written to again
- **Path traversal protection** — file serving canonicalizes paths and validates against the data directory
- **Ephemeral by design** — courier runs for minutes, not hours; minimizes attack surface window
- **SHA-256 verification** — optional per-resource integrity checking
- **No secrets** — courier never handles mnemonics, private keys, or credentials
