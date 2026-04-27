# o-line CLI Reference

## Usage

```
validator deployment orchestrator

Usage: oline [OPTIONS] <COMMAND>

Commands:
  encrypt         Encrypt mnemonic and store in .env
  endpoints       Probe Akash RPC/gRPC endpoints and save the fastest to .env
  deploy          Full automated deployment (phases A → B → C → E)
  sdl             Render SDL templates without broadcasting
  init            Collect deployment config and write deploy-config.json
  manage          View and manage active deployments
  test-s3         Test S3/MinIO bucket connectivity
  test-grpc       Test gRPC-Web endpoint health
  dns             Upsert Cloudflare DNS records
  bootstrap       Bootstrap a private validator node with peers + snapshot
  sites           Deploy and manage IPFS static websites via MinIO-IPFS on Akash
  refresh         SSH-based node management: push env updates, run scripts, check health
  node            Deploy and manage a dedicated Akash full node
  firewall        Manage pfSense firewall SSH keys and connectivity
  relayer         Manage a Cosmos IBC relayer (binary hot-swap, config reload, key install)
  vpn             Provision and manage WireGuard VPN on pfSense
  providers       Manage trusted Akash providers (saved to ~/.config/oline/trusted-providers.json)
  registry        Embedded OCI container registry (serve, import, list)
  testnet-deploy  Bootstrap a fresh testnet on Akash with validator, faucet, and full sentry array
  console         Interact with Akash Console API (deployments, providers, leases, etc.)
  help            Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
  -h, --help               Print help
  -V, --version            Print version
```

## Subcommands

### Available Commands

```
Commands:
  encrypt         Encrypt mnemonic and store in .env
  endpoints       Probe Akash RPC/gRPC endpoints and save the fastest to .env
  deploy          Full automated deployment (phases A → B → C → E)
  sdl             Render SDL templates without broadcasting
  init            Collect deployment config and write deploy-config.json
  manage          View and manage active deployments
  test-s3         Test S3/MinIO bucket connectivity
  test-grpc       Test gRPC-Web endpoint health
  dns             Upsert Cloudflare DNS records
  bootstrap       Bootstrap a private validator node with peers + snapshot
  sites           Deploy and manage IPFS static websites via MinIO-IPFS on Akash
  refresh         SSH-based node management: push env updates, run scripts, check health
  node            Deploy and manage a dedicated Akash full node
  firewall        Manage pfSense firewall SSH keys and connectivity
  relayer         Manage a Cosmos IBC relayer (binary hot-swap, config reload, key install)
  vpn             Provision and manage WireGuard VPN on pfSense
  providers       Manage trusted Akash providers (saved to ~/.config/oline/trusted-providers.json)
  registry        Embedded OCI container registry (serve, import, list)
  testnet-deploy  Bootstrap a fresh testnet on Akash with validator, faucet, and full sentry array
  console         Interact with Akash Console API (deployments, providers, leases, etc.)
  help            Print this message or the help of the given subcommand(s)
```

### oline encrypt

```
Encrypt mnemonic and store in .env

Usage: oline encrypt [OPTIONS]

Options:
      --examples           Print usage examples and exit
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
  -h, --help               Print help
```

#### Examples

# oline encrypt

Encrypt your mnemonic and store it in `.env` for use by other oline commands.

## Usage

```bash
# Interactive — prompts for mnemonic and password
oline encrypt
```

The mnemonic is encrypted with AES-256-GCM using a password-derived key
(Argon2id). The ciphertext is stored as `OLINE_ENCRYPTED_MNEMONIC` in `.env`.

## How it works

1. You enter your mnemonic (hidden input)
2. You set a password (used to derive the encryption key)
3. The encrypted mnemonic is written to `.env`
4. Subsequent commands (`deploy`, `manage`, etc.) decrypt it at runtime

## Environment Variables

| Variable | Description |
|---|---|
| `OLINE_ENCRYPTED_MNEMONIC` | AES-256-GCM encrypted mnemonic (written by this command) |

---

### oline endpoints

```
Probe Akash RPC/gRPC endpoints and save the fastest to .env

Usage: oline endpoints [OPTIONS] [COMMAND]

Commands:
  check  Probe all endpoints and print the latency table (no .env changes)
  save   Probe and write the fastest healthy endpoints to .env
  help   Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline endpoints

Probe all public Akash RPC and gRPC endpoints and save the fastest healthy
ones to `.env`.

Endpoints are discovered from the Cosmos Chain Registry (akash/chain.json)
with a hardcoded fallback list when the network is unavailable.

## Usage

    oline endpoints              # probe all endpoints, prompt to save fastest
    oline endpoints check        # probe only, print table, no save prompt
    oline endpoints save         # probe + auto-save fastest to .env
    oline endpoints save --rpc https://... --grpc host:port
                                 # save explicit endpoints without probing

## Output

    RPC Endpoints:
      #  ms     URL
      1  142    https://akash-rpc.polkachu.com:18252   (Polkachu)
      2  287    https://rpc-akash.ecostake.com:443     (Ecostake)
      3  DEAD   https://rpc.akashnet.net:443           (Akash Network)

    gRPC Endpoints:
      #  ms     Address
      1   98    akash-grpc.lavenderfive.com:443        (Lavender.Five)
      2  312    grpc.akashnet.net:9090                 (Akash Network)

## Environment Variables

    OLINE_RPC_ENDPOINT    Saved by `oline endpoints save`
    OLINE_GRPC_ENDPOINT   Saved by `oline endpoints save`

## Examples

    # Quick check — see which endpoints are alive
    oline endpoints check

    # Probe and immediately save fastest to .env
    oline endpoints save

    # Pin a specific endpoint pair
    oline endpoints save --rpc https://akash-rpc.polkachu.com:18252 \
                         --grpc akash-grpc.polkachu.com:18262

---

### oline deploy

```
Full automated deployment (phases A → B → C → E)

Usage: oline deploy [OPTIONS]

Options:
  -p, --profile <PROFILE>
          Config profile to use (mainnet, testnet, local)
          
          [env: OLINE_PROFILE=]
          [default: mainnet]

      --raw
          Enter mnemonic interactively instead of reading from .env

      --parallel
          Use parallel deployment: deploy all phases before snapshot sync wait. All phases (A, B, C) are deployed up-front; B and C use SNAPSHOT_MODE=sftp and receive the snapshot archive after phase A syncs, saving ~60 min

      --sequential
          Use sequential deployment (legacy, one phase at a time)

      --sdl <PATH>
          Deploy a raw SDL file directly (bypasses phase templates). The file is read, variables from .env are substituted, and it is deployed as a single deployment to any available provider. Without --select, creates deployment and prints bids then exits. With --select, completes the deployment with the chosen provider

      --select <SELECTION>...
          Select provider(s) for an existing deployment (step 2).
          
          For --sdl: --select <DSEQ> <PROVIDER_ADDRESS> For --parallel: --select a=<PROVIDER> b=<PROVIDER> c=<PROVIDER> [e=<PROVIDER>]
          
          Phase keys: a (snapshot+seed), b (tackles), c (forwards), e (relayer). Only phases that printed NEEDS_SELECTION=true require a selection. Trusted/auto-selected phases are kept automatically.

      --examples
          Print usage examples and exit

  -h, --help
          Print help (see a summary with '-h')
```

#### Examples

# oline deploy

Full automated deployment of the Terp Network validator infrastructure
across phases A (Special Teams), B (Tackles), C (Forwards), and E (Relayer).

## Usage

```bash
# Parallel deployment (default) — deploys all phases up-front
oline deploy

# Sequential deployment — one phase at a time
oline deploy --sequential

# Enter mnemonic interactively (instead of .env)
oline deploy --raw
```

## Non-interactive (CI / scripting)

```bash
OLINE_NON_INTERACTIVE=1 \
OLINE_MNEMONIC="word1 word2 ... word24" \
OLINE_PASSWORD=mypassword \
OLINE_AUTO_SELECT=1 \
  oline deploy
```

## Justfile recipes

```bash
# Build + deploy (parallel)
just deploy

# Dry-run — render SDLs without broadcasting
just dry-run
```

## Key environment variables

| Variable | Description |
|---|---|
| `OLINE_NON_INTERACTIVE` | Skip all prompts |
| `OLINE_MNEMONIC` | Mnemonic (bypasses rpassword prompt) |
| `OLINE_PASSWORD` | Config encryption password |
| `OLINE_AUTO_SELECT` | Auto-select cheapest provider |
| `SDL_DIR` | Custom SDL template directory |
| `OLINE_TEST_STOP_AFTER_DEPLOY` | Stop after deploy step (testing) |

---

### oline sdl

```
Render SDL templates without broadcasting

Usage: oline sdl [OPTIONS]

Options:
  -o, --output <DIR>        Write rendered SDL files and deploy-config.json to this directory
  -p, --profile <PROFILE>   Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --load-config <PATH>  Load a deploy-config.json instead of prompting for values
      --examples            Print usage examples and exit
  -h, --help                Print help
```

#### Examples

# oline sdl / oline init

Generate SDL templates and deployment configs for Akash.

## oline init — Create deployment config

```bash
# Interactive — prompts for all config values
oline init

# Use a named template (non-interactive)
oline init --template terp-mainnet

# List available templates
oline init --list-templates

# Custom output path
oline init -o my-config.json
```

## oline sdl — Render SDL templates

```bash
# Interactive — choose phase, enter config values
oline sdl

# Load config from a file (from `oline init`)
oline sdl --load-config deploy-config.json

# Write rendered SDL files to a directory
oline sdl --output ./rendered/

# Load config + write to directory (non-interactive rendering)
oline sdl --load-config deploy-config.json --output ./rendered/
```

## Workflow

```bash
# 1. Generate config
oline init -o deploy-config.json

# 2. Review and edit deploy-config.json

# 3. Render SDL from config
oline sdl --load-config deploy-config.json --output ./sdl-output/

# 4. Inspect rendered SDL files
cat ./sdl-output/a.yml
```

## Phases

| Phase | Description |
|---|---|
| a | Phase A: Kickoff Special Teams (snapshot + seed) |
| b | Phase B: Left & Right Tackles |
| c | Phase C: Left & Right Forwards |
| e | Phase E: IBC Relayer |
| f | Phase F: Argus Indexer |
| all | All phases |

---

### oline init

```
Collect deployment config and write deploy-config.json

Usage: oline init [OPTIONS]

Options:
  -o, --output <OUTPUT>    Path to write deploy-config.json [default: deploy-config.json]
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
  -t, --template <NAME>    Use a named template for non-interactive config generation
      --list-templates     Print available template names and exit
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline sdl / oline init

Generate SDL templates and deployment configs for Akash.

## oline init — Create deployment config

```bash
# Interactive — prompts for all config values
oline init

# Use a named template (non-interactive)
oline init --template terp-mainnet

# List available templates
oline init --list-templates

# Custom output path
oline init -o my-config.json
```

## oline sdl — Render SDL templates

```bash
# Interactive — choose phase, enter config values
oline sdl

# Load config from a file (from `oline init`)
oline sdl --load-config deploy-config.json

# Write rendered SDL files to a directory
oline sdl --output ./rendered/

# Load config + write to directory (non-interactive rendering)
oline sdl --load-config deploy-config.json --output ./rendered/
```

## Workflow

```bash
# 1. Generate config
oline init -o deploy-config.json

# 2. Review and edit deploy-config.json

# 3. Render SDL from config
oline sdl --load-config deploy-config.json --output ./sdl-output/

# 4. Inspect rendered SDL files
cat ./sdl-output/a.yml
```

## Phases

| Phase | Description |
|---|---|
| a | Phase A: Kickoff Special Teams (snapshot + seed) |
| b | Phase B: Left & Right Tackles |
| c | Phase C: Left & Right Forwards |
| e | Phase E: IBC Relayer |
| f | Phase F: Argus Indexer |
| all | All phases |

---

### oline manage

```
View and manage active deployments

Usage: oline manage [OPTIONS] [COMMAND]

Commands:
  sync        Query on-chain active deployments, reconcile local store
  prune-keys  Delete SSH key files for non-active DSEQs
  restart     SSH into node, kill process, re-run full start sequence
  logs        Stream container logs from an Akash provider via WebSocket
  tui         Reconnect to a session's TUI log viewer
  status      Check liveness of deployments in a session
  close       Close one or more active deployments by DSEQ
  drain       Return remaining funds from HD child accounts back to master
  update      Send an updated manifest (SDL) to a running deployment without redeploying
  help        Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline manage

View and manage active deployments.

## Subcommands

```bash
# Interactive list + actions (default)
oline manage

# Query on-chain active deployments, reconcile local store
oline manage sync

# Delete SSH key files for non-active DSEQs
oline manage prune-keys

# SSH into node, kill process, re-run full start sequence
oline manage restart "Phase A - Snapshot"
```

## Examples

```bash
# Sync local records with chain state
oline manage sync

# Clean up stale SSH keys after closing deployments
oline manage prune-keys

# Restart a node to pick up config changes (full re-bootstrap)
oline manage restart "Phase B - Left Tackle"
```

## Debugging Deployments

When a container fails to start or SSH doesn't connect, **always check provider
logs first** — never retry SSH blindly:

```bash
# Stream the last 30 lines of a specific service's container logs
oline manage logs <DSEQ> --service <SERVICE_NAME> --tail 30

# Examples:
oline manage logs 26523081 --service testnet-sentry-a --tail 30
oline manage logs 26523081 --service testnet-lb --tail 50
```

This streams actual container stdout/stderr from the Akash provider via
WebSocket. Common errors this catches immediately:
- Missing binaries (`sh: curl: not found`) — wrong or stale Docker image
- Config errors — bad env vars, missing genesis URL
- Crash loops — OOM, permission errors, port conflicts

**Standard procedure when bootstrap/SSH fails:**
1. `oline manage logs <DSEQ> --service <svc> --tail 30` — read the error
2. Diagnose root cause (image issue? config? provider problem?)
3. Fix and redeploy — don't waste time retrying a broken container

---

### oline test-s3

```
Test S3/MinIO bucket connectivity

Usage: oline test-s3 [OPTIONS]

Options:
      --examples           Print usage examples and exit
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
  -h, --help               Print help
```

#### Examples

# oline test-s3

Test S3/MinIO bucket connectivity. Runs four checks: list objects, put test
object, get test object, delete test object.

## Usage

```bash
# Interactive — prompts for S3 credentials
oline test-s3

# Non-interactive (CI)
S3_KEY=mykey S3_SECRET=mysecret \
S3_HOST=https://provider.host:30000 \
SNAPSHOT_PATH=snapshots/terpnetwork \
  oline test-s3
```

## Output

```
[1/4] List objects in bucket... OK (HTTP 200, 3 objects listed)
[2/4] Put test object... OK (HTTP 200)
[3/4] Get test object... OK (data verified)
[4/4] Delete test object... OK (HTTP 204)
All S3 tests passed. Credentials are fully functional.
```

## Environment Variables

| Variable | Description |
|---|---|
| `S3_KEY` | S3 access key |
| `S3_SECRET` | S3 secret key |
| `S3_HOST` | S3 endpoint URL (e.g. `https://provider.host:30000`) |
| `SNAPSHOT_PATH` | Bucket/prefix path (e.g. `snapshots/terpnetwork`) |

---

### oline test-grpc

```
Test gRPC-Web endpoint health

Usage: oline test-grpc [OPTIONS] [DOMAIN]

Arguments:
  [DOMAIN]  gRPC-Web domain to test (falls back to GRPC_D_SNAP env var)

Options:
      --examples           Print usage examples and exit
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
  -h, --help               Print help
```

#### Examples

# oline test-grpc

Send a gRPC-Web GetNodeInfo request to a domain and verify the endpoint
is healthy.

## Usage

```bash
# Test a specific domain
oline test-grpc grpc.terp.network

# Use GRPC_DOMAIN_SNAPSHOT env var
GRPC_DOMAIN_SNAPSHOT=grpc.terp.network oline test-grpc
```

## Output

```
=== gRPC-Web Test ===
Endpoint: https://grpc.terp.network/cosmos.base.tendermint.v1beta1.Service/GetNodeInfo
HTTP status:  200
Content-Type: application/grpc-web+proto
gRPC status:  0
Node info strings:
  terpnetwork-1
  terp-core
  0.7.0
gRPC-Web endpoint OK
```

---

### oline dns

```
Upsert Cloudflare DNS records

Usage: oline dns [OPTIONS] [COMMAND]

Commands:
  update       Interactive DNS record editor (legacy)
  list         List DNS records (optionally filtered by name)
  set-txt      Upsert a TXT record
  set-cname    Upsert a CNAME record (proxied by default)
  set-a        Upsert an A record
  delete       Delete DNS records by name
  web3-enable  Enable Cloudflare Web3 IPFS gateway for a domain (free, one-time setup)
  web3-list    List Web3 IPFS gateway hostnames
  publish      Full IPFS publish: Web3 gateway + DNSLink + CNAME (one command)
  keys         Manage encrypted credential keys (add, list, remove)
  help         Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline dns

Manually upsert Cloudflare DNS records. Useful when the automatic DNS update
after deploy failed or when a record needs manual correction.

## Usage

```bash
# Interactive — prompts for credentials, domain, record type, and target
oline dns
```

## Workflow

1. Enter Cloudflare API token and zone ID (or decrypt from saved config)
2. Enter domain to update
3. Choose record type:
   - **CNAME** — for HTTP ingress (provider hostname)
   - **A** — for NodePort (provider IPv4)
4. Enter the target value
5. Repeat for additional domains, or `q` to quit

## Environment Variables

| Variable | Description |
|---|---|
| `OLINE_CF_API_TOKEN` | Cloudflare API token |
| `OLINE_CF_ZONE_ID` | Cloudflare zone ID |

---

### oline bootstrap

```
Bootstrap a private validator node with peers + snapshot

Usage: oline bootstrap [OPTIONS]

Options:
  -l, --local                Run commands locally instead of over SSH
  -p, --profile <PROFILE>    Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --host <HOST>          SSH host IP or hostname (env: OLINE_PRIVATE_NODE_HOST) [env: OLINE_PRIVATE_NODE_HOST=]
      --port <PORT>          SSH port (env: OLINE_PRIVATE_NODE_P) [env: OLINE_PRIVATE_NODE_P=] [default: 22]
      --key <KEY>            SSH private key path (env: OLINE_PRIVATE_NODE_KEY) [env: OLINE_PRIVATE_NODE_KEY=]
      --binary <BINARY>      Cosmos daemon binary name (env: OLINE_BINARY) [env: OLINE_BINARY=terpd] [default: terpd]
      --home <HOME>          Node home directory (env: OLINE_PRIVATE_NODE_HOME) [env: OLINE_PRIVATE_NODE_HOME=]
      --peers <PEERS>        Persistent peers id@host:port,... (env: OLINE_PERSISTENT_PEERS) [env: OLINE_PERSISTENT_PEERS=a43c1415bc3a58b0881d2c5c2abe857b45f0a7e7@135.181.60.157:26716,58e01ab84eb931a82a024324520021d2e075ec67@185.248.24.16:29656,fdfcac2813a3c2bf66cff73a9e61fb0f0bda21e1@108.28.11.226:26656]
      --snapshot <SNAPSHOT>  Snapshot URL (env: OLINE_SNAP_BASE_URL) [env: OLINE_SNAP_BASE_URL=]
      --format <FORMAT>      Snapshot format (env: OLINE_SNAP_SAVE_FORMAT) [env: OLINE_SNAP_SAVE_FORMAT=tar.gz] [default: tar.lz4]
  -y, --yes                  Skip confirmation prompt
      --examples             Print usage examples and exit
  -h, --help                 Print help
```

#### Examples

# oline bootstrap

Bootstrap a private (non-Akash) validator node: inject persistent peers,
stop the running daemon, clear the data directory, and install a snapshot.

## Usage

```bash
# Interactive — prompts for host, binary, peers, snapshot
oline bootstrap

# SSH to a remote node
oline bootstrap --host 10.0.0.5 --port 22 --binary terpd

# Run locally (no SSH)
oline bootstrap --local --binary terpd --home /root/.terp

# Skip confirmation prompt
oline bootstrap --host 10.0.0.5 -y
```

## Non-interactive

```bash
OLINE_PRIVATE_NODE_HOST=10.0.0.5 \
OLINE_BINARY=terpd \
OLINE_PRIVATE_NODE_HOME=/root/.terp \
OLINE_PERSISTENT_PEERS="id@host:26656" \
OLINE_SNAPSHOT_BASE_URL=https://snapshots.example.com/ \
  oline bootstrap -y
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `OLINE_PRIVATE_NODE_HOST` | SSH host IP or hostname | (prompted) |
| `OLINE_PRIVATE_NODE_PORT` | SSH port | 22 |
| `OLINE_PRIVATE_NODE_KEY` | SSH private key path | ~/.ssh/id_ed25519 |
| `OLINE_BINARY` | Cosmos daemon binary name | terpd |
| `OLINE_PRIVATE_NODE_HOME` | Node home directory | (prompted) |
| `OLINE_PERSISTENT_PEERS` | Persistent peers (id@host:port,...) | (prompted) |
| `OLINE_SNAPSHOT_BASE_URL` | Snapshot base URL | (prompted) |
| `OLINE_SNAPSHOT_STATE_URL` | Snapshot state metadata URL | (optional) |
| `OLINE_SNAPSHOT_SAVE_FORMAT` | Snapshot format | tar.lz4 |

---

### oline sites

```
Deploy and manage IPFS static websites via MinIO-IPFS on Akash

Usage: oline sites [OPTIONS] <COMMAND>

Commands:
  deploy   Deploy a standalone MinIO-IPFS gateway on Akash
  upload   Upload a local file or directory to the site's S3 bucket
  publish  Set DNSLink TXT record to point a domain at an IPFS CID
  list     List managed IPFS sites
  help     Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline sites — IPFS static website management

Deploy, upload, and publish static websites via a MinIO-IPFS gateway on Akash Network.
DNSLink TXT records are automatically managed through Cloudflare for verifiable IPFS hosting.

## Subcommands

### sites deploy

Deploy a standalone MinIO-IPFS gateway on Akash and configure DNS.

```bash
oline sites deploy
```

Prompts for:
- Site domain (e.g. `mysite.example.com`)
- S3 bucket name for site assets
- Cloudflare zone ID (defaults to OLINE_CF_ZONE_ID)

Creates:
- Akash deployment with persistent MinIO + Kubo IPFS storage
- Cloudflare CNAME: `<domain>` → provider ingress hostname
- Encrypted site record saved to `$SECRETS_PATH/sites.enc`

### sites upload

Upload a local file or directory to the site's S3 bucket.

```bash
oline sites upload <domain> <local-path>
oline sites upload mysite.example.com ./dist/index.html
oline sites upload mysite.example.com ./dist/          # upload directory
```

After upload, files are auto-pinned to IPFS by the gateway. The resulting CID
is printed so you can publish it with `sites publish`.

### sites publish

Set the DNSLink TXT record for a domain, pointing it to an IPFS CID.

```bash
oline sites publish <domain> <cid>
oline sites publish mysite.example.com bafybeig6xv5nwphfmvcnektpnojts33jqcuam7bmye2pb54adnrtccjlsu
```

Sets:
- `_dnslink.<domain>` TXT = `"dnslink=/ipfs/<cid>"`
- `<domain>` CNAME → `cloudflare-ipfs.com`

Your site is then accessible at `https://<domain>` via Cloudflare's IPFS gateway.

### sites list

List all managed IPFS sites and their current CIDs.

```bash
oline sites list
```

## Environment Variables

| Variable | Description |
|---|---|
| `OLINE_CF_API_TOKEN` | Cloudflare API token with DNS edit permission |
| `OLINE_CF_ZONE_ID` | Default Cloudflare zone ID |
| `MINIO_IPFS_IMAGE` | MinIO-IPFS Docker image |
| `OLINE_AUTOPIN_INTERVAL` | IPFS auto-pin interval in seconds (default: 300) |
| `SECRETS_PATH` | Directory for encrypted site store (default: `.`) |
| `SSH_PORT` | SSH port for pre-start file delivery (default: 22) |

## Workflow

```
oline sites deploy                      # 1. Deploy gateway on Akash
oline sites upload mysite.com ./dist/   # 2. Upload HTML/assets to S3
oline sites publish mysite.com <cid>    # 3. Point domain to IPFS CID
```

---

### oline refresh

```
SSH-based node management: push env updates, run scripts, check health

Usage: oline refresh [OPTIONS] <COMMAND>

Commands:
  run     Push updated env vars to a saved node and run a command
  add     Register a node in the encrypted store
  list    List saved nodes
  status  Check RPC health of all saved nodes
  remove  Remove a node from the store by DSEQ
  help    Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline refresh — SSH-based node management

Push updated environment variables to running Akash nodes and re-run scripts
without redeploying. All config stays encrypted on your local machine.

## Subcommands

### refresh run

SSH into a saved node and push updated env vars, then run a shell command.

```bash
oline refresh run <node-label>
oline refresh run "Phase A - Snapshot"
```

The node's env vars are rebuilt from the current encrypted config, written to
`/tmp/oline-env.sh` on the remote node, and then the run-command executes.

Default run-command (restarts the bootstrap script):
```bash
OLINE_PHASE=refresh nohup bash /tmp/wrapper.sh >/tmp/oline-node.log 2>&1 &
```

### refresh add

Register a node in the encrypted node store for future management.

```bash
oline refresh add
```

Prompts for:
- Label (e.g. "Phase A - Snapshot")
- DSEQ
- Phase (A / B / C / E)
- SSH host + port
- RPC URL (for health checks)
- SSH key filename (default: oline-ssh-key)

### refresh list

List all saved nodes.

```bash
oline refresh list
```

### refresh status

Check the RPC health of all saved nodes.

```bash
oline refresh status
```

Queries `/status` on each node's RPC URL and shows moniker + block height.

### refresh remove

Remove a node from the store by DSEQ.

```bash
oline refresh remove <dseq>
```

## Workflow

```bash
# After initial deployment:
oline refresh add            # register the deployed nodes

# Later, when you want to update config:
# 1. Edit your .env or deploy-config.json
# 2. Push updated vars + re-run the entrypoint:
oline refresh run "Phase A - Snapshot"

# Check all nodes are healthy:
oline refresh status
```

## Environment Variables

| Variable | Description |
|---|---|
| `SECRETS_PATH` | Directory for SSH keys and the nodes.enc store (default: `.`) |
| `OLINE_CF_API_TOKEN` | Cloudflare API token (used when refreshing DNS) |

---

### oline node

```
Deploy and manage a dedicated Akash full node

Usage: oline node [OPTIONS] <COMMAND>

Commands:
  deploy  Deploy a dedicated Akash full node and save endpoints to .env
  status  Check RPC health of the deployed Akash node
  close   Close the Akash node deployment and remove from store
  help    Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline node — Deploy a dedicated Akash full node

Deploy, monitor, and manage a private Akash full node on Akash Network.
The node provides dedicated RPC/gRPC/REST endpoints for oline itself.

## Examples

```bash
# Deploy a new Akash full node
oline node deploy

# Check RPC health of the deployed node
oline node status

# Close the deployment and remove from store
oline node close
```

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AKASH_SNAPSHOT_URL` | Akash chain snapshot URL | (prompted) |
| `AKASH_ADDRBOOK_URL` | Akash address book URL | chain-registry default |
| `OLINE_NON_INTERACTIVE` | Skip all prompts | unset |
| `OLINE_AUTO_SELECT` | Auto-select cheapest provider | unset |

## After deploy

On success, the node's RPC/gRPC/REST endpoints are saved to `.env` as:
- `OLINE_RPC_ENDPOINT`
- `OLINE_GRPC_ENDPOINT`
- `OLINE_REST_ENDPOINT`

Subsequent `oline deploy` commands will use these private endpoints.

---

### oline firewall

```
Manage pfSense firewall SSH keys and connectivity

Usage: oline firewall [OPTIONS] <COMMAND>

Commands:
  bootstrap      Install SSH key on a pfSense firewall for passwordless management
  list           Show saved firewall connections
  status         Check SSH connectivity to saved firewalls
  grant-access   Grant a client SSH access to internal servers via pfSense jump host
  list-clients   Show all granted client access records
  revoke-access  Revoke a client's SSH access from all their target servers
  help           Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

#### Examples

# oline firewall — pfSense SSH Key Provisioning

## Bootstrap

```bash
# Interactive — prompts for host, password
oline firewall bootstrap

# Specify host and key path
oline firewall bootstrap --host 192.168.1.1 --user admin --key-path ~/.ssh/oline-server

# Force install method
oline firewall bootstrap --host 192.168.1.1 --method ssh-copy-id

# Non-interactive
OLINE_NON_INTERACTIVE=1 PFSENSE_HOST=192.168.1.1 PFSENSE_PASSWORD=pfsense \
  oline firewall bootstrap --key-path ~/.ssh/oline-server

# Key already installed (just save the record)
oline firewall bootstrap --host 192.168.1.1 --key-path ~/.ssh/oline-server \
  --pubkey ~/.ssh/oline-server.pub --key-installed

# Forward key to internal servers via pfSense jump host
oline firewall bootstrap --host 192.168.1.1 \
  --forward-to root@10.0.0.50 \
  --forward-to deploy@10.0.0.51:2222
```

## List & Status

```bash
oline firewall list      # show saved firewalls
oline firewall status    # check SSH connectivity
```

## Client Access Management

```bash
# Grant a client SSH access to an internal server via pfSense
oline firewall grant-access --name alice --pubkey alice.pub --target root@10.0.0.50

# Grant to firewall + target
oline firewall grant-access --name alice --pubkey alice.pub \
  --include-firewall --target root@10.0.0.50

# List all client access records
oline firewall list-clients

# Revoke a client's access
oline firewall revoke-access --name alice
```

---

### oline relayer

```
Manage a Cosmos IBC relayer (binary hot-swap, config reload, key install)

Usage: oline relayer [OPTIONS] <COMMAND>

Commands:
  status         Show relayer process status and rly API health
  logs           Tail relayer logs (/tmp/rly.log)
  update-binary  Hot-swap the rly binary without restarting the container
  update-config  Upload a new config.yaml and signal a relayer restart
  keys           Install a relayer key mnemonic into the container's key directory
  help           Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

---

### oline vpn

```
Provision and manage WireGuard VPN on pfSense

Usage: oline vpn [OPTIONS] <COMMAND>

Commands:
  setup          Extract credentials from deployment logs and store encrypted
  register       Register this device with the tailnet
  health         Check Headscale server health
  nodes          Manage tailnet nodes
  users          Manage tailnet users
  keys           Manage preauth and API keys
  policy         Manage ACL policy
  pfsense-setup  Install Tailscale on pfSense and register with Headscale
  servers        Show stored server configurations
  help           Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>    Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --server <SERVER>      Headscale server label (uses default from store if omitted)
      --endpoint <ENDPOINT>  Override Headscale gRPC endpoint (e.g. https://admin.terp.network:443)
      --examples             Print usage examples and exit
  -h, --help                 Print help
```

---

### oline providers

```
Manage trusted Akash providers (saved to ~/.config/oline/trusted-providers.json)

Usage: oline providers [OPTIONS] <COMMAND>

Commands:
  list     List all trusted providers
  add      Add a provider to the trusted list (fetches provider info from chain)
  remove   Remove a provider from the trusted list
  inspect  Show detailed info for a trusted provider
  path     Print the path to the trusted providers file
  help     Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
      --examples           Print usage examples and exit
  -h, --help               Print help
```

---

### oline registry

```
Embedded OCI container registry (serve, import, list)

Usage: oline registry [OPTIONS] <COMMAND>

Commands:
  serve   Start the OCI container registry server
  import  Import a local Docker image into the registry
  list    List images available in the registry
  help    Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
  -h, --help               Print help
```

---

### oline testnet-deploy

```
Bootstrap a fresh testnet on Akash with validator, faucet, and full sentry array

Usage: oline testnet-deploy [OPTIONS]

Options:
      --fast-blocks
          Use fast blocks (200ms timeouts) on the validator
      --chain-id <CHAIN_ID>
          Testnet chain ID (default: testnet-1) [default: testnet-1]
      --localterp-image <LOCALTERP_IMAGE>
          localterp Docker image (must be pre-built and pushed to a registry) [env: LOCALTERP_IMAGE=] [default: ghcr.io/permissionlessweb/localterp:latest]
      --raw
          Enter raw mnemonic directly (skip encrypted .env)
      --non-interactive
          Skip interactive prompts — use env vars + defaults
      --validator-rpc <VALIDATOR_RPC>
          Use an external validator instead of deploying one (skip Phase V). Format: <RPC_URL> e.g. https://rpc-testnet.terp.network
      --validator-peer <VALIDATOR_PEER>
          External validator P2P peer address. Required with --validator-rpc. Format: <node_id>@<host>:<port>
      --profile <PROFILE>
          Config profile to use (default: testnet for testnet-deploy) [default: testnet]
      --resume
          Resume from saved state — accept leases for previously created deployments. Requires --provider-a (and optionally --provider-b, --provider-c)
      --provider-a <PROVIDER_A>
          Provider address for Phase A (snapshot+seed). Used with --resume
      --provider-b <PROVIDER_B>
          Provider address for Phase B (tackles). Used with --resume
      --provider-c <PROVIDER_C>
          Provider address for Phase C (forwards). Used with --resume
      --examples
          Print usage examples and exit
  -h, --help
          Print help
```

---

### oline console

```
Interact with Akash Console API (deployments, providers, leases, etc.)

Usage: oline console [OPTIONS] <COMMAND>

Commands:
  deployment   Deployment lifecycle: list, get, create, update, close, deposit
  lease        Lease management: create, status
  bid          Bid listing
  provider     Provider discovery: list, get, leases graph, JWT
  network      Network node endpoints
  pricing      Pricing estimates
  auth         API key management
  certificate  Certificate creation
  address      Address balances and transactions
  settings     Deployment settings (auto top-up)
  help         Print this message or the help of the given subcommand(s)

Options:
  -p, --profile <PROFILE>  Config profile to use (mainnet, testnet, local) [env: OLINE_PROFILE=] [default: mainnet]
  -h, --help               Print help
```

---

### oline help

```
No detailed help available for help
```

---

## Justfile Recipes

### just deploy

# oline deploy

Full automated deployment of the Terp Network validator infrastructure
across phases A (Special Teams), B (Tackles), C (Forwards), and E (Relayer).

## Usage

```bash
# Parallel deployment (default) — deploys all phases up-front
oline deploy

# Sequential deployment — one phase at a time
oline deploy --sequential

# Enter mnemonic interactively (instead of .env)
oline deploy --raw
```

## Non-interactive (CI / scripting)

```bash
OLINE_NON_INTERACTIVE=1 \
OLINE_MNEMONIC="word1 word2 ... word24" \
OLINE_PASSWORD=mypassword \
OLINE_AUTO_SELECT=1 \
  oline deploy
```

## Justfile recipes

```bash
# Build + deploy (parallel)
just deploy

# Dry-run — render SDLs without broadcasting
just dry-run
```

## Key environment variables

| Variable | Description |
|---|---|
| `OLINE_NON_INTERACTIVE` | Skip all prompts |
| `OLINE_MNEMONIC` | Mnemonic (bypasses rpassword prompt) |
| `OLINE_PASSWORD` | Config encryption password |
| `OLINE_AUTO_SELECT` | Auto-select cheapest provider |
| `SDL_DIR` | Custom SDL template directory |
| `OLINE_TEST_STOP_AFTER_DEPLOY` | Stop after deploy step (testing) |

---

### just pfsense

# just pfsense-connect

Full pfSense bootstrap: SSH key provisioning, firewall configuration, and
tunnel setup in one step.

## Usage

```bash
# Full bootstrap — interactive prompts for IPs and passwords
just pfsense-connect

# Reset pfSense SSH config (remove oline keys)
just pfsense-reset

# Reconfigure subnets after network change
just pfsense-resubnet

# Show pfSense status
just pfsense
```

## Required environment variables

| Variable | Description |
|---|---|
| `CLIENT_IP` | Client machine WAN IP |
| `CLIENT_LAN_IP` | Client machine LAN IP (preferred for SSH) |
| `CLIENT_USER` | Client SSH username |
| `PROXY_TARGET` | Target host behind pfSense |
| `PFSENSE_HOST` | pfSense WAN IP |
| `PFSENSE_PASSWORD` | pfSense admin password |

## Workflow

```bash
# 1. Set environment
export CLIENT_IP=192.168.1.101
export PFSENSE_HOST=192.168.1.168

# 2. Run full bootstrap
just pfsense-connect

# 3. Verify tunnel
just tunnel test
```

---

### just push

# just sync-client — SSH-multiplexed repo sync

Sync the oline repository to a remote machine and install via SSH.
Uses multiplexed SSH connections for efficiency (single password prompt).

## Usage

```bash
# Sync to a remote host
just sync-client user@host

# Sync to a remote host with custom port
just sync-client user@host:2222

# Push changes only (no install)
just push user@host

# Run oline commands on remote
just remote user@host "oline endpoints check"
```

## Workflow

```bash
# 1. Sync repo + build on remote server
just sync-client deploy@10.0.0.50

# 2. Run commands remotely
just remote deploy@10.0.0.50 "oline deploy"
```

---

### just tunnel

# just tunnel — SOCKS proxy + pinned tunnels

Manage SSH tunnels through pfSense for accessing internal services.

## Usage

```bash
# Start SOCKS proxy tunnel
just tunnel up

# Stop SOCKS proxy tunnel
just tunnel down

# Add a pinned port forward
just tunnel add 8080:10.0.0.50:80

# Remove a pinned tunnel
just tunnel remove 8080

# Test tunnel connectivity
just tunnel test

# List active tunnels
just tunnel list
```

## Workflow

```bash
# 1. Start the SOCKS proxy
just tunnel up

# 2. Add specific port forwards as needed
just tunnel add 8545:10.0.0.50:8545
just tunnel add 26657:10.0.0.50:26657

# 3. Access internal services through localhost
curl http://localhost:8545

# 4. Clean up
just tunnel down
```

---

## Examples

For detailed examples of any command, run:

```bash
oline <command> --examples
```

