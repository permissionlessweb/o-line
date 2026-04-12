# O-Line Quickstart

Deploy a complete Terp Network sentry array — snapshot node, seed node, MinIO storage, left/right tackles, and left/right forwards — all in a single command on Akash Network.

```
                          ┌─────────────────────────────────────┐
[Snapshot] ──peers──────► │ Left Tackle  ──private──► [Validator]│
[Seed]     ──seeds──────► │ Right Tackle ──private──► [Validator]│
[MinIO]    ──archives───► │ Left Forward  (public RPC/API/gRPC)  │
                          │ Right Forward (public RPC/API/gRPC)  │
                          └─────────────────────────────────────┘
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | stable | Build the `oline` binary |
| An Akash wallet | — | Pay for deployments (needs AKT) |
| Cloudflare account | — | DNS for node subdomains |
| A domain name | — | e.g. `terp.network` (managed by Cloudflare) |
| `openssl` | any | TLS cert generation (system package) |

The wallet mnemonic for your **Akash deployer account** (not the validator) is the only secret needed.
Fund it with at least **80 AKT** — approximately 10 AKT per deployment unit.

---

## Install

```bash
git clone https://github.com/permissionlessweb/o-line
cd o-line
cargo install --path .
```

The `oline` binary is now in `~/.cargo/bin/oline`.

---

## Step 1 — Copy and fill in `.env`

```bash
cp .env.example .env
```

Open `.env` and fill in the sections below. Required fields are marked **`★`**.

### Akash Network

```env
# ★ Akash endpoints (defaults usually work)
OLINE_RPC_ENDPOINT=https://rpc.akashnet.net:443
OLINE_GRPC_ENDPOINT=https://grpc.akashnet.net:443
```

### Cloudflare DNS  ★ required

```env
OLINE_CF_API_TOKEN=<your Cloudflare API token with Zone:Edit permissions>
OLINE_CF_ZONE_ID=<your zone ID — found in Cloudflare dashboard → Overview → right sidebar>
```

### Your Validator Peer  ★ recommended

```env
# Peer ID of your home/private validator so tackles connect to it directly.
OLINE_VALIDATOR_PEER_ID=<nodeid>@<host>:<port>
```

### Node Subdomains  ★ required for each node you want publicly accessible

Pick subdomains on your Cloudflare-managed domain.
`oline` creates the CNAME records automatically — you only need to choose the names.

**Phase A — Special Teams (snapshot + seed)**

```env
# Snapshot node
RPC_D_SNAP=statesync.terp.network
P2P_D_SNAP=statesync-peer.terp.network
# Optional — leave blank to skip
API_D_SNAP=
GRPC_D_SNAP=

# Seed node
RPC_D_SEED=seed-rpc.terp.network
P2P_D_SEED=seed.terp.network
API_D_SEED=
GRPC_D_SEED=
```

**Phase B — Tackles (sentry nodes that face your validator)**

```env
RPC_D_TL=tackle-l.terp.network
P2P_D_TL=tackle-l-peer.terp.network
RPC_D_TR=tackle-r.terp.network
P2P_D_TACKLE_R=tackle-r-peer.terp.network
```

**Phase C — Forwards (public-facing RPC/API/gRPC)**

```env
RPC_D_FL=rpc-l.terp.network
API_D_FL=api-l.terp.network
GRPC_D_FL=grpc-l.terp.network
P2P_D_FL=rpc-l-peer.terp.network

RPC_D_FR=rpc-r.terp.network
API_D_FR=api-r.terp.network
GRPC_D_FR=grpc-r.terp.network
P2P_D_FR=rpc-r-peer.terp.network
```

**Ports** — leave at defaults unless your chain uses non-standard ports:

```env
RPC_P_SNAP=26657
P2P_P_SNAP=26656
# ... (all PORT_* vars default to standard Cosmos ports)
```

### Snapshot Bootstrap

```env
# Where nodes download state snapshots on first boot.
# Defaults point to itrocket.net public snapshots for terpnetwork — change if needed.
OLINE_SNAP_STATE_URL=https://server-4.itrocket.net/mainnet/terp/.current_state.json
OLINE_SNAP_BASE_URL=https://server-4.itrocket.net/mainnet/terp/
```

### Secrets directory

```env
# Local directory where the deployer saves SSH keys and TLS certs.
SECRETS_PATH=secrets
```

Create it:

```bash
mkdir -p secrets
```

---

## Step 2 — Encrypt your mnemonic

`oline` never stores your mnemonic in plaintext. It encrypts it with AES-256-GCM
(password-derived with Argon2id) and stores the ciphertext in `.env`.

```bash
oline encrypt
```

You will be prompted for:
1. Your Akash deployer **mnemonic** (24 words)
2. An **encryption password** (you choose; required again for each deploy)

The encrypted blob is written to `OLINE_ENCRYPTED_MNEMONIC=` in `.env`.

---

## Step 3 — Deploy the full array

```bash
oline deploy
```

You will be prompted once for your **encryption password**, then the parallel deployment begins automatically.

### What happens

```
FundChildAccounts     HD-derive 8 child accounts (one per node), fund from master
DeployAllUnits        Broadcast CreateDeployment for all 8 units simultaneously
SelectAllProviders    For each unit: display bids, you pick a provider (interactive)
UpdateAllDns          Create/update all Cloudflare CNAME records in parallel
WaitSnapshotReady     Poll snapshot node RPC until synced and catching_up=false
DistributeSnapshot    Fetch archive from snapshot node, push to all 6 sentry nodes
SignalAllNodes        Push TLS certs via SFTP, fire OLINE_PHASE=start on all nodes
InjectPeers           SSH-push discovered peer IDs to tackles/forwards
WaitAllPeers          Poll all node RPCs until each has at least one peer
Summary               Print DSEQs, endpoints, SSH access instructions
Complete
```

**Provider selection** pauses at `SelectAllProviders` — one at a time, in sequence.
For each unit, `oline` displays available bids sorted by price and waits for you to type
a number to accept. All other steps are fully automated.

---

## Step 4 — SSH into any node

After deployment completes, `oline` prints an SSH command for each node.
The format is:

```bash
# SSH private key is auto-generated and saved to $SECRETS_PATH/ssh-key
ssh -i secrets/ssh-key -p <NodePort> root@<provider-host>
```

The exact host and port come from the Akash provider lease — they change each deployment.
Run `oline manage` to see current endpoints.

---

## Day-2 Operations

### Check node status

```bash
oline manage
```

Lists all active leases with their DSEQ, provider host, and service endpoints.

### Push a configuration update to all nodes

```bash
oline refresh
```

Reads any changed env vars from `.env` and SSH-pushes them to running nodes,
then signals each node to reload. Use this after updating peers, domains, or
RPC/gRPC settings without redeploying.

### Check Akash endpoint health

```bash
oline endpoints
```

Probes the configured Akash RPC/gRPC endpoints and saves the fastest responsive
one back to `.env`. Run this if deployments are failing due to endpoint timeouts.

### Test S3/MinIO connectivity

```bash
oline test-s3
```

---

## Optional: Sequential Deployment

The default `oline deploy` deploys all units in parallel using HD-derived child accounts
(one per unit). Each unit gets its own Akash account so sequence-number conflicts are avoided.

To use the legacy sequential path (phases A → B → C one at a time):

```bash
oline deploy --sequential
```

Sequential mode is slower but requires only one Akash account.

---

## Optional: IBC Relayer (Phase E)

Add to `.env`:

```env
RLY_REMOTE_CHAIN_ID=osmosis-1
RLY_IMAGE=ghcr.io/permissionlessweb/rly-docker:latest
RLY_API_D=relayer.terp.network
```

The relayer deploys after Phase C completes. Phase E is optional — the array works
fully without it.

---

## Variable Reference

Full list of all supported env vars with descriptions:

| Variable | Required | Description |
|----------|----------|-------------|
| `OLINE_ENCRYPTED_MNEMONIC` | ★ | Written by `oline encrypt` |
| `OLINE_CF_API_TOKEN` | ★ | Cloudflare API token (Zone:Edit) |
| `OLINE_CF_ZONE_ID` | ★ | Cloudflare zone ID |
| `RPC_D_SNAP` | ★ | Snapshot RPC subdomain |
| `P2P_D_SNAP` | ★ | Snapshot P2P subdomain |
| `RPC_D_SEED` | ★ | Seed RPC subdomain |
| `P2P_D_SEED` | ★ | Seed P2P subdomain |
| `RPC_D_TL/R` | ★ | Left/Right tackle RPC subdomains |
| `P2P_D_TL/R` | ★ | Left/Right tackle P2P subdomains |
| `RPC_D_FL/R` | ★ | Left/Right forward RPC subdomains |
| `P2P_D_FL/R` | ★ | Left/Right forward P2P subdomains |
| `OLINE_VALIDATOR_PEER_ID` | recommended | Your validator's peer string `nodeid@host:port` |
| `OLINE_RPC_ENDPOINT` | default ok | Akash RPC endpoint |
| `OLINE_GRPC_ENDPOINT` | default ok | Akash gRPC endpoint |
| `OLINE_CHAIN_JSON` | default ok | Chain registry JSON URL |
| `OLINE_SNAP_BASE_URL` | default ok | Bootstrap snapshot URL |
| `OLINE_SNAP_STATE_URL` | default ok | Snapshot state metadata URL |
| `SECRETS_PATH` | default ok | Local dir for SSH key + certs (`secrets`) |
| `OMNIBUS_IMAGE` | default ok | SDL deployment image |
| `API_D_*`, `GRPC_D_*` | optional | Public API/gRPC subdomains per node |
| `RLY_REMOTE_CHAIN_ID` | optional | Remote chain for IBC relayer (Phase E) |

All `*_P_*` variables default to standard Cosmos ports (26657/26656/1317/9090).

---

## Troubleshooting

**Deployment fails at SelectAllProviders — no bids**
→ Your SDL bid price may be too low. Run `oline endpoints` to refresh Akash endpoints,
or increase the AKT/day in `templates/sdls/`.

**DNS update fails**
→ Verify `OLINE_CF_API_TOKEN` has `Zone:DNS:Edit` permissions on the correct zone.
Run `oline dns` to test DNS updates in isolation.

**Node is stuck waiting for snapshot**
→ The snapshot URL may be temporarily down. Check `OLINE_SNAP_BASE_URL` in a browser.
Resume with `oline refresh` after the URL becomes available.

**SSH connection refused after deployment**
→ The provider's NodePort for SSH may take 1–2 minutes to become routable.
Wait and retry: `ssh -i secrets/ssh-key -p <port> root@<host>`.

**"OLINE_ENCRYPTED_MNEMONIC not set"**
→ Run `oline encrypt` first. The encrypted mnemonic must be in `.env`.

**Child account funding fails**
→ The master Akash account needs enough AKT. Aim for ≥ 80 AKT before deploying.
Check balance via the Akash dashboard or: `akash query bank balances <address>`.

---

## Directory Layout

```
.
├── .env                        Your config (gitignored)
├── .env.example                Template — copy this to .env
├── secrets/                    SSH keys + TLS certs (gitignored, auto-created)
├── templates/
│   ├── sdls/                   SDL templates for each phase
│   │   ├── a/                  Phase A: snapshot, seed, minio
│   │   ├── b/                  Phase B: left-tackle, right-tackle
│   │   ├── c/                  Phase C: left-forward, right-forward
│   │   └── e/                  Phase E: relayer
│   └── json/
│       └── chain.json          Local chain registry entry
├── plays/audible/
│   ├── oline-entrypoint.sh     Container lifecycle script (bootstrap + start modes)
│   └── tls-setup.sh            nginx TLS reverse proxy setup
├── plays/flea-flicker/nginx/   nginx config templates (rpc, api, grpc, p2p)
├── docs/                       Specialist guides (one per subsystem)
└── src/                        Rust source for the oline binary
```
