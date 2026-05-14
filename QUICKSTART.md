# O-Line Quickstart

Quickly deploy a complete Terp Network sentry array — snapshot node, seed node, MinIO storage, left/right tackles, and left/right forwards — all in a single command on Akash Network.

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

## Quickstart

Initialize your deployment config and render SDL templates in a few minutes.

```bash
# 1. Clone and build
git clone https://github.com/permissionlessweb/o-line
cd o-line
cargo install --path .

# 2. Initialize config (creates ~/.oline/config.yml)
oline init --list-templates   # see available presets
oline init --template dev     # choose a template (e.g. 'dev', 'mainnet', 'staging')

# 3. Review and customize ~/.oline/config.yml
# All fields are documented with comments. Required fields are marked 【required】.

# 4. Render SDL for a specific phase (skip --template if config.yml is already set)
oline sdl --phase c --template dev

# 5. Deploy (uses .env for secrets — encrypt first)
oline encrypt                  # prompts for mnemonic, writes encrypted blob to .env
oline deploy --phase c         # deploys Phase C: left+right forward nodes
```

For the full deployment pipeline (all phases), run:

```bash
oline deploy                # deploys all phases in parallel
oline deploy --sequential   # legacy: phases A → B → C → E one at a time
```

### Where things go

| What | Path |
|------|------|
| YAML config (initializer) | `~/.oline/config.yml` |
| Deploy config (JSON) | `~/.oline/deploy-config.json` |
| Encrypted mnemonic | `.env` (project root) |
| SSH keys & TLS certs | `$SECRETS_PATH` or `secrets/` |
| SDL templates | `templates/sdls/{a,b,c,e}/` |

### Source of truth — config fields definition

All field definitions live in one place. When you need to find a variable's type, default, or whether it's secret, **go directly to the source**:

- **`src/toml_config.rs:1393`** — `pub const CONFIG_FIELDS: &[ConfigField]` — the single source of truth. Every field (path, description, is_secret flag) is defined here. This is what `oline init` uses to generate `~/.oline/config.yml`.
- **`src/toml_config.rs:1705`** — `pub const SECRET_PATHS: &[&str]` — list of secret fields.
- **`src/config.rs:47`** — `pub fn oline_config_dir() -> PathBuf` — defines the `~/.oline` home directory.

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
