# oline recipes

Structured data and episode workflows for LLM-driven Akash deployments.
Replaces the embedded state machine in `workflow/` with composable async tools.

## Architecture

```
Before: oline deploy → OLineWorkflow (stateful state machine, ~3000 lines)
After:  LLM reads recipes/ → calls oline atomic tools → episode_id tracks state
```

oline becomes a **thin async tool executor**, not a runtime.
State lives in `~/.config/oline/sessions/{episode_id}.json`.

---

## File map

| File | Purpose |
|------|---------|
| `containers.toml` | Container image registry — local + remote tags |
| `sdl-vars.toml` | SDL variable schema — compact array format for LLM |
| `groups.toml` | Deployment group definitions — parallelism + sequencing |
| `bootstrap/<node>.md` | Per-node bootstrap step recipes |
| `episodes/full-deploy.md` | Complete sentry array deployment episode |
| `episodes/refresh.md` | Day-2 SSH operations episode |

---

## LLM usage pattern (TensorZero episode style)

Each deployment is an **episode**: a sequence of `oline` tool calls sharing an `episode_id`.

```python
# Inference 1: start episode
episode_id = run("oline session new")

# Inference 2: populate SDLs (compact var arrays — minimal tokens)
run(f"oline sdl populate --episode {episode_id} --phase a --vars '[...]'")
run(f"oline sdl populate --episode {episode_id} --phase b --vars '[...]'")

# Inference 3: deploy foundation group (A + B parallel)
run(f"oline deploy-group --episode {episode_id} --group foundation --sdls a.yml,b.yml --parallel")

# Inference 4-N: bootstrap, wait, inject peers, deploy C, update DNS...
# (see episodes/full-deploy.md for full sequence)

# Final: session summary
run(f"oline session summary --episode {episode_id}")
```

Episode state is persisted between inferences — each step writes outputs (peer IDs,
DSEQs, hostnames) to the session JSON file. Subsequent steps read from it.

---

## SDL variable compact format

When calling `oline sdl populate --vars`, pass only `input` vars.
Skip `auto` vars — oline generates those (SSH keys, S3 creds, monikers, accept lists).

```bash
# Minimal phase A call — all other vars come from .env config
oline sdl populate --phase a --vars '[
  ["RPC_D_SNAP",  "statesync.terp.network"],
  ["P2P_D_SNAP",  "statesync-peer.terp.network"],
  ["RPC_D_SEED",  "seed.terp.network"]
]'

# Override a chain-level default
oline sdl populate --phase a --vars '[
  ["OMNIBUS_IMAGE", "ghcr.io/akash-network/cosmos-omnibus:v1.2.40-generic"],
  ["OLINE_SYNC_METHOD", "snapshot"]
]'
```

---

## Simplified CLI surface

### Session management
```
oline session new                              → episode_id (UUIDv7)
oline session status  --episode <id>           → step history + pending
oline session summary --episode <id>           → deployment recap
oline session close   --episode <id>           → archive session
```

### SDL population
```
oline sdl populate --phase a|b|c|e|f --vars '[...]' [--out path]
```

### Deployment
```
oline deploy-group --group <name> --sdls <paths> [--parallel] [--episode <id>]
```

### Bootstrap (reads recipe from recipes/bootstrap/<node>.md)
```
oline bootstrap --node <label> [--episode <id>]
oline push-files --node <label> [--episode <id>]
oline signal-start --node <label> [--episode <id>]
```

### Peer + sync operations
```
oline wait-ssh      --node <label> --timeout <secs>
oline wait-peer     --node <label> --timeout <secs>
oline wait-ready    --node <label> --timeout <secs>
oline inject-peers  --to <nodes> --from <nodes>
oline distribute-snapshot --from <node> --to <nodes>
```

### DNS + infra
```
oline update-dns    [--node <label>] [--phase a|b|c|e]
oline test-s3       [--episode <id>]
```

### Day-2 (stateless)
```
oline refresh --node <label> list|health|env|restart|logs|inject-peers
```

### Utility (keep as-is)
```
oline encrypt        ← mnemonic encryption
oline endpoints      ← probe Akash RPC endpoints
oline init           ← interactive config collection
oline manage         ← view/close deployments
oline providers      ← trusted provider list
```

---

## Code deletion plan

The following modules can be **deleted** once the recipe-based CLI is implemented.
Together they represent ~3500–4000 lines of heuristic orchestration code.

### Delete entirely
| Module | Lines (est.) | Replaced by |
|--------|-------------|-------------|
| `workflow/mod.rs` | ~400 | episode JSON state |
| `workflow/context.rs` | ~200 | episode JSON state |
| `workflow/step.rs` | ~190 | recipes/groups.toml |
| `workflow/phases/a.rs` | ~300 | recipes/bootstrap/snapshot.md + seed.md |
| `workflow/phases/b.rs` | ~250 | recipes/bootstrap/tackle.md |
| `workflow/phases/c.rs` | ~250 | recipes/bootstrap/forward.md |
| `workflow/phases/e.rs` | ~200 | recipes/bootstrap/relayer.md |
| `workflow/phases/parallel.rs` | ~500 | deploy-group --parallel |
| `tui/` (ratatui TUI) | ~400 | oline prints structured JSON/text |
| `cli.rs` (interactive prompts) | ~400 | --vars array input |
| `sessions.rs` (HD orchestration) | ~300 | simplified in deploy-group |
| `testing/` (docker harness) | ~800 | external test scripts |

### Simplify (keep core, remove orchestration wrappers)
| Module | Keep | Remove |
|--------|------|--------|
| `cmd/deploy.rs` | preflight, encrypt, manage | full workflow orchestration |
| `akash.rs` | `build_phase_*_vars()` | sync method branching (move to recipe data) |
| `deployer.rs` | Akash client, bid/accept | complex session tracking |

### Keep as-is
- `crypto.rs` — SSH keygen, SFTP, AES encryption (core)
- `dns/cloudflare.rs` — DNS operations (core)
- `snapshots.rs` — snapshot push/pull (core)
- `nodes/mod.rs` — encrypted node record store (core)
- `config.rs` + `lib.rs` field descriptors (core)
- `providers.rs` — trusted provider list (core)
- `cmd/refresh.rs` — day-2 SSH ops (keep, useful)
- `cmd/manage.rs` — deployment management (keep)
- All SDL templates in `templates/sdls/oline/` (keep)

---

## Session state schema

`~/.config/oline/sessions/{episode_id}.json`

```json
{
  "episode_id": "019612ab-xxxx-7xxx-xxxx-xxxxxxxxxxxx",
  "created_at": "2026-04-13T00:00:00Z",
  "config_snapshot": { "OLINE_CHAIN_ID": "morocco-1", "..." : "..." },
  "deployments": {
    "phase_a": { "dseq": 1234, "provider": "akash1abc...", "host": "provider.akash.network", "ssh_port": 32456 },
    "phase_b": { "dseq": 5678, "provider": "akash1def...", "host": "provider2.akash.network", "ssh_port": 29000 },
    "phase_c": { "dseq": 9012, "provider": "akash1ghi...", "host": "provider3.akash.network", "ssh_port": 26001 }
  },
  "peers": {
    "snapshot_peer": "<id>@<host>:26656",
    "seed_peer":     "<id>@<host>:26656",
    "lt_peer":       "<id>@<host>:26656",
    "rt_peer":       "<id>@<host>:26656",
    "lf_peer":       "<id>@<host>:26656",
    "rf_peer":       "<id>@<host>:26656"
  },
  "credentials": {
    "phase_a_ssh_key_path": "~/.config/oline/keys/oline-parallel-key",
    "s3_key": "<key>",
    "s3_secret": "<secret>"
  },
  "steps_completed": [
    "deploy_foundation",
    "bootstrap_snapshot",
    "bootstrap_seed",
    "bootstrap_minio",
    "bootstrap_tackles",
    "wait_snapshot_ready",
    "distribute_snapshot",
    "wait_tackle_peers"
  ]
}
```
