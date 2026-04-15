# Episode: Day-2 Refresh Operations

**Outcome**: SSH-based management of running Akash nodes without redeployment.
**Trigger**: Any time after initial deploy. Stateless — no episode_id needed.

---

## Available refresh operations

All commands target nodes by label (from `oline node list`):

```bash
oline refresh --node <label> <operation>
# or target a phase:
oline refresh --phase a|b|c|e <operation>
# or all nodes:
oline refresh --all <operation>
```

---

## Operations

### list — show all tracked nodes
```bash
oline refresh --all list
```
Output: label, dseq, phase, host:ssh_port, RPC health status.

### health — check RPC liveness
```bash
oline refresh --all health
# or:
oline refresh --phase c health
```
Polls `/status` on each node's RPC. Reports: height, catching_up, peer_count.

### env — push updated environment variables
```bash
oline refresh --node oline-a-snapshot env \
  --set SNAPSHOT_RETAIN="3 days" \
  --set SNAPSHOT_KEEP_LAST=3
```
SSH exec: updates `/tmp/oline-env.sh` → sends SIGHUP to entrypoint to reload env.
Does NOT restart the node process.

### restart — restart node entrypoint
```bash
oline refresh --node oline-c-left-forward restart
```
SSH exec: kills the chain process gracefully → entrypoint re-runs from `/tmp/wrapper.sh`.
The container stays alive (Akash lease persists). Chain resumes from last block.

### logs — stream container logs
```bash
oline refresh --node oline-b-left-tackle logs --tail 100 --follow
```
SSH exec: `tail -f /proc/1/fd/1` (entrypoint stdout) via WebSocket stream.

### inject-peers — push updated peer list
```bash
oline refresh --node oline-b-left-tackle inject-peers \
  --peers "abc123@host:26656,def456@host2:26656"
```
Updates `TERPD_P2P_UNCONDITIONAL_PEER_IDS` + `TERPD_P2P_PERSISTENT_PEERS` in env.
Triggers peer connection attempt without full restart.

### snapshot-now — trigger manual snapshot
```bash
oline refresh --node oline-a-snapshot snapshot-now
```
SSH exec: sends trigger to snapshot scheduler. Useful before planned maintenance.

### update-dns — refresh CNAME records
```bash
oline refresh --phase c update-dns
```
Re-runs Cloudflare DNS upsert for all phase C domains.
Use when provider reassigns external hostname.

---

## Batch env update example

Push a new WASMVM version to all cosmos-omnibus nodes:

```bash
oline refresh --phase a,b,c env \
  --set WASMVM_VERSION=v3.1.0 \
  --set WASMVM_URL=https://github.com/CosmWasm/wasmvm/releases/download/v3.1.0/libwasmvm.x86_64.so
```

Then restart to apply:
```bash
oline refresh --phase a,b,c restart
```

---

## State

Refresh operations read node records from `$SECRETS_PATH/nodes.enc` (AES-256-GCM).
No episode_id needed — refresh is stateless.
