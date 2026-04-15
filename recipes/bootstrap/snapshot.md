# Bootstrap: Snapshot Node (oline-a-snapshot)

Phase A — provides state sync source and writes snapshots to MinIO.
Auth: SSH (ED25519), port from `SSH_P` (default 22), pubkey injected at deploy via `SSH_PUBKEY` env.

## Trigger condition
Deploy `phase_a` group completes and provider assigns external SSH port.

## Steps

### 1. Wait for SSH availability
```
oline wait-ssh --episode $EID --node snapshot --timeout 120
```
Polls `ssh -p $SSH_PORT $HOST exit` until success. Max 2 min — Akash containers boot fast.

### 2. Push pre-start files (SFTP)
Files delivered before `OLINE_PHASE=start` is fired:
```
/tmp/oline-env.sh       ← node-specific env overrides (domains, ports, S3 creds)
/tmp/tls.crt            ← nginx TLS certificate (from Cloudflare or self-signed)
/tmp/tls.key            ← nginx TLS private key
```
```
oline push-files --episode $EID --node snapshot
```
Internally: SFTP upload → verify SHA256 → proceed.

### 3. Signal start
```
oline signal-start --episode $EID --node snapshot
```
Sends `OLINE_PHASE=start` env var trigger to entrypoint. Node begins:
- Chain sync (full archive, pruning=nothing)
- Snapshot scheduling to MinIO at `OLINE_SNAP_TIME`
- nginx TLS proxy for RPC/API/gRPC domains

### 4. Wait for snapshot node peer ID
```
oline wait-peer --episode $EID --node snapshot --timeout 600
```
Polls `GET /status` on `RPC_D_SNAP:RPC_P_SNAP` until `result.node_info.id` is non-empty.
Writes `snapshot_peer = "<id>@<p2p_host>:<p2p_port>"` to session state.

### 5. Wait for snapshot to complete (if sync_method=snapshot)
```
oline wait-ready --episode $EID --node snapshot --timeout 5400
```
Polls `catching_up` field in `/status`. Snapshot node must reach chain tip before
distributing to tackles. Typical: 30–90 min depending on chain height.

## Outputs written to session state
```json
{
  "snapshot_peer": "<node_id>@<host>:<p2p_port>",
  "snapshot_rpc":  "https://<RPC_D_SNAP>",
  "snapshot_ready": true
}
```

## Environment vars injected by entrypoint
The `OLINE_ENTRYPOINT_URL` script reads these from `/tmp/oline-env.sh`:
- `RPC_DOMAIN`, `RPC_P` — nginx upstream
- `API_D`, `API_P`
- `P2P_D`, `P2P_P`
- `GRPC_D`, `GRPC_P`
- `S3_KEY`, `S3_SECRET`, `S3_HOST`
- `SNAPSHOT_PATH`, `SNAPSHOT_TIME`, `SNAPSHOT_SAVE_FORMAT`
- `SNAPSHOT_METADATA_URL`
