# Bootstrap: Tackle Nodes (oline-b-left-tackle, oline-b-right-tackle)

Phase B — private sentries. PEX=false. Communicate only with:
- Snapshot node (persistent peer for sync source)
- Validator (unconditional + private peer)
- Each forward (unconditional peer — injected AFTER forwards have peer IDs)

Auth: SSH (ED25519), fresh keypair generated per phase_b deploy.

## Trigger condition
Phase A deploy complete (snapshot peer ID must be in session state).
Bootstrap can start before snapshot node reaches chain tip.

## Steps (run in parallel for left + right tackle)

### 1. Wait for SSH availability
```
oline wait-ssh --episode $EID --node left-tackle --timeout 120
oline wait-ssh --episode $EID --node right-tackle --timeout 120
```

### 2. Push pre-start files (SFTP)
```
/tmp/oline-env.sh    ← OLINE_OFFLINE=1 (if snapshot mode), peer IDs, domains
/tmp/tls.crt
/tmp/tls.key
```
```
oline push-files --episode $EID --node left-tackle
oline push-files --episode $EID --node right-tackle
```

### 3. Signal start (OLINE_OFFLINE mode)
```
oline signal-start --episode $EID --node left-tackle
oline signal-start --episode $EID --node right-tackle
```
If `OLINE_SYNC_METHOD=snapshot`: nodes start with `OLINE_OFFLINE=1`.
They wait for snapshot archive delivery before initializing chain.

If `OLINE_SYNC_METHOD=statesync`: nodes start immediately and sync from RPC servers.

### 4. Distribute snapshot (snapshot mode only)
After snapshot node is ready (`snapshot_ready=true` in session):
```
oline distribute-snapshot --episode $EID --from snapshot --to left-tackle,right-tackle
```
SSH-streams the `.tar.lz4` archive from snapshot node directly to each tackle.
No intermediate storage — pipe: `ssh snapshot "cat archive" | ssh tackle "tar -xf -"`.
Parallel streams to both tackles simultaneously.

### 5. Wait for tackle peer IDs
```
oline wait-peer --episode $EID --node left-tackle --timeout 600
oline wait-peer --episode $EID --node right-tackle --timeout 600
```
Polls `/status` on tackle RPC endpoint (if exposed) or via SSH exec.
Writes peer IDs to session state — required before forwarding phase.

### 6. Inject forward peer IDs (after forwards deploy and have peer IDs)
```
oline inject-peers --episode $EID --to left-tackle,right-tackle --from left-forward,right-forward
```
SSH exec: updates `/tmp/oline-env.sh` with forward peer IDs, then:
`TERPD_P2P_UNCONDITIONAL_PEER_IDS=<lf_peer>,<rf_peer>`
Container reads updated env on next connection or via signal.

## Outputs written to session state
```json
{
  "lt_peer": "<node_id>@<host>:<p2p_port>",
  "rt_peer": "<node_id>@<host>:<p2p_port>"
}
```

## Security notes
- Tackles have NO global P2P exposure by default
- They only accept from: validator (unconditional), snapshot (persistent), forwards (unconditional)
- `TERPD_P2P_PEX=false` — peer exchange disabled (no crawling)
- SSH port IS global for management access
