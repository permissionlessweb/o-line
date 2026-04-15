# Bootstrap: Seed Node (oline-a-seed)

Phase A — provides peer discovery for forwards. PEX=true, no private peers.
Auth: SSH (ED25519), same keypair as snapshot (shared `SSH_PUBKEY` in phase A SDL).

## Trigger condition
Phase A deploy complete. Can bootstrap in parallel with snapshot node.

## Steps

### 1. Wait for SSH availability
```
oline wait-ssh --episode $EID --node seed --timeout 120
```

### 2. Push pre-start files (SFTP)
```
/tmp/oline-env.sh    ← domains, ports, snapshot URL
/tmp/tls.crt
/tmp/tls.key
```
```
oline push-files --episode $EID --node seed
```
No S3 credentials needed (seed doesn't write snapshots).

### 3. Signal start
```
oline signal-start --episode $EID --node seed
```
Seed syncs using snapshot URL (`OLINE_SNAP_FULL_URL`) or statesync.

### 4. Wait for seed peer ID
```
oline wait-peer --episode $EID --node seed --timeout 300
```
Seed is lighter — syncs faster than snapshot node. Timeout 5 min.
Writes `seed_peer = "<id>@<p2p_host>:26656"` to session state.

## Outputs written to session state
```json
{
  "seed_peer": "<node_id>@<host>:26656"
}
```

## Notes
- Seed does NOT need to reach chain tip before tackles can start
- Seed peer ID is required for forwards (phase_c) `TERPD_P2P_SEEDS`
- If seed fails, forwards can still use snapshot as persistent peer
