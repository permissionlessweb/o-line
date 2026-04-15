# Bootstrap: Relayer Node (oline-e-relayer)

Phase E — IBC go-relayer. Independent of sentry array phases.
Auth: SSH (ED25519), fresh keypair generated per phase_e deploy.
Transport: SSH for config + key delivery; REST API on port 3000 for monitoring.

## Trigger condition
Can deploy any time after both chains are live and have public RPC endpoints.
Does NOT depend on phases A, B, or C.

## Steps

### 1. Wait for SSH availability
```
oline wait-ssh --episode $EID --node relayer --timeout 120
```

### 2. Push relayer config (SFTP)
```
/tmp/config.yaml      ← go-relayer chain configuration
/tmp/oline-env.sh     ← RLY_KEY_NAME, chain endpoints
```

`config.yaml` is generated from:
- `OLINE_CHAIN_ID` + `OLINE_RPC_ENDPOINT` + `OLINE_GRPC_ENDPOINT`
- `RLY_REMOTE_CHAIN_ID` + remote chain endpoints

```
oline push-files --episode $EID --node relayer
```

### 3. Install chain keys via SSH exec
Keys are never written to disk on the oline host — piped directly:
```
oline install-relayer-keys --episode $EID
```
Internally:
```bash
ssh relayer "rly keys restore $OLINE_CHAIN_ID $RLY_KEY_NAME '$RLY_KEY_TERP'"
ssh relayer "rly keys restore $RLY_REMOTE_CHAIN_ID $RLY_KEY_NAME '$RLY_KEY_REMOTE'"
```
Keys exist only in the container's keyring.

### 4. Signal start
```
oline signal-start --episode $EID --node relayer
```
Relayer starts, creates clients + connections + channels on both chains.

### 5. Update DNS (optional)
```
oline update-dns --episode $EID --node relayer
```
Creates CNAME for `RLY_API_D` → provider hostname (for REST monitoring API).

### 6. Verify relayer is relaying
```
oline wait-ready --episode $EID --node relayer --check rest --timeout 120
```
Polls `GET /api/v1/chains` on relayer REST API until both chains appear.

## Outputs written to session state
```json
{
  "relayer_rest": "https://<RLY_API_D>",
  "relayer_ready": true
}
```

## Hot-swap (day-2)
Relayer binary can be hot-swapped without redeployment:
```
oline relayer hot-swap --node relayer --binary-url <url>
```
Downloads new binary → stops old process → starts new process.
No chain lease required — container stays alive.

## Notes
- `RLY_KEY_TERP` and `RLY_KEY_REMOTE` are marked `secret=true` in sdl-vars.toml
- They are never logged or stored in session state files
- Port 3000 is globally exposed for REST monitoring
