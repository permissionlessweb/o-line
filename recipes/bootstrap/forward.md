# Bootstrap: Forward Nodes (oline-c-left-forward, oline-c-right-forward)

Phase C — public-facing RPC/API/gRPC endpoints.
PEX=true. Accepts from open network + seeds from seed node.
Unconditional peers: both tackles (private, protected).

Auth: SSH (ED25519), fresh keypair generated per phase_c deploy.

## Trigger condition
Phase B complete — both tackle peer IDs must be in session state.

## Steps (run in parallel for left + right forward)

### 1. Wait for SSH availability
```
oline wait-ssh --episode $EID --node left-forward --timeout 120
oline wait-ssh --episode $EID --node right-forward --timeout 120
```

### 2. Push pre-start files (SFTP)
```
/tmp/oline-env.sh    ← SEEDS=<seed_peer>, UNCONDITIONAL=<lt_peer,rt_peer>, domains
/tmp/tls.crt
/tmp/tls.key
```
`oline-env.sh` is built from session state: seed_peer + lt_peer + rt_peer.
```
oline push-files --episode $EID --node left-forward
oline push-files --episode $EID --node right-forward
```

### 3. Signal start
```
oline signal-start --episode $EID --node left-forward
oline signal-start --episode $EID --node right-forward
```
Forwards sync via statesync or snapshot URL. PEX=true so they use seed network too.

### 4. Wait for forward peer IDs
```
oline wait-peer --episode $EID --node left-forward --timeout 600
oline wait-peer --episode $EID --node right-forward --timeout 600
```
Writes peer IDs to session state (needed for back-injection into tackles).

### 5. Update DNS
```
oline update-dns --episode $EID --nodes left-forward,right-forward
```
Upserts Cloudflare CNAMEs:
- `RPC_D_FL` → provider hostname for left forward
- `API_D_FL`, `GRPC_D_FL`, `P2P_D_FL` (if set)
- Same for right forward (`*_FR` vars)

### 6. Back-inject forward peers into tackles
After forwards have peer IDs:
```
oline inject-peers --episode $EID --to left-tackle,right-tackle --from left-forward,right-forward
```
See tackle.md step 6.

## Outputs written to session state
```json
{
  "lf_peer": "<node_id>@<host>:<p2p_port>",
  "rf_peer": "<node_id>@<host>:<p2p_port>",
  "rpc_left":  "https://<RPC_D_FL>",
  "rpc_right": "https://<RPC_D_FR>",
  "api_left":  "https://<API_D_FL>",
  "api_right": "https://<API_D_FR>"
}
```

## Notes
- Forwards are the ONLY publicly advertised RPC/API endpoints
- gRPC on port 9090 exposed via Akash NodePort (TLS NodePort, not HTTP ingress)
- Monitors should check `catching_up=false` before routing traffic here
