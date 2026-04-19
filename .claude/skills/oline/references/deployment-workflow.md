# Deployment Workflow

## Phases

| Phase | Name | SDL templates | Purpose |
|-------|------|---------------|---------|
| A | Special Teams | `templates/sdls/a.*.yml` | Snapshot + seed + MinIO-IPFS |
| B | Tackles | `templates/sdls/b.*.yml` | Left/right sentries |
| C | Forwards | `templates/sdls/c.*.yml` | Additional sentries |
| E | Relayer | `templates/sdls/e.*.yml` | IBC relayer (optional) |

B/C deploy with empty peer vars (`SNAPSHOT_MODE=sftp`), receive snapshot and peers via SSH later.

## Parallel Step Machine

HD-derived child accounts avoid tx sequence conflicts:

```
1. FundChildAccounts    -- master multi-send -> N children at m/44'/118'/0'/0/{i}
2. DeployAllUnits       -- concurrent MsgCreateDeployment (one per child)
3. SelectAllProviders   -- interactive or auto (OLINE_AUTO_SELECT=1)
4. UpdateAllDns         -- parallel Cloudflare CNAME/A updates
5. WaitSnapshotReady    -- poll Phase A until synced
6. DistributeSnapshot   -- SSH-stream archive to B/C/E
7. SignalAllNodes       -- push TLS certs as startup sync signal
8. InjectPeers          -- SSH-push peer env vars to B/C/E
9. WaitAllPeers         -- poll until peer connected
```

Phase A detailed: `DeploySpecialTeams -> UpdateDnsPhaseA -> PushCertsSnapshot -> SignalSnapshotStart -> WaitSnapshotPeer -> PushCertsSeed -> SignalSeedStart -> PushCertsMinio -> WaitSeedPeer`

## TLS Cert Delivery

Certs are a **startup sync signal**, not for TLS termination (Akash ingress handles TLS).

1. SSH keypair generated in `build_phase_a_vars` -> pubkey as `SSH_PUBKEY` env in SDL
2. `push_tls_certs_sftp()` uploads cert+key to `/tmp/tls/`
3. Container checks cert presence -> triggers `OLINE_PHASE=start`

## Port Conventions (Phase A)

| Port | Usage |
|------|-------|
| 26656 | P2P — NodePort, raw TCP |
| 26657 | RPC — NodePort, health checks |
| 80 | HTTP ingress with `accept:` domains |
| 22 | SSH — SFTP cert delivery |

## Funding

`OLINE_FUNDING_METHOD=hd:4:5000000` (derive 4 children, fund each 5M uakt) or `direct` or `master`.

After workflow: `oline manage drain` returns child funds to master.
