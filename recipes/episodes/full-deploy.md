# Episode: Full Sentry Array Deployment

**Outcome**: A complete Terp Network sentry topology live on Akash with public RPC/API endpoints.
**Wall clock**: ~90–120 min (dominated by snapshot node sync time).
**Groups**: foundation (A+B parallel) → public (C) → [relayer, indexer optional].

---

## Pre-flight

```
# 1. Verify config is loaded and mnemonic is funded
oline preflight

# 2. Probe Akash endpoints, save fastest to .env
oline endpoints

# 3. Start episode — returns episode_id (UUIDv7)
EID=$(oline session new)
echo "Episode: $EID"
```

---

## Inference 1: Populate SDL for Group A (foundation)

LLM calls `oline sdl populate` with compact var arrays for phase A and B.
Only pass `input` vars — auto/runtime vars are handled by oline.

```bash
# Phase A vars (minimal — most come from .env config)
oline sdl populate \
  --episode $EID \
  --phase a \
  --vars '[
    ["OMNIBUS_IMAGE",        "ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic"],
    ["OLINE_CHAIN_ID",       "morocco-1"],
    ["RPC_D_SNAP",           "statesync.terp.network"],
    ["P2P_D_SNAP",           "statesync-peer.terp.network"],
    ["RPC_D_SEED",           "seed.terp.network"],
    ["P2P_D_SEED",           "seed-peer.terp.network"],
    ["OLINE_SNAP_PATH",      "snapshots/terpnetwork"],
    ["OLINE_SNAP_DOWNLOAD_DOMAIN", "snapshots.terp.network"]
  ]' \
  --out /tmp/oline-a.yml

# Phase B vars (no peer IDs yet — tackles start offline)
oline sdl populate \
  --episode $EID \
  --phase b \
  --vars '[
    ["OMNIBUS_IMAGE", "ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic"]
  ]' \
  --out /tmp/oline-b.yml
```

---

## Inference 2: Deploy Group foundation (A + B in parallel)

```bash
oline deploy-group \
  --episode $EID \
  --group foundation \
  --sdls /tmp/oline-a.yml,/tmp/oline-b.yml \
  --parallel
```

This command:
1. Funds HD child accounts (index 1 for A, index 2 for B)
2. Broadcasts CreateDeployment for both SDLs simultaneously
3. Presents interactive provider selection for each unit
4. Returns deployment DSEQs + provider hosts → saved to session state

---

## Inference 3: Bootstrap Phase A

Run bootstrap steps in parallel (snapshot + seed + minio are independent):

```bash
oline bootstrap --episode $EID --node snapshot &
oline bootstrap --episode $EID --node seed &
oline bootstrap --episode $EID --node minio &
wait
```

Each `oline bootstrap` executes the recipe from `recipes/bootstrap/<node>.md`.

---

## Inference 4: Bootstrap Phase B (tackles start offline)

```bash
oline bootstrap --episode $EID --node left-tackle &
oline bootstrap --episode $EID --node right-tackle &
wait
```

Tackles start with `OLINE_OFFLINE=1` — they wait for snapshot delivery.

---

## Inference 5: Wait for snapshot node ready

Long wait — chain must fully sync:

```bash
oline wait-ready --episode $EID --node snapshot --timeout 5400
# prints progress: "catching_up=true, height=1234567/2345678 (52.6%)"
```

---

## Inference 6: Distribute snapshot to tackles

```bash
oline distribute-snapshot --episode $EID --from snapshot --to left-tackle,right-tackle
# SSH-pipes archive simultaneously to both tackles
# ~5–15 min depending on snapshot size and network
```

---

## Inference 7: Wait for tackle peer IDs

```bash
oline wait-peer --episode $EID --node left-tackle --timeout 600 &
oline wait-peer --episode $EID --node right-tackle --timeout 600 &
wait
# Writes lt_peer + rt_peer to session state
```

---

## Inference 8: Populate SDL for Group B (public forwards)

Now we have peer IDs — inject them into phase C vars:

```bash
oline sdl populate \
  --episode $EID \
  --phase c \
  --vars '[
    ["OMNIBUS_IMAGE", "ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic"],
    ["RPC_D_FL",  "rpc.terp.network"],
    ["API_D_FL",  "api.terp.network"],
    ["GRPC_D_FL", "grpc.terp.network"],
    ["RPC_D_FR",  "rpc2.terp.network"],
    ["API_D_FR",  "api2.terp.network"]
  ]' \
  --out /tmp/oline-c.yml
# oline auto-injects: seed_peer, snapshot_peer, lt_peer, rt_peer from session state
```

---

## Inference 9: Deploy Group public (C)

```bash
oline deploy-group \
  --episode $EID \
  --group public \
  --sdls /tmp/oline-c.yml
```

---

## Inference 10: Bootstrap Phase C + Update DNS + Back-inject peers

```bash
oline bootstrap --episode $EID --node left-forward &
oline bootstrap --episode $EID --node right-forward &
wait

# Wait for forward peer IDs, update DNS, back-inject into tackles
oline wait-peer --episode $EID --node left-forward --timeout 600 &
oline wait-peer --episode $EID --node right-forward --timeout 600 &
wait

oline update-dns --episode $EID --nodes left-forward,right-forward

oline inject-peers \
  --episode $EID \
  --to left-tackle,right-tackle \
  --from left-forward,right-forward
```

---

## Inference 11: Session summary

```bash
oline session summary --episode $EID
```

Output:
```
Episode: 019612ab-...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase A: oline-a-snapshot   dseq=1234  host=provider1.akash.network:32456
Phase A: oline-a-seed       dseq=1234  host=provider1.akash.network:31234
Phase A: oline-a-minio-ipfs dseq=1234  host=provider1.akash.network:30001
Phase B: oline-b-left-tackle  dseq=5678 host=provider2.akash.network:28456
Phase B: oline-b-right-tackle dseq=5678 host=provider2.akash.network:29456
Phase C: oline-c-left-forward  dseq=9012 host=provider3.akash.network:26001
Phase C: oline-c-right-forward dseq=9012 host=provider3.akash.network:26002
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RPC:  https://rpc.terp.network  https://rpc2.terp.network
API:  https://api.terp.network  https://api2.terp.network
gRPC: grpc.terp.network:9090
```

---

## Optional: Deploy Relayer

```bash
oline sdl populate --episode $EID --phase e --vars '[...]' --out /tmp/oline-e.yml
oline deploy-group --episode $EID --group relayer --sdls /tmp/oline-e.yml
oline bootstrap --episode $EID --node relayer
```

---

## Error handling

If any step fails, the episode state persists. Resume from where you left off:

```bash
oline session status --episode $EID
# shows: last completed step, what's pending, any errors

# Re-run a single step:
oline bootstrap --episode $EID --node left-tackle  # idempotent
oline wait-peer --episode $EID --node left-tackle --timeout 600
```

Session state file: `~/.config/oline/sessions/{episode_id}.json`
