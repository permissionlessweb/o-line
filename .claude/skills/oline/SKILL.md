---
name: oline
description: >
  O-line CLI: parallel Akash validator deployment (phases A/B/C/E),
  HD key derivation, DNS KeyStore, MinIO-IPFS sites, SSH node management,
  snapshot distribution, pfSense firewall/VPN, OCI registry, IBC relayer,
  TUI, and testnet bootstrapping. Built on akash-deploy-rs.
  Use for: "o-line", "oline", "validator deploy", "sentry deploy",
  "parallel deployment", "akash deploy workflow", "oline manage",
  "oline dns", "oline sites", "oline bootstrap", "oline refresh".
---

# O-Line CLI

Deployment orchestrator for Cosmos validator sentry arrays on Akash Network.

## Critical Rules

**NEVER edit o-line locally and rsync to groot2.** All edits directly on groot2 `~/abstract/bme/o-line/` via SSH.

**NEVER restart or remove a syncing container.** Syncing takes hours/days.

**NEVER hallucinate config values.** Read peers, seeds, URLs from `.env` or live RPC.

## Skill Contents

- `references/cli-reference.md` -- Commands, flags, non-interactive mode
- `references/deployment-workflow.md` -- Step machine, phases, HD funding, TLS sync
- `references/architecture.md` -- Key patterns and gotchas (not a file listing)
- `references/configuration.md` -- Env vars, DNS KeyStore
- `rules/networking.md` -- Akash TLS ingress, P2P transport, openssh gotchas
- `rules/testing.md` -- Docker, Akash dev cluster, local-terp, test-provider
- `rules/devops/justfile-recipes.md` -- Build, test, deploy recipes
- `rules/devops/doc-generation.md` -- CLI reference generation
