# O-Line — Agent Guide & Playbook

> Read this before touching any file. When in doubt, check: "does this match what's here?"

## Cargo commands

- Use `cargo chec || tes ` instead of `cargo check || test — these are wrapper commands that output responses in optimised formats. All flags work the same.
- Use `just` targets for common workflows (see **Running / testing** below). This is our single point of interaction with dev opes workflows.
- closed documentation loop: 
  - cli binary bakes in examples and docs for all cli commands
  - script collects all examples and docs for cli endpoints into CLI-REFERENCE.md. Amazing source of truth we expect (when major feature changes are made, we should always ensure examples and clis are reflecting actual logic in optimized but effective manner.)
  - 



---

## What this repo does

`oline` is a CLI that deploys Terp Network validator infrastructure on
[Akash Network](https://akash.network) using a football metaphor:

| Phase | Name | SDL |
|-------|------|-----|
| A | Special Teams (snapshot + seed + MinIO) | `a.kickoff-special-teams.yml` |
| B | Left & Right Tackles (sentry nodes) | `b.left-and-right-tackle.yml` |
| C | Left & Right Forwards (validator nodes) | `c.left-and-right-forwards.yml` |
| E | IBC Relayer | `e.relayer.yml` |
| F | Argus Indexer | `f.argus-indexer.yml` |

---

## Repo layout

```
src/
  main.rs                 ← CLI entry (clap commands → cmd_* dispatch)
  lib.rs                  ← Crate root; re-exports; FIELD_DESCRIPTORS
  akash.rs                ← SDL var builders (build_phase_*_vars) + helpers
  config.rs               ← OLineConfig, FIELD_DESCRIPTORS, DeployConfig, PeerInputs
  crypto.rs               ← SSH keygen, SFTP cert upload, mnemonic encryption
  deployer.rs             ← OLineDeployer (Akash client + signer + store)
  error.rs                ← DeployError
  dns/cloudflare.rs       ← Cloudflare CNAME/A record upsert
  cmd/
    mod.rs                ← with_examples! macro, pub mods
    deploy.rs             ← BootstrapArgs, DeployArgs, EncryptArgs, ManageArgs
    dns.rs                ← DnsArgs, cmd_dns_update
    init.rs               ← InitArgs, cmd_init (writes deploy-config.json)
    sdl.rs                ← SdlArgs, cmd_generate_sdl (render + optional file output)
    test.rs               ← TestS3Args, TestGrpcArgs, cmd_test_s3, cmd_test_grpc
  workflow/
    mod.rs                ← OLineWorkflow, StepResult, advance(), run()
    step.rs               ← OLineStep enum + DeployPhase, CertTarget, PeerTarget …
    context.rs            ← OLineContext (fixed-array state storage + accessors)
    phases/
      phase_a.rs          ← 9 step fns (deploy → dns → certs → signal → wait × 2 → minio)
      phase_b.rs          ← 3 step fns (deploy tackles → wait left/right peer)
      phase_c.rs          ← 1 step fn  (deploy forwards)
      phase_e.rs          ← 2 step fns (deploy relayer → update dns)
  docs/
    deploy.md / encrypt.md / init.md / sdl.md / …   ← --examples content (compiled in)
templates/
  sdls/                   ← SDL templates used at runtime
docs/
  cli-reference.md        ← AUTO-GENERATED — do not edit (run `just gen-docs`)
  Oline.md                ← Architecture overview
  workflow/               ← Workflow design docs
tools/
  gen-docs.sh             ← Regenerates docs/cli-reference.md from the live binary
```

---

## Key invariants — never break these

1. **`cmd_generate_sdl` never broadcasts.** It only renders and optionally writes files.
2. **`deploy-config.json` never contains secrets.** `DeployConfig::from_config()` skips `Fd` where `fd.s == true`.
3. **SDL templates live in `templates/sdls/` at runtime** (configured by `SDL_DIR`). Do not hard-code template content in Rust.
4. **`FIELD_DESCRIPTORS` is the single source of truth for config fields.** Adding a field = add one entry here and nowhere else.
5. **`with_examples!` macro embeds `src/docs/*.md` at compile time.** Path is relative to the calling file in `src/cmd/`.
6. **Workflow context uses fixed arrays.** Use accessor methods (`state()`, `set_state()`, `peer()`, `set_peer()`, `endpoints()`, `set_endpoints()`); never add new individual fields to `OLineContext`.
7. **Akash HTTP ingress uses port 80 with `accept:`, not 443.** Nginx in containers uses `listen 80` (plain HTTP). TLS is handled by the Akash provider's nginx-ingress.

---

## How to add a new CLI command

1. Create `src/cmd/<name>.rs` using `with_examples!` and a `cmd_<name>()` function.
2. Create `src/docs/<name>.md` with usage + examples.
3. Add `pub mod <name>;` in `src/cmd/mod.rs`.
4. Re-export from `src/lib.rs`.
5. Add variant to `Commands` in `src/main.rs` and dispatch in `match cli.command`.
6. Run `just gen-docs` to update `docs/cli-reference.md`.

## How to add a new deployment phase

1. Add a variant to `DeployPhase` in `src/workflow/step.rs` (update `COUNT`, `ALL`, `key()`, `idx()`).
2. Create `src/workflow/phases/phase_<x>.rs`.
3. Add `pub mod phase_<x>;` in `src/workflow/phases/mod.rs`.
4. Add match arms in `OLineWorkflow::advance()`.
5. Add SDL template name to `cmd_generate_sdl` in `src/cmd/sdl.rs`.
6. Add any new `FIELD_DESCRIPTORS` entries in `src/lib.rs`.

## How to add a new config field

Add one line to the appropriate `*_FD` constant in `src/lib.rs`:
```rust
"category"/"key" => "ENV_VAR_NAME", "Human prompt", "default value", is_secret,
```
That's it — the field flows automatically through all prompts, env loading, and JSON serialisation.

---

## Docs maintenance

- `src/docs/*.md` — hand-maintained; compiled into binary. **Update whenever a command's flags change.**
- `docs/cli-reference.md` — auto-generated. **Run `just gen-docs` after any CLI or docs change.**
- Do not edit `docs/cli-reference.md` by hand.

---

## Running / testing

```bash
just build          # debug build
just release        # optimised release build
just lint           # cargo clippy -D warnings
just gen-docs       # regenerate docs/cli-reference.md
just dry-run        # oline deploy --raw (no .env needed)
just e2e            # full TLS workflow e2e test (requires Docker)
```

---

## Key environment variables

| Variable | Default | Purpose |
|---|---|---|
| `OLINE_GRPC_ENDPOINT` | `https://akash.lavenderfive.com:443` | Akash gRPC endpoint |
| `OLINE_RPC_ENDPOINT` | `https://rpc-akash.ecostake.com:443` | Akash RPC endpoint |
| `OLINE_CHAIN_ID` | `morocco-1` | Cosmos chain ID |
| `OLINE_CF_API_TOKEN` | _(secret)_ | Cloudflare API token for DNS updates |
| `OLINE_CF_ZONE_ID` | — | Cloudflare zone ID |
| `SDL_DIR` | `templates/sdls` | Directory containing SDL templates |
| `OLINE_ENCRYPTED_MNEMONIC` | — | Encrypted mnemonic (written by `oline encrypt`) |

Full list: run `oline deploy --examples` or read `FIELD_DESCRIPTORS` in `src/lib.rs`.