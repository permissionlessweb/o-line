# O-Line Architecture

Package: `o-line-sdl`. Binaries: `oline`, `test-provider`.

## Key Patterns

**Step machine** (`src/workflow/`): Each step does work via `w.ctx.deployer.*`, writes to `w.ctx.*`, sets `w.step = <next>`, returns `Ok(StepResult::Continue)`. See `step.rs` for the full enum.

**Phase functions** live in `src/workflow/phases/{a,b,c,e}.rs`. Parallel orchestration in `phases/parallel.rs`.

**OLineDeployer** (`src/deployer.rs`): Wraps `AkashClient` from akash-deploy-rs. Needs trait imports:
```rust
use akash_deploy_rs::{AkashBackend, DeploymentStore};
```

**SDL variable builders** (`src/akash.rs`): `build_phase_a_vars()`, `build_phase_b_vars()`, `build_phase_c_vars()`. Templates use `${VAR}` syntax via `substitute_template_raw`.

**DNS KeyStore** (`src/keys/`): AES-256-GCM + Argon2id, domain-keyed with longest-suffix matching. Stored at `~/.oline/keys.enc`.

**Sessions** (`src/sessions.rs`): Track parallel deploy state. Stored at `~/.oline/sessions/<id>/session.json`.

## Gotchas

- `akash-deploy-rs` uses local path dep `../akash-deploy-rs` — not a git dep
- Akash gRPC deployment queries use `v1beta4` (NOT v1beta5)
- `load_dotenv` reads `OLINE_ENV_FILE` (defaults to `.env`, NOT `.env.local.mainnet`)
- `OLINE_OFFLINE=1`: Sentries start sshd and wait; receive ALL data via SFTP
- Bootstrap entrypoint is pushed via SFTP, not baked into the Docker image

## Feature Flags

- `testing`: ict-rs integration (`src/testing/ict_network.rs`)
- `interface`: cw-orch adapter (`src/interface/`)
