# Testing Infrastructure

## Test Hierarchy

| Test | File | What it tests |
|------|------|---------------|
| Single-node E2E | `tests/e2e_workflow.rs` | Basic deployment workflow |
| Phase A multi-node | `tests/local_phase_a.rs` | SSH delivery + signal + peer ID polling |
| Full local network | `tests/local_network_e2e.rs` | local-terp + snapshot + seed containers |
| Akash parallel E2E | `tests/akash_parallel.rs` | Full parallel deploy on Akash dev cluster |

## Docker Testing (src/testing/)

- `docker.rs`: `ContainerSpec` (with `extra_hosts`), `ContainerHandle` (RAII Drop), `run_container`, `wait_for_tcp`
- `harness.rs`: `LocalPhaseHarness::start_phase_a()` -- snapshot+seed containers
- `binary.rs`: `NodeConfig`, `NodeProcess` -- run chain binary directly without Docker

### macOS vs Linux Docker

- macOS: `host.docker.internal` is automatic, do NOT add `--add-host` (causes exit 125)
- Linux: needs `--add-host host.docker.internal:host-gateway`, use `cfg!(target_os = "linux")` guard

## Akash Dev Cluster (data/akash-devnet.sh)

Shell script: `data/akash-devnet.sh [setup|start|wait|stop|clean|status|info|faucet|check]`

Rust wrapper: `src/testing/akash_cluster.rs` -- `AkashDevCluster::start()` parses JSON from `wait`

**Critical**: `AKASH_NODE=http://localhost:26657` resolves to `::1` (IPv6) on macOS -> silent failure.
Fix: pass `AKASH_NODE=http://127.0.0.1:${NODE_RPC_PORT}` as make command-line var.

## test-provider (src/bin/test_provider.rs)

Rust binary replacing Kind-based provider-services. No Kubernetes required.

- Bid engine: gRPC `market::v1beta5` orders query (REST returns HTTP 501)
- HTTPS server: self-signed cert (rcgen), TLS (tokio-rustls), manual HTTP/1.1
- `TestProviderHandle::start(mnemonic, rpc, grpc, rest, port)` -- RAII Drop kills subprocess

## AkashLocalNetwork (src/testing/akash_network.rs)

Single struct wrapping cluster + provider + faucet client.

```rust
let net = AkashLocalNetwork::start().await;
net.faucet(address, amount_uakt).await;
let client = net.deployer_client().await;
```

## local-terp

Container: `terpnetwork/terp-core:localterp`
Chain: `120u-1`, denoms: `uterp`/`uthiol`
Faucet: `GET http://127.0.0.1:5000/faucet?address=<addr>`
Keys: `--keyring-backend test`

## ict-rs Integration

Feature flag `testing` enables `IctAkashNetwork` in `src/testing/ict_network.rs`.

## Env Vars for Testing

| Variable | Description |
|----------|-------------|
| `OLINE_NON_INTERACTIVE=1` | Auto-accept all prompts |
| `OLINE_TEST_STOP_AFTER_DEPLOY=1` | Stop after DeployAllUnits |
| `SDL_DIR=tests/fixtures/sdls` | Use minimal test SDLs |
| `E2E_OMNIBUS_IMAGE` | arm64-compatible test image |
| `CARGO_BIN_EXE_oline` | Compile-time path to oline binary |

## Justfile Test Recipes

```bash
just e2e              # Single-node E2E
just e2e-multi        # Phase A multi-node
just e2e-network      # Full local network
just e2e-akash-parallel  # Akash parallel deploy
```
