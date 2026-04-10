# Testnet deploy tests (testnet_deploy.rs)
#
#   just test testnet render   — SDL template rendering (no infra)
#   just test testnet deploy   — full Akash deploy lifecycle (requires devnet + localterp image)
#   just test testnet all      — everything

import '../helpers.just'

set working-directory := "../../.."

# All testnet tests (render + deploy)
all: render deploy

# SDL template rendering — no infrastructure required
render:
    cargo test --features testing --test testnet_deploy -- test_testnet_sdl_render --nocapture

# Full testnet deploy lifecycle on local Akash devnet
deploy: _require-docker
    RUST_LOG=info,akash_deploy_rs=debug,test_provider=debug,ict_rs=debug \
      cargo test --features testing --test testnet_deploy -- test_testnet_deploy_akash --nocapture --ignored --test-threads=1
