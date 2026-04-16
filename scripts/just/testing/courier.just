# Courier tests
#
#   just test courier unit          — manifest parsing unit tests (courier crate)
#   just test courier compose       — compose module unit tests (o-line crate)
#   just test courier integration   — full binary lifecycle (fetch → serve → confirm → shutdown)
#   just test courier e2e           — courier + app deployment on local Akash
#   just test courier all           — everything

import '../helpers.just'

set working-directory := "../../.."

# All courier tests (no-infra)
all: unit compose integration

# Courier binary unit tests (manifest parsing, url extraction)
unit:
    cargo test -p oline-courier --bin courier

# Compose module unit tests (YAML generation, port mapping, volumes)
compose:
    cargo test --no-default-features --lib testing::compose

# Courier binary integration tests (full lifecycle: fetch → serve → confirm → shutdown)
# Builds courier binary first if needed.
integration:
    cargo build -p oline-courier
    cargo test -p oline-courier --test courier_integration -- --nocapture --test-threads=1

# Deploy courier + app to local Akash network (requires devnet + test-provider with containers)
e2e: _require-docker
    PROVIDER_SPAWN_CONTAINERS=1 \
    RUST_LOG=info,akash_deploy_rs=debug,test_provider=debug \
    cargo test --no-default-features --test unified_courier_e2e -- --nocapture --ignored --test-threads=1
