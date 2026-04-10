/// Local testing infrastructure for the o-line deployment workflow.
///
/// # Overview
///
/// The three submodules provide everything needed to test the full Phase A
/// workflow (TLS cert delivery → node start signal → peer ID polling) against
/// real `cosmos-omnibus` Docker containers running locally — the exact same
/// images that get deployed to Akash providers.
///
/// | Module    | What it does                                                      |
/// |-----------|-------------------------------------------------------------------|
/// | `docker`  | Container lifecycle — start, stop, port mapping, TCP polling      |
/// | `binary`  | Run a chain binary directly (no Docker, faster for offline tests) |
/// | `harness` | Multi-node Phase A harness — starts snapshot + seed containers    |
///
/// # Two testing modes
///
/// ## Docker mode (`harness::LocalPhaseHarness`)
///
/// Starts cosmos-omnibus containers with the same env vars as the SDL.
/// All SSH/cert/peer steps run against local ports:
///
/// ```text
/// snapshot  SSH  → 127.0.0.1:2232   RPC → 127.0.0.1:26757   P2P → 127.0.0.1:26756
/// seed      SSH  → 127.0.0.1:2233   RPC → 127.0.0.1:26767   P2P → 127.0.0.1:26766
/// ```
///
/// Advantages: tests the exact production image; validates nginx, tls-setup.sh,
/// entrypoint bootstrap, and SSH cert delivery.
///
/// ## Binary mode (`binary::NodeProcess`)
///
/// Runs the chain binary (`terpd start`) directly on the host.  No Docker,
/// no SSH setup — only the RPC/P2P layer is tested.  Useful for offline CI
/// where Docker is unavailable or for fast unit-style peer-ID polling tests.
///
/// # Local deploy mode (planned — see `plays/coach/README.md`)
///
/// `oline deploy --local` will use `LocalPhaseHarness` in place of the Akash
/// deployer for every `Deploy(phase)` step, letting you run the full
/// deployment workflow loop on a laptop before broadcasting to the network.
pub mod akash_cluster;
pub mod akash_network;
pub mod binary;
pub mod docker;
pub mod harness;
#[cfg(feature = "testing")]
pub mod ict_network;
pub mod test_provider;
pub mod ws_events;

pub use akash_cluster::AkashDevCluster;
pub use akash_network::AkashLocalNetwork;
pub use harness::LocalPhaseHarness;
#[cfg(feature = "testing")]
pub use ict_network::IctAkashNetwork;
pub use test_provider::TestProviderHandle;
pub use ws_events::{CometEvent, CometEventKind, WsEventStream};
