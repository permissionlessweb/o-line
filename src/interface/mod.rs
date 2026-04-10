//! cw-orchestrator compatible testing interface.
//!
//! Feature-gated by `interface`. Provides helpers for terp.network
//! and other test suites to spawn local chains and invoke oline.

mod binary;
mod env;

pub use binary::OLineBinary;
pub use env::OLineTestEnv;
