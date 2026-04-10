//! Local chain environment for cw-orch integration.

use std::error::Error;

/// A local chain environment backed by ict-rs Docker containers.
///
/// Provides a configured cw-orch `Daemon` for contract deployment testing
/// alongside o-line's infrastructure deployment capabilities.
pub struct OLineTestEnv {
    pub grpc_url: String,
    pub rpc_url: String,
    pub chain_id: String,
}

impl OLineTestEnv {
    /// Spawn a local chain for testing.
    ///
    /// Uses ict-rs chain spawning under the hood. Requires Docker.
    pub async fn spawn(chain_id: &str) -> Result<Self, Box<dyn Error>> {
        // TODO: wire up ict-rs TestChain lifecycle
        Ok(Self {
            grpc_url: String::new(),
            rpc_url: String::new(),
            chain_id: chain_id.to_string(),
        })
    }

    /// Build a cw-orch Daemon connected to this environment.
    ///
    /// Returns a fully configured `Daemon` that can be used with cw-orch
    /// contract `interface` macros for deployment and interaction.
    pub fn daemon(&self) -> Result<cw_orch::prelude::Daemon, Box<dyn Error>> {
        use cw_orch::prelude::*;
        use cw_orch::environment::{ChainInfoOwned, ChainKind, NetworkInfoOwned};

        let chain_info = ChainInfoOwned {
            chain_id: self.chain_id.clone(),
            gas_denom: "uterp".into(),
            gas_price: 0.025,
            grpc_urls: vec![self.grpc_url.clone()],
            lcd_url: None,
            fcd_url: None,
            network_info: NetworkInfoOwned {
                chain_name: "terp".into(),
                pub_address_prefix: "terp".into(),
                coin_type: 118,
            },
            kind: ChainKind::Local,
        };
        Daemon::builder(chain_info)
            .build()
            .map_err(|e| e.into())
    }
}
