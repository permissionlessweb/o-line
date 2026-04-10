//! ict-rs based Akash local network — drop-in replacement for [`AkashLocalNetwork`].
//!
//! Uses ict-rs Docker chain lifecycle instead of the shell-script-based
//! `AkashDevCluster`.  The existing `TestProviderHandle` is reused for the
//! mock provider — only the chain spawning changes.
//!
//! # Usage
//!
//! ```ignore
//! let net = IctAkashNetwork::start("my-test").await?;
//! let client = net.deployer_client().await?;
//! // ... deploy, test, etc.
//! // RAII: chain + provider cleaned up on Drop
//! ```

use crate::accounts::{child_address, derive_child_signer};
use crate::testing::test_provider::TestProviderHandle;
use std::error::Error;

/// Local Akash network backed by ict-rs Docker containers + test-provider.
///
/// Mirrors the API of `AkashLocalNetwork` so tests can switch between
/// implementations with minimal code changes.
pub struct IctAkashNetwork {
    /// Reused test-provider binary (RAII — killed on Drop).
    ///
    /// Listed before `_chain` so Rust's field-declaration-order Drop kills
    /// the provider BEFORE tearing down the chain containers.  Otherwise the
    /// provider loses its RPC connection and polls "no open orders" until
    /// the chain cleanup finishes.
    _provider: TestProviderHandle,
    /// ict-rs spawned Akash chain (RAII — containers cleaned up on Drop).
    _chain: ict_rs::chain::akash::SpawnedAkashChain,
    pub rpc: String,
    pub grpc: String,
    pub rest: String,
    pub provider_uri: String,
    pub chain_id: String,
    pub faucet_mnemonic: String,
    pub deployer_mnemonic: String,
    pub provider_address: String,
}

impl IctAkashNetwork {
    /// Start a local Akash network with a unique test name.
    ///
    /// Each parallel test MUST use a different `test_name` to avoid Docker
    /// container and provider port collisions.
    pub async fn start(test_name: &str) -> Result<Self, Box<dyn Error>> {
        let faucet_mnemonic = std::env::var("FAUCET_MNEMONIC")
            .unwrap_or_else(|_| "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());

        let deployer_mnemonic = std::env::var("DEPLOYER_MNEMONIC")
            .unwrap_or_else(|_| "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());

        // 1. Derive provider address at HD index 99 (avoids collision with deployer at 0).
        let provider_signer = derive_child_signer(&deployer_mnemonic, 99)
            .map_err(|e| format!("derive provider address: {}", e))?;
        let provider_address = child_address(&provider_signer, "akash");

        // 2. Spawn Akash chain with provider pre-funded at genesis.
        //    uact cannot be bank-sent at runtime (BME SendRestrictionFn), so the
        //    provider must have uact from block 0 to pay bid deposits.
        let chain = ict_rs::chain::akash::spawn_akash_chain_with_accounts(
            test_name,
            &faucet_mnemonic,
            &[(&provider_address, 500_000_000, 100_000_000)], // 500M uact + 100M uakt
        )
        .await
        .map_err(|e| format!("ict-rs spawn_akash_chain: {}", e))?;

        let rpc = chain.rpc.clone();
        let grpc = chain.grpc.clone();
        let rest = chain.rest.clone();
        let chain_id = chain.chain_id.clone();
        let faucet_mnemonic = chain.faucet_mnemonic.clone();

        tracing::info!(
            provider = %provider_address,
            "provider pre-funded at genesis (500M uact + 100M uakt)"
        );

        // 3. Start test-provider binary.
        let provider_port = pick_free_port()?;
        let provider = TestProviderHandle::start(
            &deployer_mnemonic,
            &rpc,
            &grpc,
            &rest,
            provider_port,
        )
        .await
        .map_err(|e| format!("TestProviderHandle::start: {}", e))?;
        let provider_uri = format!("https://localhost:{}", provider_port);

        tracing::info!(
            test_name = %test_name,
            rpc = %rpc, grpc = %grpc, rest = %rest,
            provider_uri = %provider_uri,
            chain_id = %chain_id,
            "IctAkashNetwork started"
        );

        Ok(Self {
            _provider: provider,
            _chain: chain,
            rpc,
            grpc,
            rest,
            provider_uri,
            chain_id,
            faucet_mnemonic,
            deployer_mnemonic,
            provider_address,
        })
    }

    /// Fund an address from the faucet account.
    pub async fn faucet(&self, address: &str, amount_uakt: u128) -> Result<(), Box<dyn Error>> {
        let client = self.client_from_mnemonic(&self.faucet_mnemonic).await?;
        client
            .bank_send(address, amount_uakt, "uakt")
            .await
            .map_err(|e| format!("faucet bank_send: {}", e))?;
        Ok(())
    }

    /// Fund multiple addresses sequentially from the faucet account.
    ///
    /// Sequential sends avoid sequence conflicts on the faucet account.
    pub async fn faucet_many(
        &self,
        addresses: &[&str],
        amount_uakt: u128,
    ) -> Result<(), Box<dyn Error>> {
        for addr in addresses {
            self.faucet(addr, amount_uakt).await?;
        }
        Ok(())
    }

    /// Build a deployer AkashClient from the deployer mnemonic.
    pub async fn deployer_client(
        &self,
    ) -> Result<akash_deploy_rs::AkashClient<akash_deploy_rs::FileBackedStorage>, Box<dyn Error>>
    {
        self.client_from_mnemonic(&self.deployer_mnemonic).await
    }

    /// Build an AkashClient for any mnemonic.
    pub async fn client_from_mnemonic(
        &self,
        mnemonic: &str,
    ) -> Result<akash_deploy_rs::AkashClient<akash_deploy_rs::FileBackedStorage>, Box<dyn Error>>
    {
        let client = akash_deploy_rs::AkashClient::new_from_mnemonic(
            mnemonic,
            &self.rpc,
            &self.grpc,
        )
        .await
        .map_err(|e| format!("AkashClient::new_from_mnemonic: {}", e))?;
        let client = client.with_rest(&self.rest);
        Ok(client)
    }

    // ── Accessor methods ───────────────────────────────────────────────

    pub fn rpc(&self) -> &str {
        &self.rpc
    }

    pub fn grpc(&self) -> &str {
        &self.grpc
    }

    pub fn rest(&self) -> &str {
        &self.rest
    }

    pub fn provider_uri(&self) -> &str {
        &self.provider_uri
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub fn provider_address(&self) -> &str {
        &self.provider_address
    }
}

/// Bind to port 0, read the OS-assigned port, and close the socket.
fn pick_free_port() -> Result<u16, Box<dyn Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}
