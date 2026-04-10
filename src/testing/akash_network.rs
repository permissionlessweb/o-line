//! Canonical local Akash network for integration tests.
//!
//! [`AkashLocalNetwork`] is the single entry point for any test that needs to
//! deploy against a real (but local) Akash network.  It composes two pieces:
//!
//! | Piece                | What it does                                                |
//! |----------------------|-------------------------------------------------------------|
//! | [`AkashDevCluster`]  | Starts/resets the Akash node **and** the test-provider via  |
//! |                      | `akash-devnet.sh reset` (fresh ledger, sequence = 0).       |
//! | Faucet `AkashClient` | Funds arbitrary addresses on demand via `bank_send`.        |
//!
//! The devnet script manages the `test-provider` binary (start + stop); there is
//! no separate Rust-owned provider subprocess.  Both components clean up
//! automatically when the handle is dropped.
//!
//! # Quickstart
//!
//! ```rust,ignore
//! #[tokio::test]
//! #[ignore] // requires: just akash-setup  (one-time)
//! async fn test_my_deployment() {
//!     let net = AkashLocalNetwork::start().await.expect("network start");
//!
//!     // Fund the test deployer with 50 AKT
//!     let deployer = net.deployer_client().await.expect("deployer");
//!     net.faucet(deployer.address(), 50_000_000).await.expect("faucet");
//!
//!     // Use the deployer to create a deployment…
//!     // net.rpc / net.grpc / net.rest / net.provider_uri / net.chain_id
//!     // are all pre-populated.
//!
//! } // Drop → provider killed, cluster stopped
//! ```
//!
//! # One-time setup
//!
//! ```bash
//! just akash-setup          # clone provider repo, build bins, create Kind cluster
//! cargo build --bin test-provider
//! ```
//!
//! # Faucet design
//!
//! The Akash dev cluster pre-funds two genesis accounts:
//!
//! - **faucet** (`faucet_mnemonic`): large balance — used only for funding others.
//! - **deployer** (`deployer_mnemonic`): moderate balance — used by tests to
//!   create deployments.
//!
//! The mock provider registers under its own key (`provider_mnemonic`, which may
//! equal `faucet_mnemonic` when no dedicated `provider.json` key-secret exists).
//! `start()` resets the chain to genesis before each run, so all sequences start
//! at 0 and no stale orders from previous runs can interfere with faucet sends.

use std::sync::Arc;
use tokio::sync::Mutex;

use akash_deploy_rs::AkashClient;
use reqwest;

use super::AkashDevCluster;

/// A fully-running local Akash network — node + test-provider + faucet.
///
/// All components are shut down automatically on `Drop`.
pub struct AkashLocalNetwork {
    /// Keeps the Akash node and test-provider alive; `Drop` calls `akash-devnet.sh stop`.
    _cluster: AkashDevCluster,
    /// Pre-built client for the faucet account — used by [`Self::faucet`].
    ///
    /// Wrapped in `Arc<Mutex>` so concurrent `faucet()` calls on different
    /// tokio tasks serialize their bank_sends rather than racing on the same
    /// cached account sequence number.
    faucet_client: Arc<Mutex<AkashClient>>,

    // ── Public endpoint / identity fields ─────────────────────────────────
    /// Akash node RPC endpoint, e.g. `http://127.0.0.1:26657`.
    pub rpc: String,
    /// Akash node gRPC endpoint, e.g. `http://127.0.0.1:9090`.
    pub grpc: String,
    /// Akash node REST endpoint, e.g. `http://127.0.0.1:1317`.
    pub rest: String,
    /// Mock provider HTTPS endpoint, e.g. `https://127.0.0.1:8443`.
    pub provider_uri: String,
    /// Chain-id of the running node, e.g. `"local"`.
    pub chain_id: String,
    /// Mnemonic for a pre-funded deployer account.
    ///
    /// Use this with [`Self::deployer_client`] to create an `AkashClient`
    /// that can broadcast deployment transactions.
    pub deployer_mnemonic: String,
    /// Mnemonic for the faucet genesis account.
    ///
    /// Prefer [`Self::faucet`] over constructing your own client from this
    /// mnemonic — it avoids sequence-number conflicts with the mock provider.
    pub faucet_mnemonic: String,
    /// Bech32 address of the registered mock provider.
    pub provider_address: String,
}

impl AkashLocalNetwork {
    /// Start a local Akash network and block until all components are ready.
    ///
    /// # Sequence of events
    ///
    /// 1. `AkashDevCluster::start_fresh()` — resets chain state to genesis
    ///    (`akash unsafe-reset-all`), then starts node + test-provider and
    ///    waits for both ports to be reachable.  All account sequences = 0.
    /// 2. Build a faucet `AkashClient` from `faucet_mnemonic`.
    ///
    /// Because the chain is reset to genesis, the provider's registration tx
    /// is the first tx in history.  The faucet and provider use independent
    /// accounts (when a dedicated `provider.json` key-secret exists), so there
    /// are no sequence conflicts.  Even when both share the `faucet_mnemonic`,
    /// the fresh ledger ensures no stale orders trigger bid-engine races.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if any step fails.  Common causes:
    /// - `just akash-setup` was never run (Kind cluster missing)
    /// - `cargo build --bin test-provider` was never run
    pub async fn start() -> Result<Self, String> {
        // ── 1. Reset chain state and start the cluster ─────────────────────
        //
        // start_fresh() = stop + akash unsafe-reset-all + wait.
        // This gives us a clean ledger (sequence=0 for all accounts) and a
        // freshly-running test-provider managed by the devnet script.
        eprintln!("[akash-local] resetting chain state and starting cluster…");
        let cluster = AkashDevCluster::start_fresh()
            .map_err(|e| format!("AkashDevCluster::start_fresh failed: {}", e))?;

        eprintln!(
            "[akash-local] cluster ready  rpc={}  chain={}",
            cluster.rpc, cluster.chain_id
        );

        // ── 1b. Wait for provider /readiness (PROVIDER_REGISTERED=true) ────
        //
        // cmd_wait only checks TCP port connectivity — the test-provider HTTPS
        // server starts BEFORE on-chain registration completes (so the port
        // comes up while the provider has no balance and can't register yet).
        // Polling /readiness here blocks until MsgCreateProvider is accepted
        // on-chain, so deployment orders won't appear before the provider can
        // bid on them.
        //
        // The provider binary retries registration for up to 60 s (12 × 5 s).
        // We give it 90 s to handle slow CI systems.
        {
            let readiness_url = format!("{}/readiness", cluster.provider);
            let http = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            eprintln!(
                "[akash-local] waiting for provider /readiness ({})…",
                readiness_url
            );
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
            let mut registered = false;
            while std::time::Instant::now() < deadline {
                match http.get(&readiness_url).send().await {
                    Ok(r) if r.status().is_success() => {
                        registered = true;
                        eprintln!("[akash-local] provider registered and ready ✓");
                        break;
                    }
                    Ok(r) => {
                        eprintln!(
                            "[akash-local] /readiness → {} (not yet registered, retrying…)",
                            r.status()
                        );
                    }
                    Err(e) => {
                        eprintln!("[akash-local] /readiness error: {} — retrying…", e);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            if !registered {
                // Non-fatal: log a warning and continue. The provider might still
                // succeed in registration; this is just a best-effort wait.
                eprintln!(
                    "[akash-local] WARNING: provider /readiness did not return 200 within 90 s \
                     — proceeding anyway (bids may fail if provider is unregistered)"
                );
            }
        }

        // Derive the provider's on-chain address from its mnemonic.
        let provider_address = crate::accounts::child_address_str(&cluster.provider_mnemonic, 0, "akash")
            .unwrap_or_else(|_| "<unknown>".into());
        eprintln!("[akash-local] provider addr={}", provider_address);

        // ── 2. Build faucet client ─────────────────────────────────────────
        eprintln!("[akash-local] initialising faucet client…");
        let faucet_client = AkashClient::new_from_mnemonic(
            &cluster.faucet_mnemonic,
            &cluster.rpc,
            &cluster.grpc,
        )
        .await
        .map_err(|e| format!("faucet AkashClient init failed: {}", e))?;

        // ── 3. Fund provider if it uses a separate key ─────────────────────
        //
        // After `unsafe-reset-all`, non-genesis accounts have 0 balance.  The
        // devnet's provider key may not be included in genesis (it's typically
        // funded by a setup tx that is wiped on reset).  Fund it from the faucet
        // so the test-provider can pay gas for MsgCreateProvider + MsgCreateBid.
        //
        // The test-provider's registration retry loop (12 × 5 s = 60 s) will
        // pick up the funding and complete registration before orders appear.
        let faucet_address = faucet_client.address().to_string();
        let rest_url = cluster.rest.clone();
        if provider_address != faucet_address && provider_address != "<unknown>" {
            eprintln!(
                "[akash-local] provider has separate key — funding {} (100 AKT) from faucet…",
                provider_address
            );
            match faucet_client
                .bank_send(&provider_address, 100_000_000, "uakt")
                .await
            {
                Ok(r) if r.code == 0 => {
                    eprintln!(
                        "[akash-local] provider funded (tx={}) — polling balance for commit…",
                        r.hash
                    );
                    // Poll REST until the balance is confirmed (max 30 s).
                    // This is cheaper than a fixed sleep and adapts to real
                    // block times rather than guessing at a constant.
                    let balance_url = format!(
                        "{}/cosmos/bank/v1beta1/balances/{}/by_denom?denom=uakt",
                        rest_url.trim_end_matches('/'),
                        provider_address
                    );
                    let http = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(5))
                        .build()
                        .unwrap_or_else(|_| reqwest::Client::new());
                    let poll_deadline = tokio::time::Instant::now()
                        + tokio::time::Duration::from_secs(30);
                    loop {
                        match http.get(&balance_url).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                if let Ok(json) = resp.json::<serde_json::Value>().await {
                                    let bal = json
                                        .pointer("/balance/amount")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| s.parse::<u128>().ok())
                                        .unwrap_or(0);
                                    if bal > 0 {
                                        eprintln!(
                                            "[akash-local] provider balance confirmed: {} uakt",
                                            bal
                                        );
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                        if tokio::time::Instant::now() >= poll_deadline {
                            eprintln!(
                                "[akash-local] WARNING: provider balance not confirmed within 30 s"
                            );
                            break;
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
                Ok(r) => {
                    eprintln!(
                        "[akash-local] WARNING: provider fund tx non-zero code={} log={}",
                        r.code, r.raw_log
                    );
                }
                Err(e) => {
                    eprintln!("[akash-local] WARNING: provider fund failed: {}", e);
                }
            }
        } else {
            eprintln!("[akash-local] provider uses faucet key — no separate funding needed.");
        }

        // ── 4. Rebuild faucet client to pick up fresh account sequence ────────
        //
        // The faucet_client was created before the provider funding tx.
        // Layer-climb caches the account sequence at construction time (seq=0).
        // After the provider funding tx commits (chain seq=1), the cached client
        // would still use seq=0 for the next tx → "sequence mismatch" error.
        // Recreating the client forces a fresh sequence query from the chain.
        eprintln!("[akash-local] refreshing faucet client (post-fund sequence sync)…");
        let faucet_client = AkashClient::new_from_mnemonic(
            &cluster.faucet_mnemonic,
            &cluster.rpc,
            &cluster.grpc,
        )
        .await
        .map_err(|e| format!("faucet AkashClient refresh failed: {}", e))?;

        let rpc = cluster.rpc.clone();
        let grpc = cluster.grpc.clone();
        let rest = cluster.rest.clone();
        let provider_uri = cluster.provider.clone();
        let chain_id = cluster.chain_id.clone();
        let deployer_mnemonic = cluster.deployer_mnemonic.clone();
        let faucet_mnemonic = cluster.faucet_mnemonic.clone();

        Ok(Self {
            _cluster: cluster,
            faucet_client: Arc::new(Mutex::new(faucet_client)),
            rpc,
            grpc,
            rest,
            provider_uri,
            chain_id,
            deployer_mnemonic,
            faucet_mnemonic,
            provider_address,
        })
    }

    // ── Faucet ─────────────────────────────────────────────────────────────

    /// Send `amount_uakt` from the faucet account to `address`.
    ///
    /// The denom is always `"uakt"`.  One call per address keeps sequence
    /// numbers predictable; use [`Self::faucet_many`] for bulk funding.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// net.faucet("akash1xyz…", 10_000_000).await?; // 10 AKT
    /// ```
    pub async fn faucet(&self, address: &str, amount_uakt: u128) -> Result<(), String> {
        tracing::info!(to = address, amount_uakt, "faucet: sending uakt");
        let client = self.faucet_client.lock().await;
        let r = client
            .bank_send(address, amount_uakt, "uakt")
            .await
            .map_err(|e| format!("faucet bank_send failed: {}", e))?;
        drop(client);
        if r.code != 0 {
            return Err(format!(
                "faucet tx rejected  code={}  log={}",
                r.code, r.raw_log
            ));
        }
        tracing::info!(to = address, tx = %r.hash, "faucet: tx confirmed");
        Ok(())
    }

    /// Fund multiple addresses sequentially from the faucet.
    ///
    /// Sequential (not batched) so that each tx has a fresh sequence number.
    pub async fn faucet_many(
        &self,
        addresses: &[&str],
        amount_uakt: u128,
    ) -> Result<(), String> {
        for addr in addresses {
            self.faucet(addr, amount_uakt).await?;
        }
        Ok(())
    }

    // ── Client builders ────────────────────────────────────────────────────

    /// Build an [`AkashClient`] from [`Self::deployer_mnemonic`].
    ///
    /// The deployer account is pre-funded in genesis and is separate from the
    /// faucet account, so deployment txs don't conflict with faucet sends.
    pub async fn deployer_client(&self) -> Result<AkashClient, String> {
        AkashClient::new_from_mnemonic(&self.deployer_mnemonic, &self.rpc, &self.grpc)
            .await
            .map_err(|e| format!("deployer AkashClient init failed: {}", e))
    }

    /// Build an [`AkashClient`] from an arbitrary mnemonic against this network.
    ///
    /// Useful for child accounts derived from the deployer mnemonic (HD indices
    /// > 0) — the caller is responsible for funding the account first via
    /// [`Self::faucet`].
    pub async fn client_from_mnemonic(&self, mnemonic: &str) -> Result<AkashClient, String> {
        AkashClient::new_from_mnemonic(mnemonic, &self.rpc, &self.grpc)
            .await
            .map_err(|e| format!("AkashClient init failed: {}", e))
    }

    // ── Convenience accessors ──────────────────────────────────────────────

    /// RPC endpoint, e.g. `http://127.0.0.1:26657`.
    pub fn rpc(&self) -> &str {
        &self.rpc
    }

    /// gRPC endpoint, e.g. `http://127.0.0.1:9090`.
    pub fn grpc(&self) -> &str {
        &self.grpc
    }

    /// REST endpoint, e.g. `http://127.0.0.1:1317`.
    pub fn rest(&self) -> &str {
        &self.rest
    }

    /// Provider HTTPS URI, e.g. `https://127.0.0.1:8443`.
    pub fn provider_uri(&self) -> &str {
        &self.provider_uri
    }

    /// Chain-id of the running node, e.g. `"local"`.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Bech32 address of the registered mock provider.
    pub fn provider_address(&self) -> &str {
        &self.provider_address
    }
}
