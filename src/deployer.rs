use crate::{
    config::OLineConfig,
    providers::TrustedProviderStore,
};
use akash_deploy_rs::{
    AkashBackend, AkashClient, Bid, DeployError, DeploymentState, DeploymentStore,
    DeploymentWorkflow, FileDeploymentStore, InputRequired, KeySigner, ProviderInfo,
    ServiceEndpoint, Step, StepResult as AkashStepResult, WorkflowConfig,
};
use bip32::DerivationPath;
use std::{collections::HashMap, error::Error, io, str::FromStr};

/// Context for AuthZ-delegated deployments.
///
/// When present, the deployer wallet (grantee) executes operations on behalf
/// of the main wallet (granter). All deployment messages are wrapped in
/// `MsgExec` and fees are paid by the granter via FeeGrant.
#[derive(Clone, Debug)]
pub struct AuthzContext {
    /// The main wallet address that owns deployments.
    pub granter_address: String,
}

pub struct OLineDeployer {
    pub client: AkashClient,
    pub signer: KeySigner,
    pub config: OLineConfig,
    pub password: String,
    pub deployment_store: FileDeploymentStore,
    /// When set, this deployer operates via AuthZ delegation.
    pub authz_context: Option<AuthzContext>,
}

impl OLineDeployer {
    pub async fn new(config: OLineConfig, password: String) -> Result<Self, DeployError> {
        let rpc = config.val("OLINE_RPC_ENDPOINT");
        let grpc = config.val("OLINE_GRPC_ENDPOINT");
        let rest = config.val("OLINE_REST_ENDPOINT");

        let mut client = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            AkashClient::new_from_mnemonic(&config.mnemonic, &rpc, &grpc),
        )
        .await
        .map_err(|_| {
            DeployError::InvalidState(format!(
                "Timed out connecting to Akash RPC ({}).\n  \
                 Run `oline endpoints` to find a working endpoint and save it to .env.",
                rpc
            ))
        })??;

        if !rest.is_empty() {
            client = client.with_rest(rest);
        }

        Ok(Self {
            client,
            signer: KeySigner::new_mnemonic_str(&config.mnemonic, None)
                .map_err(|e| DeployError::Signer(format!("Failed to create signer: {}", e)))?,
            config,
            password,
            deployment_store: FileDeploymentStore::new_default().await?,
            authz_context: None,
        })
    }

    /// Create a deployer backed by a child HD account at BIP44 index `hd_index`.
    ///
    /// The child account signs independently from the master, eliminating
    /// sequence conflicts during parallel deployment.
    pub async fn new_child(
        config: OLineConfig,
        password: String,
        hd_index: u32,
    ) -> Result<Self, DeployError> {
        let rpc = config.val("OLINE_RPC_ENDPOINT");
        let grpc = config.val("OLINE_GRPC_ENDPOINT");
        let rest = config.val("OLINE_REST_ENDPOINT");

        let mut client = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            AkashClient::new_from_mnemonic_at_index(&config.mnemonic, hd_index, &rpc, &grpc),
        )
        .await
        .map_err(|_| {
            DeployError::InvalidState(format!(
                "Timed out connecting to Akash RPC (child {}, {})",
                hd_index, rpc
            ))
        })??;

        if !rest.is_empty() {
            client = client.with_rest(rest);
        }

        let path = DerivationPath::from_str(&format!("m/44'/118'/0'/0/{}", hd_index))
            .map_err(|e| DeployError::Signer(format!("Bad HD path: {}", e)))?;

        Ok(Self {
            client,
            signer: KeySigner::new_mnemonic_str(&config.mnemonic, Some(&path))
                .map_err(|e| DeployError::Signer(format!("Child signer {}: {}", hd_index, e)))?,
            config,
            password,
            deployment_store: FileDeploymentStore::new_default().await?,
            authz_context: None,
        })
    }

    /// Create a deployer using AuthZ delegation.
    ///
    /// The deployer wallet (grantee) signs transactions, but all deployment
    /// messages are wrapped in `MsgExec` and executed on behalf of the granter.
    /// No password is needed — the deployer mnemonic is stored unencrypted.
    pub async fn new_authz(
        config: OLineConfig,
        granter_address: String,
    ) -> Result<Self, DeployError> {
        let rpc = config.val("OLINE_RPC_ENDPOINT");
        let grpc = config.val("OLINE_GRPC_ENDPOINT");
        let rest = config.val("OLINE_REST_ENDPOINT");

        let mut client = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            AkashClient::new_from_mnemonic(&config.mnemonic, &rpc, &grpc),
        )
        .await
        .map_err(|_| {
            DeployError::InvalidState(format!(
                "Timed out connecting to Akash RPC ({}).",
                rpc
            ))
        })??;

        if !rest.is_empty() {
            client = client.with_rest(rest);
        }

        // Enable AuthZ wrapping on all broadcast calls
        client = client.with_authz_granter(&granter_address);

        Ok(Self {
            client,
            signer: KeySigner::new_mnemonic_str(&config.mnemonic, None)
                .map_err(|e| DeployError::Signer(format!("Failed to create authz signer: {}", e)))?,
            config,
            password: String::new(),
            deployment_store: FileDeploymentStore::new_default().await?,
            authz_context: Some(AuthzContext { granter_address }),
        })
    }

    /// Returns the effective owner address for deployments.
    ///
    /// With AuthZ, the granter owns deployments. Without, it's the signer's address.
    pub fn deployment_owner(&self) -> String {
        if let Some(ref ctx) = self.authz_context {
            ctx.granter_address.clone()
        } else {
            self.client.address()
        }
    }

    /// Pre-flight connectivity check: query providers list + open bids for this
    /// owner via REST.  Logs results so the operator can confirm the API is
    /// reachable and see any existing open bids before starting the deployment
    /// lifecycle on mainnet.
    ///
    /// Returns an error if the REST endpoint is not configured or unreachable.
    pub async fn preflight_check(&self) -> Result<(), DeployError> {
        let rest = self.config.val("OLINE_REST_ENDPOINT");
        if rest.is_empty() {
            tracing::warn!("OLINE_REST_ENDPOINT not set — skipping REST pre-flight check");
            return Ok(());
        }

        tracing::info!(endpoint = %rest, "=== REST API pre-flight check ===");

        // ── Providers list (connectivity check) ────────────────────────────────
        tracing::info!("  querying providers list...");
        match akash_deploy_rs::rest::query_providers(&rest).await {
            Ok(providers) => {
                tracing::info!(
                    count = providers.len(),
                    "  providers reachable ✓  (showing first {})",
                    providers.len()
                );
                for p in &providers {
                    tracing::info!("        provider {} → {}", p.address, p.host_uri);
                }
            }
            Err(e) => {
                return Err(DeployError::Query(format!(
                    "REST pre-flight failed (providers): {e}\n  \
                     Check OLINE_REST_ENDPOINT in .env — try https://api.akashnet.net:443"
                )));
            }
        }

        tracing::info!("=== REST API pre-flight check passed ✓ ===\n");
        Ok(())
    }

    pub fn workflow_config(&self) -> WorkflowConfig {
        // Allow overriding bid wait via env (useful in CI where the provider
        // may take longer to register and place bids).
        // Default: 10 attempts × 12 s = 120 s.  Set OLINE_MAX_BID_WAIT=20 for 240 s.
        let max_bid_wait_attempts = std::env::var("OLINE_MAX_BID_WAIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        WorkflowConfig {
            max_bid_wait_attempts,
            ..WorkflowConfig::default()
        }
    }

    pub async fn deploy_phase_with_selection(
        &self,
        sdl_template: &str,
        variables: &HashMap<String, String>,
        label: &str,
        lines: &mut io::Lines<impl io::BufRead>,
    ) -> Result<(DeploymentState, Vec<ServiceEndpoint>), DeployError> {
        let rendered_sdl = akash_deploy_rs::substitute_partial(sdl_template, variables);

        let mut state = DeploymentState::new(label, self.deployment_owner())
            .with_sdl(&rendered_sdl)
            .with_label(label);

        let workflow = DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        // 60 iterations × ~12s bid wait = ~12 min max before giving up.
        for i in 0..60 {
            tracing::info!("    [{}] step {}: {:?}", label, i, state.step);

            let result = match workflow.advance(&mut state).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("    [{}] error at step {:?}: {:?}", label, state.step, e);
                    return Err(e);
                }
            };

            match result {
                AkashStepResult::Continue => continue,
                AkashStepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    let choice = self
                        .interactive_select_provider(&bids, lines)
                        .await
                        .map_err(|e| {
                            DeployError::InvalidState(format!("Provider selection failed: {}", e))
                        })?;
                    DeploymentWorkflow::<AkashClient>::select_provider(&mut state, &choice)?;
                }
                AkashStepResult::NeedsInput(InputRequired::ProvideSdl) => {
                    return Err(DeployError::InvalidState(
                        "SDL content missing (should never happen)".into(),
                    ));
                }
                AkashStepResult::Complete => {
                    tracing::info!("\n    [{}] complete!", label);
                    if let Some(dseq) = state.dseq {
                        tracing::info!("    [{}] DSEQ: {}", label, dseq);
                    }
                    for ep in &state.endpoints {
                        tracing::info!(
                            "    [{}] endpoint: {} ({}:{})",
                            label,
                            ep.uri,
                            ep.service,
                            ep.port
                        );
                    }
                    let endpoints = state.endpoints.clone();
                    return Ok((state, endpoints));
                }
                AkashStepResult::Failed(reason) => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' failed at step {:?}: {}",
                        label, state.step, reason
                    )));
                }
            }
        }

        Err(DeployError::InvalidState(format!(
            "Deployment '{}' exceeded 60 iterations without completing",
            label
        )))
    }

    /// Phase 1 of split deployment: create deployment on-chain and wait for bids.
    ///
    /// Returns the in-progress `DeploymentState` and collected bids. The caller
    /// selects a provider (via trusted list, interactive prompt, or auto-cheapest),
    /// calls `DeploymentWorkflow::select_provider(&mut state, &choice)`, then
    /// passes the state to `deploy_phase_complete` to finish the workflow.
    pub async fn deploy_phase_until_bids(
        &self,
        sdl_template: &str,
        variables: &HashMap<String, String>,
        label: &str,
    ) -> Result<(DeploymentState, Vec<Bid>), DeployError> {
        let rendered_sdl = akash_deploy_rs::substitute_partial(sdl_template, variables);

        let mut state = DeploymentState::new(label, self.deployment_owner())
            .with_sdl(&rendered_sdl)
            .with_label(label);

        let workflow = DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        for i in 0..60 {
            tracing::info!("    [{}] step {}: {:?}", label, i, state.step);

            let result = match workflow.advance(&mut state).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("    [{}] error at step {:?}: {:?}", label, state.step, e);
                    return Err(e);
                }
            };

            match result {
                AkashStepResult::Continue => continue,
                AkashStepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    tracing::info!(
                        "    [{}] {} bid(s) received — awaiting provider selection.",
                        label,
                        bids.len()
                    );
                    return Ok((state, bids));
                }
                AkashStepResult::NeedsInput(InputRequired::ProvideSdl) => {
                    return Err(DeployError::InvalidState(
                        "SDL content missing (should never happen)".into(),
                    ));
                }
                AkashStepResult::Complete => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' completed before provider selection",
                        label
                    )));
                }
                AkashStepResult::Failed(reason) => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' failed at step {:?}: {}",
                        label, state.step, reason
                    )));
                }
            }
        }

        Err(DeployError::InvalidState(format!(
            "Deployment '{}' exceeded 60 iterations waiting for bids",
            label
        )))
    }

    /// Wait for bids on a deployment that was already created externally
    /// (e.g., via `broadcast_multi_signer`).
    ///
    /// The caller provides a `DeploymentState` with `dseq` and `sdl_content` set.
    /// This method sets the step to `WaitForBids` and drives the workflow until
    /// `NeedsInput(SelectProvider { bids })`.
    pub async fn wait_for_bids(
        &self,
        state: &mut DeploymentState,
        label: &str,
    ) -> Result<Vec<Bid>, DeployError> {
        if state.dseq.is_none() {
            return Err(DeployError::InvalidState(
                "wait_for_bids: state.dseq must be set".into(),
            ));
        }
        if state.sdl_content.is_none() {
            return Err(DeployError::InvalidState(
                "wait_for_bids: state.sdl_content must be set".into(),
            ));
        }

        // Jump directly to WaitForBids — the deployment tx is already confirmed.
        state.step = Step::WaitForBids { waited_blocks: 0 };

        let workflow = DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        for i in 0..60 {
            tracing::info!("    [{}] wait-bids step {}: {:?}", label, i, state.step);

            let result = match workflow.advance(state).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("    [{}] error at step {:?}: {:?}", label, state.step, e);
                    return Err(e);
                }
            };

            match result {
                AkashStepResult::Continue => continue,
                AkashStepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    tracing::info!(
                        "    [{}] {} bid(s) received — ready for provider selection.",
                        label,
                        bids.len()
                    );
                    return Ok(bids);
                }
                AkashStepResult::NeedsInput(_) => {
                    return Err(DeployError::InvalidState(format!(
                        "Unexpected input needed in wait_for_bids for '{}'",
                        label
                    )));
                }
                AkashStepResult::Complete => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' completed before provider selection",
                        label
                    )));
                }
                AkashStepResult::Failed(reason) => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' failed at step {:?}: {}",
                        label, state.step, reason
                    )));
                }
            }
        }

        Err(DeployError::InvalidState(format!(
            "Deployment '{}' exceeded 60 iterations waiting for bids",
            label
        )))
    }

    /// Phase 2 of split deployment: complete the workflow after provider selection.
    ///
    /// The caller must have already called
    /// `DeploymentWorkflow::select_provider(&mut state, &choice)` on the state
    /// returned by `deploy_phase_until_bids`.
    pub async fn deploy_phase_complete(
        &self,
        state: &mut DeploymentState,
        label: &str,
    ) -> Result<Vec<ServiceEndpoint>, DeployError> {
        let workflow = DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        let skip_manifest = std::env::var("OLINE_TEST_STOP_AFTER_DEPLOY").is_ok();

        for i in 0..60 {
            // In test mode, stop before SendManifest — lease is already on-chain,
            // no real provider is available to receive the manifest.
            if skip_manifest && matches!(state.step, Step::SendManifest) {
                tracing::info!(
                    "    [{}] OLINE_TEST_STOP_AFTER_DEPLOY — skipping SendManifest, treating as complete.",
                    label
                );
                return Ok(state.endpoints.clone());
            }

            tracing::info!("    [{}] complete-step {}: {:?}", label, i, state.step);

            let result = match workflow.advance(state).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("    [{}] error at step {:?}: {:?}", label, state.step, e);
                    return Err(e);
                }
            };

            match result {
                AkashStepResult::Continue => continue,
                AkashStepResult::NeedsInput(_) => {
                    return Err(DeployError::InvalidState(format!(
                        "Unexpected input needed after provider selection in '{}'",
                        label
                    )));
                }
                AkashStepResult::Complete => {
                    tracing::info!("\n    [{}] complete!", label);
                    if let Some(dseq) = state.dseq {
                        tracing::info!("    [{}] DSEQ: {}", label, dseq);
                    }
                    for ep in &state.endpoints {
                        tracing::info!(
                            "    [{}] endpoint: {} ({}:{})",
                            label,
                            ep.uri,
                            ep.service,
                            ep.port
                        );
                    }
                    return Ok(state.endpoints.clone());
                }
                AkashStepResult::Failed(reason) => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' failed at step {:?}: {}",
                        label, state.step, reason
                    )));
                }
            }
        }

        Err(DeployError::InvalidState(format!(
            "Deployment '{}' exceeded 60 iterations after provider selection",
            label
        )))
    }

    /// Deploy a phase without stdin — always auto-selects the cheapest provider.
    ///
    /// Used by the parallel deploy path where all phases run concurrently and
    /// interactive provider selection is not possible.
    pub async fn deploy_phase_auto(
        &self,
        sdl_template: &str,
        variables: &HashMap<String, String>,
        label: &str,
    ) -> Result<(DeploymentState, Vec<ServiceEndpoint>), DeployError> {
        let rendered_sdl = akash_deploy_rs::substitute_partial(sdl_template, variables);

        let mut state = DeploymentState::new(label, self.deployment_owner())
            .with_sdl(&rendered_sdl)
            .with_label(label);

        let workflow = DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        for i in 0..60 {
            tracing::info!("    [{}] step {}: {:?}", label, i, state.step);

            let result = match workflow.advance(&mut state).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("    [{}] error at step {:?}: {:?}", label, state.step, e);
                    return Err(e);
                }
            };

            match result {
                AkashStepResult::Continue => continue,
                AkashStepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    // Require a trusted provider — never auto-select cheapest.
                    let trusted = TrustedProviderStore::open(TrustedProviderStore::default_path());
                    let choice = match trusted.select_from_bids(&bids) {
                        Some(p) => p,
                        None => {
                            tracing::warn!(
                                "  [{}] no trusted provider bidding among {} bid(s) — add trusted providers or use interactive mode",
                                label, bids.len()
                            );
                            return Err(DeployError::InvalidState(
                                "No trusted provider bidding. Use interactive mode to select a provider and trust it.".into()
                            ));
                        }
                    };
                    DeploymentWorkflow::<AkashClient>::select_provider(&mut state, &choice)?;
                }
                AkashStepResult::NeedsInput(InputRequired::ProvideSdl) => {
                    return Err(DeployError::InvalidState(
                        "SDL content missing (should never happen)".into(),
                    ));
                }
                AkashStepResult::Complete => {
                    tracing::info!("\n    [{}] complete! DSEQ: {:?}", label, state.dseq);
                    for ep in &state.endpoints {
                        tracing::info!(
                            "    [{}] endpoint: {} ({}:{})",
                            label,
                            ep.uri,
                            ep.service,
                            ep.port
                        );
                    }
                    let endpoints = state.endpoints.clone();
                    return Ok((state, endpoints));
                }
                AkashStepResult::Failed(reason) => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' failed at step {:?}: {}",
                        label, state.step, reason
                    )));
                }
            }
        }

        Err(DeployError::InvalidState(format!(
            "Deployment '{}' exceeded 60 iterations without completing",
            label
        )))
    }

    /// Query provider info for each bid and display enriched selection.
    ///
    /// Trusted providers (from `~/.config/oline/trusted-providers.json`) are
    /// shown with a `[TRUSTED]` badge. In non-interactive / CI mode the trusted
    /// list is consulted first; if no trusted provider bids, falls back to
    /// cheapest overall.
    ///
    /// Interactive shortcuts:
    ///   `<N>`   — select provider N
    ///   `t<N>`  — trust provider N and select it (saves to trusted list)
    ///   `a`     — auto-select cheapest overall
    ///   `t`     — auto-select cheapest trusted (or cheapest overall if none)
    pub async fn interactive_select_provider(
        &self,
        bids: &[Bid],
        lines: &mut io::Lines<impl io::BufRead>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let trusted_store = TrustedProviderStore::open(TrustedProviderStore::default_path());

        // Non-interactive / CI: require a trusted provider — never auto-select cheapest.
        if std::env::var("OLINE_NON_INTERACTIVE").is_ok()
            || std::env::var("OLINE_AUTO_SELECT").is_ok()
        {
            match trusted_store.select_from_bids(bids) {
                Some(provider) => return Ok(provider),
                None => {
                    tracing::warn!(
                        "  No trusted provider bidding among {} bid(s). Run interactively to select and trust a provider.",
                        bids.len()
                    );
                    return Err("No trusted provider bidding. Run interactively to select and trust a provider.".into());
                }
            }
        }

        tracing::info!("  ═══════════════════════════════════════════════════════════════════════");
        tracing::info!("    PROVIDER SELECTION — {} bid(s) received", bids.len());
        tracing::info!("  ═══════════════════════════════════════════════════════════════════════");

        // Load trusted list once for the whole selection interaction.
        let trusted_list = trusted_store.load();
        let trusted_addrs: std::collections::HashSet<&str> =
            trusted_list.iter().map(|p| p.address.as_str()).collect();

        let mut provider_infos: Vec<Option<ProviderInfo>> = Vec::with_capacity(bids.len());
        for bid in bids {
            match self.client.query_provider_info(&bid.provider).await {
                Ok(info) => provider_infos.push(info),
                Err(_) => provider_infos.push(None),
            }
        }

        for (i, bid) in bids.iter().enumerate() {
            let price_akt = bid.price as f64 / 1_000_000.0;
            let info = &provider_infos[i];
            let is_trusted = trusted_addrs.contains(bid.provider.as_str());
            let trust_badge = if is_trusted { " [TRUSTED]" } else { "" };

            tracing::info!(
                "    [{}] {:.6} AKT/block ({} uakt){}",
                i + 1,
                price_akt,
                bid.price,
                trust_badge
            );
            tracing::info!("        address:  {}", bid.provider);

            if let Some(ref info) = info {
                tracing::info!("        host:     {}", info.host_uri);

                if !info.email.is_empty() {
                    tracing::info!("        email:    {}", info.email);
                }
                if !info.website.is_empty() {
                    tracing::info!("        website:  {}", info.website);
                }

                let audited = info.attributes.iter().any(|(k, _)| k.starts_with("audit-"));
                if audited {
                    tracing::info!("        audited:  YES");
                }

                let interesting_keys = [
                    "host",
                    "organization",
                    "tier",
                    "region",
                    "capabilities/storage/3/class",
                    "capabilities/gpu/vendor/nvidia/model/*",
                ];

                let mut shown_attrs = Vec::new();
                for (key, val) in &info.attributes {
                    for ik in &interesting_keys {
                        if key.contains(ik) {
                            shown_attrs.push(format!("{}={}", key, val));
                        }
                    }
                }
                if !shown_attrs.is_empty() {
                    tracing::info!("        attrs:    {}", shown_attrs.join(", "));
                }
            } else {
                tracing::info!("        host:     (could not query provider info)");
            }
        }

        let trusted_count = bids
            .iter()
            .filter(|b| trusted_addrs.contains(b.provider.as_str()))
            .count();
        let hint = if trusted_count > 0 {
            format!(
                "'t' for cheapest trusted ({} bidding), 't<N>' to trust+select, 'a' for cheapest overall",
                trusted_count
            )
        } else {
            "'a' to auto-select cheapest, 't<N>' to trust+select".into()
        };

        loop {
            print!("    Select provider (1-{}), or {}: ", bids.len(), hint);
            io::Write::flush(&mut io::stdout())?;

            let input = lines.next().unwrap_or(Ok(String::new()))?;
            let input = input.trim().to_lowercase();

            // 'a' or 'auto' — cheapest overall
            if input == "a" || input == "auto" {
                let cheapest = bids.iter().min_by_key(|b| b.price).unwrap();
                tracing::info!("\n    Selected: {}", cheapest.provider);
                if let Some(idx) = bids.iter().position(|b| b.provider == cheapest.provider) {
                    if let Some(ref info) = provider_infos[idx] {
                        tracing::info!("    Host:     {}", info.host_uri);
                    }
                }
                tracing::info!(
                    "  ═══════════════════════════════════════════════════════════════════════\n"
                );
                return Ok(cheapest.provider.clone());
            }

            // 't' alone — cheapest trusted, or cheapest overall if none
            if input == "t" || input == "trusted" {
                let provider = bids
                    .iter()
                    .filter(|b| trusted_addrs.contains(b.provider.as_str()))
                    .min_by_key(|b| b.price)
                    .map(|b| {
                        let alias = trusted_list
                            .iter()
                            .find(|p| p.address == b.provider)
                            .and_then(|p| p.alias.as_deref());
                        tracing::info!(
                            "    Selecting trusted: {} ({} uakt/block)",
                            alias.unwrap_or(&b.provider),
                            b.price
                        );
                        b.provider.clone()
                    })
                    .unwrap_or_else(|| {
                        let cheapest = bids.iter().min_by_key(|b| b.price).unwrap();
                        tracing::info!(
                            "    No trusted provider bidding — falling back to cheapest."
                        );
                        cheapest.provider.clone()
                    });
                tracing::info!("\n    Selected: {}", provider);
                tracing::info!(
                    "  ═══════════════════════════════════════════════════════════════════════\n"
                );
                return Ok(provider);
            }

            // 't<N>' — trust provider N and select it
            let trust_select: Option<usize> = if input.starts_with('t') {
                input[1..].parse().ok()
            } else {
                None
            };
            if let Some(n) = trust_select {
                if n < 1 || n > bids.len() {
                    tracing::info!("    {} is out of range — enter t1–t{}.", n, bids.len());
                    continue;
                }
                let bid = &bids[n - 1];
                let host_uri = provider_infos[n - 1]
                    .as_ref()
                    .map(|i| i.host_uri.clone())
                    .unwrap_or_default();
                let mut tp = crate::providers::TrustedProvider::new(&bid.provider, host_uri);
                // Copy alias/notes from existing entry if present
                if let Some(existing) = trusted_store.find(&bid.provider) {
                    tp.alias = existing.alias;
                    tp.notes = existing.notes;
                }
                if let Err(e) = trusted_store.add(tp) {
                    tracing::warn!("    Could not save to trusted list: {}", e);
                } else {
                    tracing::info!("    Saved {} to trusted providers.", bid.provider);
                }
                tracing::info!("\n    Selected: {}", bid.provider);
                tracing::info!(
                    "  ═══════════════════════════════════════════════════════════════════════\n"
                );
                return Ok(bid.provider.clone());
            }

            // Plain number — select provider N
            let choice: usize = match input.parse() {
                Ok(n) => n,
                Err(_) => {
                    tracing::info!(
                        "    Invalid input '{}' — enter a number 1-{}, 'a', 't', or 't<N>'.",
                        input,
                        bids.len()
                    );
                    continue;
                }
            };

            if choice < 1 || choice > bids.len() {
                tracing::info!(
                    "    {} is out of range — enter 1-{} or 'a'.",
                    choice,
                    bids.len()
                );
                continue;
            }

            let selected = &bids[choice - 1];
            let selected_info = &provider_infos[choice - 1];

            tracing::info!("\n    Selected: {}", selected.provider);
            if let Some(ref info) = selected_info {
                tracing::info!("    Host:     {}", info.host_uri);
            }
            tracing::info!(
                "  ═══════════════════════════════════════════════════════════════════════\n"
            );
            return Ok(selected.provider.clone());
        }
    }

    /// Query `rpc_url/status` and return `"<node_id>@<p2p_address>"`.
    pub async fn extract_peer_id_at(
        rpc_url: &str,
        p2p_address: &str,
    ) -> Result<String, Box<dyn Error>> {
        let status_url = format!("{}/status", rpc_url.trim_end_matches('/'));
        let resp = reqwest::get(&status_url).await?.text().await?;
        let json: serde_json::Value = serde_json::from_str(&resp)?;
        let node_id = json["result"]["node_info"]["id"]
            .as_str()
            .ok_or("missing node_info.id in /status response")?;
        Ok(format!("{}@{}", node_id, p2p_address))
    }

    /// Retry `extract_peer_id_at` with an optional initial boot wait.
    pub async fn extract_peer_id_with_boot_wait(
        rpc_url: &str,
        p2p_address: &str,
        initial_wait_secs: u64,
        max_retries: u32,
        retry_delay_secs: u64,
    ) -> Option<String> {
        if initial_wait_secs > 0 {
            tracing::info!(
                "  Waiting {}m before querying {}/status (node boot time)",
                initial_wait_secs / 60,
                rpc_url,
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(initial_wait_secs)).await;
        }
        for attempt in 1..=max_retries {
            match Self::extract_peer_id_at(rpc_url, p2p_address).await {
                Ok(peer) => return Some(peer),
                Err(e) => {
                    if attempt < max_retries {
                        tracing::info!(
                            "  Peer ID fetch attempt {}/{} for {} failed: {} — retrying in {}s",
                            attempt,
                            max_retries,
                            rpc_url,
                            e,
                            retry_delay_secs
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(retry_delay_secs))
                            .await;
                    } else {
                        tracing::info!(
                            "  Peer ID fetch failed after {} attempts for {}: {}",
                            max_retries,
                            rpc_url,
                            e
                        );
                    }
                }
            }
        }
        None
    }

    /// Find the forwarded endpoint for `service_name` where `internal_port` matches.
    pub fn find_endpoint_by_internal_port<'a>(
        endpoints: &'a [ServiceEndpoint],
        service_name: &str,
        internal_port: u16,
    ) -> Option<&'a ServiceEndpoint> {
        endpoints
            .iter()
            .find(|e| e.service == service_name && e.internal_port == internal_port)
            .or_else(|| endpoints.iter().find(|e| e.service == service_name))
    }
}
