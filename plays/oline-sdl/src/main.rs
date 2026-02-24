use akash_deploy_rs::{
    AkashBackend, AkashClient, Bid, DeployError, DeploymentRecord, DeploymentState,
    DeploymentStore, DeploymentWorkflow, FileDeploymentStore, InputRequired, KeySigner,
    ProviderInfo, ServiceEndpoint, StepResult, WorkflowConfig,
};
use o_line_sdl::{self, akash::*, cli::*, config::*, crypto::*, dns::cloudflare::*, snapshots::*};

use std::io::{self, BufRead, Write};
use std::{collections::HashMap, error::Error};

// ── SDL variable builders ──
fn build_phase_a_vars(config: &OLineConfig, defaults: &RuntimeDefaults) -> HashMap<String, String> {
    let minio_svc = "oline-a-minio-ipfs";
    // Auto-generate credentials shared between snapshot node and MinIO
    let s3_key = generate_credential(S3_KEY);
    let s3_secret = generate_credential(S3_SECRET);
    // Use the public DNS domain so the snapshot node connects via the provider ingress.
    let s3_host = config.snapshot_download_domain.clone();

    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    insert_s3_vars(&mut vars, config, &s3_key, &s3_secret, &s3_host);
    insert_minio_vars(&mut vars, config, &s3_key, &s3_secret);
    vars.insert("SNAPSHOT_SVC".into(), "oline-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a-seed".into());
    vars.insert("MINIO_SVC".into(), minio_svc.into());
    vars.insert("CERTBOT_EMAIL".into(), config.certbot_email.clone());
    vars.insert("TLS_CONFIG_URL".into(), config.tls_config_url.clone());
    vars.insert("ENTRYPOINT_URL".into(), config.tls_config_url.clone());
    vars.insert(
        "SNAPSHOT_MONIKER".into(),
        "oline::special::snapshot-node".into(),
    );
    vars.insert("SEED_MONIKER".into(), "oline::special::seed-node".into());
    vars.insert("SNAPSHOT_URL".into(), config.snapshot_url.clone());
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars
}

fn build_phase_a2_vars(
    config: &OLineConfig,
    defaults: &RuntimeDefaults,
) -> HashMap<String, String> {
    let minio_svc = "oline-a2-minio-ipfs";
    // Auto-generate credentials shared between snapshot node and MinIO
    let s3_key = generate_credential(24);
    let s3_secret = generate_credential(40);
    // Use the public DNS domain so the snapshot node connects via the provider ingress.
    let s3_host = config.snapshot_download_domain.clone();

    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    insert_s3_vars(&mut vars, config, &s3_key, &s3_secret, &s3_host);
    insert_minio_vars(&mut vars, config, &s3_key, &s3_secret);
    vars.insert("SNAPSHOT_SVC".into(), "oline-a2-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a2-seed".into());
    vars.insert("MINIO_SVC".into(), minio_svc.into());
    vars.insert("CERTBOT_EMAIL".into(), config.certbot_email.clone());
    vars.insert(
        "SNAPSHOT_MONIKER".into(),
        "oline::backup::snapshot-node".into(),
    );
    vars.insert("SEED_MONIKER".into(), "oline::backup::seed-node".into());
    vars.insert("SNAPSHOT_URL".into(), config.snapshot_url.clone());
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars.insert("TLS_CONFIG_URL".into(), config.tls_config_url.clone());
    vars
}

fn build_phase_b_vars(
    config: &OLineConfig,
    snapshot_peer: &str,
    snapshot_2_peer: &str,
    snapshot_url: &str,
    // Comma-separated "host:port" pairs for cosmos statesync RPC servers.
    // Uses A1 snapshot node (statesync.terp.network) and A1 seed node (seed-statesync.terp.network).
    statesync_rpc_servers: &str,
    defaults: &RuntimeDefaults,
) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        format!("{},{}", snapshot_peer, snapshot_2_peer),
    );
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars.insert(
        "TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars.insert("SNAPSHOT_URL".into(), snapshot_url.to_string());
    vars.insert(
        "SNAPSHOT_SAVE_FORMAT".into(),
        config.snapshot_save_format.clone(),
    );
    // Statesync — use both A1 snapshot RPC and A1 seed RPC so tackles can
    // sync to the network quickly without waiting for a full replay.
    if !statesync_rpc_servers.is_empty() {
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
        vars.insert(
            "STATESYNC_RPC_SERVERS".into(),
            statesync_rpc_servers.to_string(),
        );
    }
    vars
}

fn build_phase_c_vars(
    seed_peer: &str,
    seed_2_peer: &str,
    snapshot_peer: &str,
    snapshot_2_peer: &str,
    left_tackle_peer: &str,
    right_tackle_peer: &str,
    defaults: &RuntimeDefaults,
) -> HashMap<String, String> {
    let tackles_combined = format!("{},{}", left_tackle_peer, right_tackle_peer);
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    vars.insert(
        "TERPD_P2P_SEEDS".into(),
        format!("{},{}", seed_peer, seed_2_peer),
    );
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        tackles_combined.clone(),
    );
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), tackles_combined);
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        format!("{},{}", snapshot_peer, snapshot_2_peer),
    );
    vars
}

pub struct OLineDeployer {
    client: AkashClient,
    signer: KeySigner,
    config: OLineConfig,
    password: String,
    deployment_store: FileDeploymentStore,
    defaults: RuntimeDefaults,
}

impl OLineDeployer {
    pub async fn new(
        config: OLineConfig,
        password: String,
        defaults: RuntimeDefaults,
    ) -> Result<Self, DeployError> {
        let client = AkashClient::new_from_mnemonic(
            &config.mnemonic,
            &config.rpc_endpoint,
            &config.grpc_endpoint,
        )
        .await?;
        let signer = KeySigner::new_mnemonic_str(&config.mnemonic, None)
            .map_err(|e| DeployError::Signer(format!("Failed to create signer: {}", e)))?;
        let deployment_store = FileDeploymentStore::new_default().await?;
        Ok(Self {
            client,
            signer,
            config,
            password,
            deployment_store,
            defaults,
        })
    }

    fn workflow_config(&self) -> WorkflowConfig {
        WorkflowConfig {
            auto_select_cheapest_bid: self.config.auto_select_provider,
            trusted_providers: self.config.trusted_providers.clone(),
            ..Default::default()
        }
    }

    pub async fn deploy_phase_with_selection(
        &self,
        sdl_template: &str,
        variables: HashMap<String, String>,
        defaults: HashMap<String, String>,
        label: &str,
        lines: &mut io::Lines<io::StdinLock<'_>>,
    ) -> Result<(DeploymentState, Vec<ServiceEndpoint>), DeployError> {
        // Pre-render template using raw substitution so ${VAR} in YAML keys
        // (like service names) are replaced before any YAML parsing.
        let rendered_sdl = substitute_template_raw(sdl_template, &variables, &defaults)
            .map_err(|e| DeployError::Template(format!("Template substitution failed: {}", e)))?;

        let mut state = DeploymentState::new(label, self.client.address())
            .with_sdl(&rendered_sdl)
            .with_label(label);

        let workflow = DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        // Bounded loop — matches akash-deploy-rs/examples/deploy.rs pattern.
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
                StepResult::Continue => continue,
                StepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    let choice = self
                        .interactive_select_provider(&bids, lines)
                        .await
                        .map_err(|e| {
                            DeployError::InvalidState(format!("Provider selection failed: {}", e))
                        })?;
                    DeploymentWorkflow::<AkashClient>::select_provider(&mut state, &choice)?;
                }
                StepResult::NeedsInput(InputRequired::ProvideSdl) => {
                    return Err(DeployError::InvalidState(
                        "SDL content missing (should never happen)".into(),
                    ));
                }
                StepResult::Complete => {
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
                StepResult::Failed(reason) => {
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
    /// Follows the pattern from akash-deploy-rs/examples/deploy.rs.
    async fn interactive_select_provider(
        &self,
        bids: &[Bid],
        lines: &mut io::Lines<io::StdinLock<'_>>,
    ) -> Result<String, Box<dyn Error>> {
        tracing::info!("  ═══════════════════════════════════════════════════════════════════════");
        tracing::info!("    PROVIDER SELECTION — {} bid(s) received", bids.len());
        tracing::info!("  ═══════════════════════════════════════════════════════════════════════");

        // Query provider info for each bid (best-effort)
        let mut provider_infos: Vec<Option<ProviderInfo>> = Vec::with_capacity(bids.len());
        for bid in bids {
            match self.client.query_provider_info(&bid.provider).await {
                Ok(info) => provider_infos.push(info),
                Err(_) => provider_infos.push(None),
            }
        }

        for (i, bid) in bids.iter().enumerate() {
            let price_akt = bid.price_uakt as f64 / 1_000_000.0;
            let info = &provider_infos[i];

            tracing::info!(
                "    [{}] {:.6} AKT/block ({} uakt)",
                i + 1,
                price_akt,
                bid.price_uakt
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

        print!(
            "    Select provider (1-{}) or 'a' to auto-select cheapest: ",
            bids.len()
        );
        io::stdout().flush()?;

        let input = lines.next().unwrap_or(Ok(String::new()))?;
        let input = input.trim().to_lowercase();

        if input == "a" || input == "auto" {
            let cheapest = bids.iter().min_by_key(|b| b.price_uakt).unwrap();
            tracing::info!("\n    Selected: {}", cheapest.provider);
            if let Some(ref info) = provider_infos[bids
                .iter()
                .position(|b| b.provider == cheapest.provider)
                .unwrap()]
            {
                tracing::info!("    Host:     {}", info.host_uri);
            }
            tracing::info!(
                "  ═══════════════════════════════════════════════════════════════════════\n"
            );
            return Ok(cheapest.provider.clone());
        }

        let choice: usize = input
            .parse()
            .map_err(|_| format!("invalid input: '{}'", input))?;

        if choice < 1 || choice > bids.len() {
            return Err(format!("selection {} out of range (1-{})", choice, bids.len()).into());
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

        Ok(selected.provider.clone())
    }

    /// Query `rpc_url/status` and return `"<node_id>@<p2p_address>"`.
    /// `p2p_address` is the fully-formatted address string, e.g. `"seed.terp.network:31039"`.
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
    ///
    /// * `initial_wait_secs` — sleep this long before the first attempt (lets the
    ///   node fully start; 0 means start immediately).
    /// * `max_retries` — number of attempts after the initial wait.
    /// * `retry_delay_secs` — pause between failed attempts.
    ///
    /// Returns `None` if all attempts fail.
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

    /// Find the forwarded endpoint for `service_name` where `internal_port` matches
    /// the SDL-specified port (e.g. 26656 or 26657).  Falls back to the first
    /// endpoint for that service if `internal_port` is 0 (old parsing path).
    fn find_endpoint_by_internal_port<'a>(
        endpoints: &'a [ServiceEndpoint],
        service_name: &str,
        internal_port: u16,
    ) -> Option<&'a ServiceEndpoint> {
        endpoints
            .iter()
            .find(|e| e.service == service_name && e.internal_port == internal_port)
            .or_else(|| endpoints.iter().find(|e| e.service == service_name))
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        tracing::info!("\n=== O-Line Deployer ===");
        tracing::info!("Account: {}", self.client.address());

        // ── Phase A: Snapshot + Seed ──
        tracing::info!("\n── Phase 1: Deploy Snapshot + Seed nodes ──");
        if !prompt_continue(&mut lines, "Deploy Kickoff (Speacial Teams)?")? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        let a_vars = build_phase_a_vars(&self.config, &self.defaults);
        let a_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &a_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        let sdl_a = self.defaults.load_sdl("a.kickoff-special-teams.yml")?;
        tracing::info!("  Deploying...");
        let (a_state, a_endpoints) = self
            .deploy_phase_with_selection(&sdl_a, a_vars, a_defaults, "oline-phase-a", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", a_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&a_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        if !self.config.cloudflare_api_token.is_empty()
            && !self.config.cloudflare_zone_id.is_empty()
        {
            tracing::info!("  Updating Cloudflare DNS for accept domains...");
            if let Some(sdl) = &a_state.sdl_content {
                cloudflare_update_accept_domains(
                    sdl,
                    &a_endpoints,
                    &self.config.cloudflare_api_token,
                    &self.config.cloudflare_zone_id,
                )
                .await;
            }
        } else {
            tracing::info!("  Note: Cloudflare DNS not configured — update CNAMEs for accept domains manually.");
        }

        // ── Extract peer IDs via DNS domains ──
        // Find the forwarded NodePorts for each service's RPC (26657) and P2P (26656).
        let snap_rpc_ep =
            Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-snapshot", 26657);
        let snap_p2p_ep =
            Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-snapshot", 26656);
        let seed_rpc_ep = Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-seed", 26657);
        let seed_p2p_ep = Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-seed", 26656);

        // Construct DNS-based query URLs and peer addresses.
        // Format: <node_id>@<dns_domain>:<nodeport>  — the cosmos-sdk peer string.
        let snap_rpc_url =
            snap_rpc_ep.map(|e| format!("http://{}:{}", SNAPSHOT_RPC_DOMAIN, e.port));
        let snap_p2p_addr = snap_p2p_ep.map(|e| format!("{}:{}", SNAPSHOT_P2P_DOMAIN, e.port));
        let seed_rpc_url = seed_rpc_ep.map(|e| format!("http://{}:{}", SEED_RPC_DOMAIN, e.port));
        let seed_p2p_addr = seed_p2p_ep.map(|e| format!("{}:{}", SEED_P2P_DOMAIN, e.port));

        // Statesync RPC servers string for Phase B (cosmos format: "host:port,host:port").
        let a1_statesync_rpc = {
            let s = snap_rpc_ep
                .map(|e| format!("{}:{}", SNAPSHOT_RPC_DOMAIN, e.port))
                .unwrap_or_default();
            let sd = seed_rpc_ep
                .map(|e| format!("{}:{}", SEED_RPC_DOMAIN, e.port))
                .unwrap_or_default();
            match (s.is_empty(), sd.is_empty()) {
                (false, false) => format!("{},{}", s, sd),
                (false, true) => s,
                (true, false) => sd,
                (true, true) => String::new(),
            }
        };

        tracing::info!(
            "  Snapshot RPC: {}",
            snap_rpc_url.as_deref().unwrap_or("(not found)")
        );
        tracing::info!(
            "  Snapshot P2P: {}",
            snap_p2p_addr.as_deref().unwrap_or("(not found)")
        );
        tracing::info!(
            "  Seed RPC:     {}",
            seed_rpc_url.as_deref().unwrap_or("(not found)")
        );
        tracing::info!(
            "  Seed P2P:     {}",
            seed_p2p_addr.as_deref().unwrap_or("(not found)")
        );
        tracing::info!("  Statesync RPC servers: {}", a1_statesync_rpc);

        // Snapshot node: 5 min initial wait (it creates a snapshot on startup before syncing),
        // then retry every 60s up to 20 times (~25 min max total).
        let snapshot_peer = match (snap_rpc_url.as_deref(), snap_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!(
                    "  Warning: no RPC/P2P endpoints found for oline-a-snapshot — skipping peer ID"
                );
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!(
                "  Warning: could not fetch snapshot peer ID — Phase B will use empty peer."
            );
            String::new()
        });

        // Seed node: also 5 min initial wait, 20×60s retries.
        let seed_peer = match (seed_rpc_url.as_deref(), seed_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!(
                    "  Warning: no RPC/P2P endpoints found for oline-a-seed — skipping peer ID"
                );
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!(
                "  Warning: could not fetch seed peer ID — Phase B will use empty peer."
            );
            String::new()
        });

        tracing::info!("    snapshot_peer: {}", snapshot_peer);
        tracing::info!("    seed_peer:     {}", seed_peer);

        // ── Phase A2: Backup Snapshot + Seed (reuses SDL_A with backup service names) ──
        tracing::info!("\n── Phase 1b: Deploy Backup Snapshot + Seed nodes ──");
        if !prompt_continue(
            &mut lines,
            "Deploy backup kickoff (a.kickoff-special-teams.yml)?",
        )? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        let a2_vars = build_phase_a2_vars(&self.config, &self.defaults);
        let a2_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &a2_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        tracing::info!("  Deploying...");
        let (a2_state, a2_endpoints) = self
            .deploy_phase_with_selection(&sdl_a, a2_vars, a2_defaults, "oline-phase-a2", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", a2_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&a2_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        // ── Cloudflare DNS for Phase A2 accept domains ──
        if !self.config.cloudflare_api_token.is_empty()
            && !self.config.cloudflare_zone_id.is_empty()
        {
            if let Some(sdl) = &a2_state.sdl_content {
                cloudflare_update_accept_domains(
                    sdl,
                    &a2_endpoints,
                    &self.config.cloudflare_api_token,
                    &self.config.cloudflare_zone_id,
                )
                .await;
            }
        }

        // ── Extract peer IDs from Phase A2 (backup nodes, same DNS domains) ──
        let snap2_rpc_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-snapshot", 26657);
        let snap2_p2p_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-snapshot", 26656);
        let seed2_rpc_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-seed", 26657);
        let seed2_p2p_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-seed", 26656);

        let snap2_rpc_url =
            snap2_rpc_ep.map(|e| format!("http://{}:{}", SNAPSHOT_RPC_DOMAIN, e.port));
        let snap2_p2p_addr = snap2_p2p_ep.map(|e| format!("{}:{}", SNAPSHOT_P2P_DOMAIN, e.port));
        let seed2_rpc_url = seed2_rpc_ep.map(|e| format!("http://{}:{}", SEED_RPC_DOMAIN, e.port));
        let seed2_p2p_addr = seed2_p2p_ep.map(|e| format!("{}:{}", SEED_P2P_DOMAIN, e.port));

        let snapshot_2_peer = match (snap2_rpc_url.as_deref(), snap2_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!("  Warning: no RPC/P2P endpoints found for oline-a2-snapshot — skipping peer ID");
                None
            }
        }.unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch snapshot-2 peer ID.");
            String::new()
        });

        let seed_2_peer = match (seed2_rpc_url.as_deref(), seed2_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!(
                    "  Warning: no RPC/P2P endpoints found for oline-a2-seed — skipping peer ID"
                );
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch seed-2 peer ID.");
            String::new()
        });

        tracing::info!("    snapshot_2_peer: {}", snapshot_2_peer);
        tracing::info!("    seed_2_peer:     {}", seed_2_peer);

        // ── Phase B: Left & Right Tackles ──
        tracing::info!("\n── Phase 2: Deploy Left & Right Tackles ──");
        if !prompt_continue(&mut lines, "Deploy b.left-and-right-tackle.yml?")? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        // Fetch the snapshot download URL from the MinIO metadata JSON.
        // Fallback: construct from config path if metadata isn't available yet.
        let b_snapshot_fallback = format!(
            "https://{}/{}/latest.{}",
            self.config.snapshot_download_domain,
            self.config.snapshot_path.trim_matches('/'),
            self.config.snapshot_save_format
        );
        let b_snapshot_metadata_url = format!(
            "https://{}/{}/snapshot.json",
            self.config.snapshot_download_domain,
            self.config.snapshot_path.trim_matches('/')
        );
        let b_snapshot_url =
            fetch_snapshot_url_from_metadata(&b_snapshot_metadata_url, &b_snapshot_fallback).await;
        tracing::info!("  Phase B snapshot URL: {}", b_snapshot_url);

        let b_vars = build_phase_b_vars(
            &self.config,
            &snapshot_peer,
            &snapshot_2_peer,
            &b_snapshot_url,
            &a1_statesync_rpc,
            &self.defaults,
        );
        let b_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &b_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        let sdl_b = self.defaults.load_sdl("b.left-and-right-tackle.yml")?;
        tracing::info!("  Deploying...");
        let (b_state, b_endpoints) = self
            .deploy_phase_with_selection(&sdl_b, b_vars, b_defaults, "oline-phase-b", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", b_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&b_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        // Extract peer IDs from Phase B tackles.
        // Tackles don't have public DNS domains — use provider URI hostname + forwarded P2P port.
        let left_rpc_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-left-node", 26657);
        let left_p2p_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-left-node", 26656);
        let right_rpc_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-right-node", 26657);
        let right_p2p_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-right-node", 26656);

        let left_rpc_url = left_rpc_ep.map(|e| e.uri.clone());
        let left_p2p_addr =
            left_p2p_ep.map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));
        let right_rpc_url = right_rpc_ep.map(|e| e.uri.clone());
        let right_p2p_addr =
            right_p2p_ep.map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

        // 5 min initial wait, 20×60s retries — tackles need to sync from statesync first.
        let left_tackle_peer = match (left_rpc_url.as_deref(), left_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!("  Warning: no endpoints for oline-b-left-node");
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch left-tackle peer ID.");
            String::new()
        });

        let right_tackle_peer = match (right_rpc_url.as_deref(), right_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!("  Warning: no endpoints for oline-b-right-node");
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch right-tackle peer ID.");
            String::new()
        });

        tracing::info!("    left_tackle:  {}", left_tackle_peer);
        tracing::info!("    right_tackle: {}", right_tackle_peer);

        // ── Phase C: Left & Right Forwards ──
        tracing::info!("\n── Phase 3: Deploy Left & Right Forwards ──");
        if !prompt_continue(&mut lines, "Deploy c.left-and-right-forwards.yml?")? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        let c_vars = build_phase_c_vars(
            &seed_peer,
            &seed_2_peer,
            &snapshot_peer,
            &snapshot_2_peer,
            &left_tackle_peer,
            &right_tackle_peer,
            &self.defaults,
        );
        let c_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &c_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        let sdl_c = self.defaults.load_sdl("c.left-and-right-forwards.yml")?;
        tracing::info!("  Deploying...");
        let (c_state, _c_endpoints) = self
            .deploy_phase_with_selection(&sdl_c, c_vars, c_defaults, "oline-phase-c", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", c_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&c_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        tracing::info!("\n=== All deployments complete! ===");
        tracing::info!("  Phase A1 DSEQ: {}", a_state.dseq.unwrap_or(0));
        tracing::info!("  Phase A2 DSEQ: {}", a2_state.dseq.unwrap_or(0));
        tracing::info!("  Phase B  DSEQ: {}", b_state.dseq.unwrap_or(0));
        tracing::info!("  Phase C  DSEQ: {}", c_state.dseq.unwrap_or(0));
        Ok(())
    }
}

// ── Subcommand: encrypt ──
fn cmd_encrypt(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Encrypt Mnemonic ===\n");

    let mnemonic = rpassword::prompt_password("Enter mnemonic: ")?;
    if mnemonic.trim().is_empty() {
        return Err("Mnemonic cannot be empty.".into());
    }

    let password = rpassword::prompt_password("Enter password: ")?;
    if password.is_empty() {
        return Err("Password cannot be empty.".into());
    }

    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err("Passwords do not match.".into());
    }

    let blob = encrypt_mnemonic(mnemonic.trim(), &password)?;
    write_encrypted_mnemonic_to_env(&defaults.env_key, &blob)?;

    tracing::info!("\nEncrypted mnemonic written to .env");
    tracing::info!("You can now run `oline deploy` to deploy using your encrypted mnemonic.");
    Ok(())
}

// ── Unlock mnemonic helper ──

fn unlock_mnemonic(defaults: &RuntimeDefaults) -> Result<(String, String), Box<dyn Error>> {
    let blob = read_encrypted_mnemonic_from_env(&defaults.env_key)?;
    let password = rpassword::prompt_password("Enter password: ")?;
    let mnemonic = decrypt_mnemonic(&blob, &password)?;
    tracing::info!("Mnemonic decrypted successfully.\n");
    Ok((mnemonic, password))
}

// ── Subcommand: deploy ──

async fn cmd_deploy(raw: bool, defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Welcome to O-Line Deployer ===\n");

    let (mnemonic, password) = if raw {
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        let password = rpassword::prompt_password("Enter a password (for config encryption): ")?;
        (m.trim().to_string(), password)
    } else {
        unlock_mnemonic(defaults)?
    };

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let config = collect_config(&password, mnemonic, &mut lines, defaults).await?;

    // Drop the stdin lock before OLineDeployer::run() re-acquires it
    drop(lines);

    let mut deployer = OLineDeployer::new(config, password, defaults.clone()).await?;
    deployer.run().await
}

// ── Subcommand: generate-sdl ──

async fn cmd_generate_sdl(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Generate SDL ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    tracing::info!("  Select phase to render:");
    tracing::info!("    a  - Phase A: Kickoff Special Teams (snapshot + seed)");
    tracing::info!("    a2 - Phase A2: Backup Kickoff");
    tracing::info!("    b  - Phase B: Left & Right Tackles");
    tracing::info!("    c  - Phase C: Left & Right Forwards");
    tracing::info!("    all - All phases");
    let phase = read_input(&mut lines, "Phase", Some("all"))?;

    // Load config (optionally from saved)
    let config = if has_saved_config() {
        tracing::info!("\n  Found saved config.");
        let password = rpassword::prompt_password(
            "Enter password to decrypt config (or press Enter to skip): ",
        )?;
        if password.is_empty() {
            None
        } else {
            load_config(&password)
        }
    } else {
        None
    };

    // Build a minimal OLineConfig for variable generation
    let config = if let Some(saved) = config {
        tracing::info!("  Using saved config.\n");
        saved
    } else {
        tracing::info!("  No saved config loaded. Prompting for values.\n");

        let snapshot_url = {
            let env_url = default_val_opt("OLINE_SNAPSHOT_URL", None);
            if let Some(url) = env_url {
                read_input(&mut lines, "Snapshot URL", Some(&url))?
            } else {
                match fetch_latest_snapshot_url(defaults).await {
                    Ok(url) => read_input(&mut lines, "Snapshot URL", Some(&url))?,
                    Err(_) => read_input(&mut lines, "Snapshot URL", None)?,
                }
            }
        };

        let d = default_val("OLINE_VALIDATOR_PEER_ID", None, "<VALIDATOR_PEER_ID>");
        let validator_peer_id = read_input(
            &mut lines,
            "Validator peer ID (or press Enter for placeholder)",
            Some(&d),
        )?;

        tracing::info!("  Note: S3/MinIO credentials are auto-generated per deployment.\n");
        let d = default_val("OLINE_SNAPSHOT_PATH", None, "snapshots/terpnetwork");
        let snapshot_path = read_input(&mut lines, "S3 snapshot path", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_TIME", None, "00:00:00");
        let snapshot_time = read_input(&mut lines, "Snapshot schedule time", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_SAVE_FORMAT", None, "tar.gz");
        let snapshot_save_format = read_input(&mut lines, "Snapshot save format", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_RETAIN", None, "2 days");
        let snapshot_retain = read_input(&mut lines, "Snapshot retention period", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_KEEP_LAST", None, "2");
        let snapshot_keep_last = read_input(&mut lines, "Minimum snapshots to keep", Some(&d))?;

        let d = default_val("OLINE_MINIO_IPFS_IMAGE", None, &defaults.minio_ipfs_image);
        let minio_ipfs_image = read_input(&mut lines, "MinIO-IPFS image", Some(&d))?;

        let d = default_val("OLINE_S3_BUCKET", None, "terp-snapshots");
        let s3_bucket = read_input(&mut lines, "S3 bucket name", Some(&d))?;

        let d = default_val("OLINE_AUTOPIN_INTERVAL", None, "300");
        let autopin_interval =
            read_input(&mut lines, "IPFS auto-pin interval (seconds)", Some(&d))?;

        let d = default_val(
            "OLINE_SNAPSHOT_DOWNLOAD_DOMAIN",
            None,
            "snapshots.terp.network",
        );
        let snapshot_download_domain = read_input(
            &mut lines,
            "Snapshot download domain (public S3 API)",
            Some(&d),
        )?;

        let d = default_val("OLINE_CERTBOT_EMAIL", None, "admin@terp.network");
        let certbot_email = read_input(&mut lines, "Certbot email (Let's Encrypt)", Some(&d))?;

        let d = default_val_opt("OLINE_CF_API_TOKEN", None);
        let cloudflare_api_token = if let Some(tok) = d {
            tok
        } else {
            read_input(
                &mut lines,
                "Cloudflare API token (optional, press Enter to skip)",
                Some(""),
            )?
        };

        let d = default_val_opt("OLINE_CF_ZONE_ID", None);
        let cloudflare_zone_id = if let Some(zid) = d {
            zid
        } else {
            read_input(
                &mut lines,
                "Cloudflare zone ID (optional, press Enter to skip)",
                Some(""),
            )?
        };

        let tls_config_url = default_val("TLS_CONFIG_URL", None, "2");
        let entrypoint_url = default_val("ENTRYPOINT_URL", None, "2");

        OLineConfig {
            mnemonic: String::new(),
            rpc_endpoint: String::new(),
            grpc_endpoint: String::new(),
            snapshot_url,
            validator_peer_id,
            trusted_providers: vec![],
            auto_select_provider: true,
            snapshot_path,
            snapshot_time,
            snapshot_save_format,
            snapshot_retain,
            snapshot_keep_last,
            minio_ipfs_image,
            s3_bucket,
            autopin_interval,
            snapshot_download_domain,
            certbot_email,
            cloudflare_api_token,
            cloudflare_zone_id,
            tls_config_url,
            entrypoint_url,
        }
    };

    // For phases B/C, prompt for peer IDs or use placeholders
    let needs_peers = matches!(phase.as_str(), "b" | "c" | "all");
    let (snapshot_peer, snapshot_2_peer, seed_peer, seed_2_peer) = if needs_peers {
        let sp = read_input(
            &mut lines,
            "Snapshot peer 1 (id@host:port)",
            Some("<SNAPSHOT_PEER_1>"),
        )?;
        let sp2 = read_input(
            &mut lines,
            "Snapshot peer 2 (id@host:port)",
            Some("<SNAPSHOT_PEER_2>"),
        )?;
        let sd = read_input(
            &mut lines,
            "Seed peer 1 (id@host:port)",
            Some("<SEED_PEER_1>"),
        )?;
        let sd2 = read_input(
            &mut lines,
            "Seed peer 2 (id@host:port)",
            Some("<SEED_PEER_2>"),
        )?;
        (sp, sp2, sd, sd2)
    } else {
        (String::new(), String::new(), String::new(), String::new())
    };

    // Phase B snapshot URL and statesync RPC (prompt operator — they know these after Phase A).
    let (b_snapshot_url, b_statesync_rpc) = if needs_peers {
        let snap_url = read_input(
            &mut lines,
            "Snapshot download URL (from metadata or fallback)",
            Some(&format!(
                "https://{}/{}/latest.{}",
                config.snapshot_download_domain,
                config.snapshot_path.trim_matches('/'),
                config.snapshot_save_format
            )),
        )?;
        let statesync_rpc = read_input(
            &mut lines,
            &format!(
                "Statesync RPC servers (e.g. {}:PORT,{}:PORT)",
                SNAPSHOT_RPC_DOMAIN, SEED_RPC_DOMAIN
            ),
            Some(""),
        )?;
        (snap_url, statesync_rpc)
    } else {
        (String::new(), String::new())
    };

    let needs_tackles = matches!(phase.as_str(), "c" | "all");
    let (left_tackle_peer, right_tackle_peer) = if needs_tackles {
        let lt = read_input(
            &mut lines,
            "Left tackle peer (id@host:port)",
            Some("<LEFT_TACKLE_PEER>"),
        )?;
        let rt = read_input(
            &mut lines,
            "Right tackle peer (id@host:port)",
            Some("<RIGHT_TACKLE_PEER>"),
        )?;
        (lt, rt)
    } else {
        (String::new(), String::new())
    };

    let template_defaults = HashMap::new();

    let sdl_a = defaults.load_sdl("a.kickoff-special-teams.yml")?;
    let sdl_b = defaults.load_sdl("b.left-and-right-tackle.yml")?;
    let sdl_c = defaults.load_sdl("c.left-and-right-forwards.yml")?;

    let render = |label: &str,
                  template: &str,
                  vars: &HashMap<String, String>|
     -> Result<(), Box<dyn Error>> {
        tracing::info!("\n── {} ──", label);
        let rendered = substitute_template_raw(template, vars, &template_defaults)?;
        tracing::info!("{}", rendered);
        Ok(())
    };

    match phase.as_str() {
        "a" => {
            let vars = build_phase_a_vars(&config, defaults);
            render("Phase A: Kickoff Special Teams", &sdl_a, &vars)?;
        }
        "a2" => {
            let vars = build_phase_a2_vars(&config, defaults);
            render("Phase A2: Backup Kickoff", &sdl_a, &vars)?;
        }
        "b" => {
            let vars = build_phase_b_vars(
                &config,
                &snapshot_peer,
                &snapshot_2_peer,
                &b_snapshot_url,
                &b_statesync_rpc,
                defaults,
            );
            render("Phase B: Left & Right Tackles", &sdl_b, &vars)?;
        }
        "c" => {
            let vars = build_phase_c_vars(
                &seed_peer,
                &seed_2_peer,
                &snapshot_peer,
                &snapshot_2_peer,
                &left_tackle_peer,
                &right_tackle_peer,
                defaults,
            );
            render("Phase C: Left & Right Forwards", &sdl_c, &vars)?;
        }
        "all" => {
            let a_vars = build_phase_a_vars(&config, defaults);
            render("Phase A: Kickoff Special Teams", &sdl_a, &a_vars)?;

            let a2_vars = build_phase_a2_vars(&config, defaults);
            render("Phase A2: Backup Kickoff", &sdl_a, &a2_vars)?;

            let b_vars = build_phase_b_vars(
                &config,
                &snapshot_peer,
                &snapshot_2_peer,
                &b_snapshot_url,
                &b_statesync_rpc,
                defaults,
            );
            render("Phase B: Left & Right Tackles", &sdl_b, &b_vars)?;

            let c_vars = build_phase_c_vars(
                &seed_peer,
                &seed_2_peer,
                &snapshot_peer,
                &snapshot_2_peer,
                &left_tackle_peer,
                &right_tackle_peer,
                defaults,
            );
            render("Phase C: Left & Right Forwards", &sdl_c, &c_vars)?;
        }
        _ => {
            tracing::info!("Unknown phase: {}. Choose a, a2, b, c, or all.", phase);
        }
    }

    Ok(())
}

// ── Subcommand: manage ──

async fn cmd_manage_deployments(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Manage Deployments ===\n");

    let mut store = FileDeploymentStore::new_default().await?;
    let records = store.list().await?;

    if records.is_empty() {
        tracing::info!("  No deployments found.");
        return Ok(());
    }

    tracing::info!(
        "  {:<6} {:<20} {:<18} {:<20} {:<20}",
        "DSEQ",
        "Label",
        "Step",
        "Provider",
        "Created"
    );
    tracing::info!("  {:-<90}", "");

    for r in &records {
        let provider = r
            .selected_provider
            .as_deref()
            .map(|p| {
                if p.len() > 18 {
                    format!("{}..{}", &p[..8], &p[p.len() - 4..])
                } else {
                    p.to_string()
                }
            })
            .unwrap_or_else(|| "-".into());

        let created = chrono_format_timestamp(r.created_at);

        tracing::info!(
            "  {:<6} {:<20} {:<18} {:<20} {:<20}",
            r.dseq,
            truncate(&r.label, 20),
            r.step.name(),
            provider,
            created,
        );
    }

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let dseq_str = read_input(&mut lines, "Enter DSEQ to manage (or 'q' to quit)", None)?;
    if dseq_str == "q" || dseq_str.is_empty() {
        return Ok(());
    }

    let dseq: u64 = dseq_str.parse().map_err(|_| "Invalid DSEQ number")?;

    let record = records.iter().find(|r| r.dseq == dseq);
    if record.is_none() {
        tracing::info!("  No record found for DSEQ {}", dseq);
        return Ok(());
    }

    tracing::info!("\n  Actions:");
    tracing::info!("    1. Close deployment");
    tracing::info!("    2. View record (JSON)");
    tracing::info!("    3. Update SDL (not yet implemented)");

    let action = read_input(&mut lines, "Select action", None)?;

    match action.as_str() {
        "1" => {
            if !prompt_continue(&mut lines, &format!("Close deployment DSEQ {}?", dseq))? {
                tracing::info!("  Cancelled.");
                return Ok(());
            }

            let (mnemonic, _password) = unlock_mnemonic(defaults)?;

            // Load saved config for RPC/gRPC endpoints
            let (rpc, grpc) = if has_saved_config() {
                let pw = rpassword::prompt_password("Enter config password: ")?;
                if let Some(cfg) = load_config(&pw) {
                    (cfg.rpc_endpoint, cfg.grpc_endpoint)
                } else {
                    let rpc = read_input(
                        &mut lines,
                        "RPC endpoint",
                        Some("https://rpc.akashnet.net:443"),
                    )?;
                    let grpc = read_input(
                        &mut lines,
                        "gRPC endpoint",
                        Some("https://grpc.akashnet.net:443"),
                    )?;
                    (rpc, grpc)
                }
            } else {
                let rpc = read_input(
                    &mut lines,
                    "RPC endpoint",
                    Some("https://rpc.akashnet.net:443"),
                )?;
                let grpc = read_input(
                    &mut lines,
                    "gRPC endpoint",
                    Some("https://grpc.akashnet.net:443"),
                )?;
                (rpc, grpc)
            };

            let client = AkashClient::new_from_mnemonic(&mnemonic, &rpc, &grpc).await?;
            let signer = KeySigner::new_mnemonic_str(&mnemonic, None)
                .map_err(|e| format!("Failed to create signer: {}", e))?;

            tracing::info!("  Closing deployment DSEQ {}...", dseq);
            let result = client
                .broadcast_close_deployment(&signer, &client.address(), dseq)
                .await?;

            tracing::info!("  Closed! TX hash: {}", result.hash);

            store.delete(dseq).await?;
            tracing::info!("  Record removed from store.");
        }
        "2" => {
            let json = serde_json::to_string_pretty(record.unwrap())?;
            tracing::info!("\n{}", json);
        }
        "3" => {
            tracing::info!("  Update SDL is not yet implemented.");
        }
        _ => {
            tracing::info!("  Unknown action.");
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

fn chrono_format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "-".to_string();
    }
    // Simple UTC timestamp formatting without chrono dependency
    let secs = ts;
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;

    // Rough date from epoch (good enough for display)
    // 1970-01-01 + days
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}Z",
        year, month, day, hours, mins
    )
}

// ── Main menu ──

async fn cmd_main_menu(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    let store = FileDeploymentStore::new_default().await?;
    let records = store.list().await.unwrap_or_default();
    let has_deployments = !records.is_empty();

    tracing::info!("=== O-Line Deployer ===\n");
    tracing::info!("  1. Deploy (full automated deployment)");
    tracing::info!("  2. Generate SDL (render & print, no broadcast)");
    if has_deployments {
        tracing::info!("  3. Manage Deployments ({} active)", records.len());
    }
    tracing::info!("  4. Test S3 Connection");
    tracing::info!("  5. Encrypt Mnemonic");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let choice = read_input(&mut lines, "\nSelect option", None)?;
    drop(lines);

    match choice.as_str() {
        "1" => cmd_deploy(false, defaults).await,
        "2" => cmd_generate_sdl(defaults).await,
        "3" if has_deployments => cmd_manage_deployments(defaults).await,
        "4" => cmd_test_s3(defaults).await,
        "5" => cmd_encrypt(defaults),
        _ => {
            tracing::info!("Invalid option.");
            Ok(())
        }
    }
}

// ── Main ──

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    load_dotenv(
        &std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into()),
    );

    // Now build runtime defaults (reads env vars, including those just loaded from .env)
    let defaults = RuntimeDefaults::load();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("encrypt") => cmd_encrypt(&defaults),
        Some("deploy") => {
            let raw = args.get(2).map(|s| s.as_str()) == Some("--raw");
            cmd_deploy(raw, &defaults).await
        }
        Some("sdl") | Some("generate-sdl") => cmd_generate_sdl(&defaults).await,
        Some("manage") => cmd_manage_deployments(&defaults).await,
        Some("test-s3") => cmd_test_s3(&defaults).await,
        None => cmd_main_menu(&defaults).await,
        Some(other) => {
            tracing::info!("Unknown command: {}", other);
            tracing::info!("Usage:");
            tracing::info!("  oline                 Interactive main menu");
            tracing::info!("  oline encrypt         Encrypt mnemonic and store in .env");
            tracing::info!("  oline deploy          Deploy using encrypted mnemonic from .env");
            tracing::info!(
                "  oline deploy --raw    Deploy with mnemonic entered directly (hidden)"
            );
            tracing::info!("  oline sdl             Generate SDL templates (render & preview)");
            tracing::info!("  oline manage          Manage active deployments");
            tracing::info!("  oline test-s3         Test S3 bucket connectivity");
            std::process::exit(1);
        }
    }
}
