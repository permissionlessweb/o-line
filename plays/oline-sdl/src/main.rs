use akash_deploy_rs::{
    AkashBackend, AkashClient, Bid, DeployError, DeploymentRecord, DeploymentState,
    DeploymentStore, DeploymentWorkflow, FileDeploymentStore, InputRequired, KeySigner,
    ProviderInfo, ServiceEndpoint, StepResult, WorkflowConfig,
};

use o_line_sdl::{
    self, akash::*, cli::*, config::*, crypto::*, dns::cloudflare::*, snapshots::*,
    FIELD_DESCRIPTORS,
};

use std::{
    collections::HashMap,
    env::var,
    error::Error,
    fs,
    io::{self, BufRead, Write},
    path::PathBuf,
};

pub struct OLineDeployer {
    client: AkashClient,
    signer: KeySigner,
    config: OLineConfig,
    password: String,
    deployment_store: FileDeploymentStore,
}

impl OLineDeployer {
    pub async fn new(config: OLineConfig, password: String) -> Result<Self, DeployError> {
        Ok(Self {
            client: AkashClient::new_from_mnemonic(
                &config.mnemonic,
                &config.val("network.rpc_endpoint"),
                &config.val("network.grpc_endpoint"),
            )
            .await?,
            signer: KeySigner::new_mnemonic_str(&config.mnemonic, None)
                .map_err(|e| DeployError::Signer(format!("Failed to create signer: {}", e)))?,
            config,
            password,
            deployment_store: FileDeploymentStore::new_default().await?,
        })
    }

    fn workflow_config(&self) -> WorkflowConfig {
        WorkflowConfig::default()
    }

    pub async fn deploy_phase_with_selection(
        &self,
        sdl_template: &str,
        variables: &HashMap<String, String>,
        label: &str,
        lines: &mut io::Lines<io::StdinLock<'_>>,
    ) -> Result<(DeploymentState, Vec<ServiceEndpoint>), DeployError> {
        // Pre-render template using raw substitution so ${VAR} in YAML keys
        // (like service names) are replaced before any YAML parsing.
        let rendered_sdl = substitute_template_raw(sdl_template, &variables)
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
        let a_vars = build_phase_a_vars(&self.config).await;
        tracing::info!("  Deploying...");
        let (a_state, a_endpoints) = self
            .deploy_phase_with_selection(
                &self.config.load_sdl("a.kickoff-special-teams.yml")?,
                &a_vars,
                "oline-phase-a",
                &mut lines,
            )
            .await?;

        tracing::info!("Deployed! DSEQ: {}", a_state.dseq.unwrap());
        self.deployment_store
            .save(&DeploymentRecord::from_state(&a_state, &self.password)?)
            .await
            .ok();

        if !self.config.val("cloudflare.api_token").is_empty()
            && !self.config.val("cloudflare.zone_id").is_empty()
        {
            tracing::info!("  Updating Cloudflare DNS for accept domains...");
            if let Some(sdl) = &a_state.sdl_content {
                cloudflare_update_accept_domains(
                    sdl,
                    &a_endpoints,
                    &self.config.val("cloudflare.api_token"),
                    &self.config.val("cloudflare.zone_id"),
                )
                .await;
            }
        } else {
            tracing::info!("  Note: Cloudflare DNS not configured — update CNAMEs for accept domains manually.");
        }

        // ── Use SFTP to transfer wildcard certs ──
        tracing::info!("  Provisioning TLS certificates via SFTP...");
        let secrets_path = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        let ssh_key_path: PathBuf = format!("{}/{}", secrets_path, a_state.dseq.unwrap()).into();
        let cert_path = format!("{}/cert.pem", secrets_path);
        let privkey_path = format!("{}/privkey.pem", secrets_path);
        let cert = fs::read(&cert_path)
            .map_err(|e| format!("Failed to read wildcard cert from '{}': {}", cert_path, e))?;
        let privkey = fs::read(&privkey_path).map_err(|e| {
            format!(
                "Failed to read wildcard privkey from '{}': {}",
                privkey_path, e
            )
        })?;
        let ssh_privkey_pem = a_vars
            .get("SSH_PRIVKEY")
            .ok_or("SSH_PRIVKEY missing from phase-A vars")?;

        push_tls_certs_sftp(
            "phase-a-snapshot",
            &a_endpoints,
            ssh_privkey_pem,
            &ssh_key_path,
            &cert,
            &privkey,
        )
        .await?;

        // ── SSH verify: confirm certs landed + signal bootstrap to proceed ──
        let remote_cert = var("TLS_REMOTE_CERT_PATH").unwrap_or_else(|_| "/tmp/tls/cert.pem".into());
        let remote_key = var("TLS_REMOTE_KEY_PATH").unwrap_or_else(|_| "/tmp/tls/privkey.pem".into());
        verify_certs_and_signal_start(
            "phase-a-snapshot",
            &a_endpoints,
            &ssh_key_path,
            &remote_cert,
            &remote_key,
        )
        .await?;

        // ── SFTP TLS certs to minio-ipfs node ──
        // init-nginx on the minio node bootstraps sshd and polls /tmp/tls/ for certs.
        // Once certs land, it renders the nginx config and exits — svc-nginx starts nginx.
        tracing::info!("  Provisioning TLS certificates to minio-ipfs node via SFTP...");
        let minio_endpoints: Vec<ServiceEndpoint> = a_endpoints
            .iter()
            .filter(|e| e.service == "oline-a-minio-ipfs")
            .cloned()
            .collect();
        if minio_endpoints.is_empty() {
            tracing::info!("  Warning: no endpoints found for oline-a-minio-ipfs — skipping cert delivery");
        } else {
            push_tls_certs_sftp(
                "phase-a-minio",
                &minio_endpoints,
                ssh_privkey_pem,
                &ssh_key_path,
                &cert,
                &privkey,
            )
            .await?;
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
            self.config.val("snapshot.download_domain"),
            self.config.val("snapshot.path").trim_matches('/'),
            self.config.val("snapshot.save_format")
        );
        let b_snapshot_metadata_url = format!(
            "https://{}/{}/snapshot.json",
            self.config.val("snapshot.download_domain"),
            self.config.val("snapshot.path").trim_matches('/'),
        );
        let b_snapshot_url =
            fetch_snapshot_url_from_metadata(&b_snapshot_metadata_url, &b_snapshot_fallback).await;
        tracing::info!("  Phase B snapshot URL: {}", b_snapshot_url);

        let b_vars = build_phase_b_vars(
            &self.config,
            &snapshot_peer,
            &b_snapshot_url,
            &a1_statesync_rpc,
        );

        tracing::info!("  Variables:");
        for (k, v) in &b_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v,));
        }

        let sdl_b = self.config.load_sdl("b.left-and-right-tackle.yml")?;
        tracing::info!("  Deploying...");
        let (b_state, b_endpoints) = self
            .deploy_phase_with_selection(&sdl_b, &b_vars, "oline-phase-b", &mut lines)
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
            &self.config,
            &seed_peer,
            &snapshot_peer,
            &left_tackle_peer,
            &right_tackle_peer,
        );

        tracing::info!("  Variables:");
        for (k, v) in &c_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v,));
        }

        let sdl_c = self.config.load_sdl("c.left-and-right-forwards.yml")?;
        tracing::info!("  Deploying...");
        let (c_state, _c_endpoints) = self
            .deploy_phase_with_selection(&sdl_c, &c_vars, "oline-phase-c", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", c_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&c_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        tracing::info!("\n=== All deployments complete! ===");
        tracing::info!("  Phase A1 DSEQ: {}", a_state.dseq.unwrap_or(0));
        tracing::info!("  Phase B  DSEQ: {}", b_state.dseq.unwrap_or(0));
        tracing::info!("  Phase C  DSEQ: {}", c_state.dseq.unwrap_or(0));
        Ok(())
    }
}

// ── Unlock mnemonic helper ──

// ── Subcommand: deploy ──
async fn cmd_deploy(raw: bool) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Welcome to O-Line Deployer ===\n");

    let (mnemonic, password) = if raw {
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        let password = rpassword::prompt_password("Enter a password (for config encryption): ")?;
        (m.trim().to_string(), password)
    } else {
        unlock_mnemonic()?
    };

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let config = collect_config(&password, mnemonic, &mut lines).await?;

    // Drop the stdin lock before OLineDeployer::run() re-acquires it
    drop(lines);

    let mut deployer = OLineDeployer::new(config, password).await?;
    deployer.run().await
}

// ── Subcommand: generate-sdl ──
async fn cmd_generate_sdl() -> Result<(), Box<dyn Error>> {
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
    let saved = if has_saved_config() {
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

    let config = if let Some(saved) = saved {
        tracing::info!("  Using saved config.\n");
        saved
    } else {
        tracing::info!("  No saved config loaded. Prompting for values.\n");
        let mut cfg = OLineConfig {
            ..Default::default()
        };
        for fd in FIELD_DESCRIPTORS.iter() {
            let resolved = std::env::var(fd.ev)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| fd.d.to_string());

            let value = if fd.d == "" && resolved.is_empty() {
                read_input(&mut lines, fd.p, Some(""))?
            } else if fd.s && !resolved.is_empty() {
                resolved
            } else {
                read_input(&mut lines, fd.p, Some(&resolved))?
            };

            cfg.category_mut(fd.c).set(fd.k, value);
        }
        cfg
    };
    // For phases B/C, prompt for peer IDs or use placeholders
    let needs_peers = matches!(phase.as_str(), "b" | "c" | "all");
    let (snapshot_peer, seed_peer) = if needs_peers {
        let sp = read_input(
            &mut lines,
            "Snapshot peer 1 (id@host:port)",
            Some("<SNAPSHOT_PEER_1>"),
        )?;

        let sd = read_input(
            &mut lines,
            "Seed peer 1 (id@host:port)",
            Some("<SEED_PEER_1>"),
        )?;

        (sp, sd)
    } else {
        (String::new(), String::new())
    };

    // Phase B snapshot URL and statesync RPC (prompt operator — they know these after Phase A).
    let (snapshot_url, statesync_rpc) = if needs_peers {
        let snap_url = read_input(
            &mut lines,
            "Snapshot download URL (from metadata or fallback)",
            Some(&format!(
                "https://{}/{}/latest.{}",
                config.val("snapshot.download_domain"),
                config.val("snapshot.path").trim_matches('/'),
                config.val("snapshot.save_format")
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

    let sdl_a = config.load_sdl("a.kickoff-special-teams.yml")?;
    let sdl_b = config.load_sdl("b.left-and-right-tackle.yml")?;
    let sdl_c = config.load_sdl("c.left-and-right-forwards.yml")?;

    let render = |label: &str,
                  template: &str,
                  vars: &HashMap<String, String>|
     -> Result<(), Box<dyn Error>> {
        tracing::info!("\n── {} ──", label);
        let rendered = substitute_template_raw(template, vars)?;
        tracing::info!("{}", rendered);
        Ok(())
    };

    match phase.as_str() {
        "a" => {
            let vars = build_phase_a_vars(&config).await;
            render("Phase A: Kickoff Special Teams", &sdl_a, &vars)?;
        }
        "b" => {
            let vars = build_phase_b_vars(&config, &snapshot_peer, &snapshot_url, &statesync_rpc);
            render("Phase B: Left & Right Tackles", &sdl_b, &vars)?;
        }
        "c" => {
            let vars = build_phase_c_vars(
                &config,
                &seed_peer,
                &snapshot_peer,
                &left_tackle_peer,
                &right_tackle_peer,
            );
            render("Phase C: Left & Right Forwards", &sdl_c, &vars)?;
        }
        "all" => {
            let (a, b, c) = (
                build_phase_a_vars(&config).await,
                build_phase_b_vars(&config, &snapshot_peer, &snapshot_url, &statesync_rpc),
                build_phase_c_vars(
                    &config,
                    &seed_peer,
                    &snapshot_peer,
                    &left_tackle_peer,
                    &right_tackle_peer,
                ),
            );
            render("Phase A: Kickoff Special Teams", &sdl_a, &a)?;
            render("Phase B: Left & Right Tackles", &sdl_b, &b)?;
            render("Phase C: Left & Right Forwards", &sdl_c, &c)?;
        }
        _ => {
            tracing::info!("Unknown phase: {}. Choose a, a2, b, c, or all.", phase);
        }
    }

    Ok(())
}

// ── Subcommand: manage ──
async fn cmd_manage_deployments() -> Result<(), Box<dyn Error>> {
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

    let mut lines = io::stdin().lock().lines();
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
    match read_input(&mut lines, "Select action", None)?.as_str() {
        "1" => {
            if !prompt_continue(&mut lines, &format!("Close deployment DSEQ {}?", dseq))? {
                tracing::info!("  Cancelled.");
                return Ok(());
            }

            let (mnemonic, _password) = unlock_mnemonic()?;

            // Load saved config for RPC/gRPC endpoints
            let (rpc, grpc) = if has_saved_config() {
                let pw = rpassword::prompt_password("Enter config password: ")?;
                if let Some(cfg) = load_config(&pw) {
                    (cfg.val("network.rpc_endpoint"), cfg.val("network.grpc_endpoint"))
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

// ── Subcommand: encrypt ──
pub fn cmd_encrypt() -> Result<(), Box<dyn Error>> {
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
    write_encrypted_mnemonic_to_env(&blob)?;

    tracing::info!("\nEncrypted mnemonic written to .env");
    tracing::info!("You can now run `oline deploy` to deploy using your encrypted mnemonic.");
    Ok(())
}

// ── Main menu ──
async fn cmd_main_menu() -> Result<(), Box<dyn Error>> {
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
        "1" => cmd_deploy(false).await,
        "2" => cmd_generate_sdl().await,
        "3" if has_deployments => cmd_manage_deployments().await,
        "4" => cmd_test_s3().await,
        "5" => cmd_encrypt(),
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

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("encrypt") => cmd_encrypt(),
        Some("deploy") => {
            let raw = args.get(2).map(|s| s.as_str()) == Some("--raw");
            cmd_deploy(raw).await
        }
        Some("sdl") | Some("generate-sdl") => cmd_generate_sdl().await,
        Some("manage") => cmd_manage_deployments().await,
        Some("test-s3") => cmd_test_s3().await,
        None => cmd_main_menu().await,
        Some(other) => {
            tracing::info!("Unknown command: {}", other);
            tracing::info!("Usage:");
            tracing::info!("  oline                 Interactive main menu");
            tracing::info!("  oline encrypt         Encrypt mnemonic and store in .env");
            tracing::info!("  oline deploy          Deploy using encrypted mnemonic from .env");
            tracing::info!("  oline sdl             Generate SDL templates (render & preview)");
            tracing::info!("  oline manage          Manage active deployments");
            tracing::info!("  oline test-s3         Test S3 bucket connectivity");
            std::process::exit(1);
        }
    }
}

#[test]
fn test_field_descriptors() {
    for fd in FIELD_DESCRIPTORS.iter() {
        println!("{:#?}", fd);
        let mut cfg = OLineConfig::default();
        let resolved = std::env::var(fd.ev)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| fd.d.to_string());

        let value = if fd.d == "" && resolved.is_empty() {
            "".to_string()
        } else if fd.s && !resolved.is_empty() {
            resolved
        } else {
            "".to_string()
        };

        cfg.category_mut(fd.c).set(fd.k, value);
    }
}
