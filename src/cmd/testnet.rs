//! `oline testnet-deploy` — bootstrap a fresh testnet on Akash Network.
//!
//! Deploys an nginx load balancer + 2 sentry nodes as a single Akash
//! deployment. The LB proxies RPC/API/gRPC to the sentry pool via Akash
//! inter-service routing. An external validator (or Phase V localterp
//! validator) provides genesis and P2P peering.
//!
//! Architecture:
//! ```text
//! Single Akash deployment:
//!   [nginx LB]         ← port 80 global, routes by Host header
//!   [Sentry A]         ← internal only (ports exposed to LB service)
//!   [Sentry B]         ← internal only (ports exposed to LB service)
//! ```
//!
//! Two-pass deployment: Pass 1 creates the deployment and collects bids,
//! Pass 2 resumes with --provider-a to accept lease + send manifest.
//! LB init script and sentry scripts are delivered via SFTP at bootstrap.

use crate::{
    config::{build_config_from_env, collect_config, OLineConfig},
    crypto::{
        ensure_ssh_key_encrypted, generate_credential, push_scripts_sftp,
        verify_files_and_signal_start,
    },
    deployer::OLineDeployer,
    with_examples, MAX_RETRIES,
};
use akash_deploy_rs::{
    broadcast_multi_signer, build_create_lease_msg, AkashBackend, AkashClient, Bid, BidId,
    DeploymentRecord, DeploymentStore, DeploymentWorkflow, FileDeploymentStore, ServiceEndpoint,
    SignerEntry, Step,
};
use std::{
    collections::HashMap,
    error::Error,
    io::{self, BufRead},
    path::PathBuf,
};

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct TestnetDeployArgs {
        /// Use fast blocks (200ms timeouts) on the validator
        #[arg(long)]
        pub fast_blocks: bool,

        /// Testnet chain ID (default: testnet-1)
        #[arg(long, default_value = "testnet-1")]
        pub chain_id: String,

        /// localterp Docker image (must be pre-built and pushed to a registry)
        #[arg(long, env = "LOCALTERP_IMAGE", default_value = "ghcr.io/permissionlessweb/localterp:latest")]
        pub localterp_image: String,

        /// Enter raw mnemonic directly (skip encrypted .env)
        #[arg(long)]
        pub raw: bool,

        /// Skip interactive prompts — use env vars + defaults
        #[arg(long)]
        pub non_interactive: bool,

        /// Config profile to use (default: testnet for testnet-deploy)
        #[arg(long, default_value = "testnet")]
        pub profile: String,

        /// Resume from saved state — accept leases for previously created deployments.
        /// Requires --provider-a (and optionally --provider-b, --provider-c).
        #[arg(long)]
        pub resume: bool,

        /// Provider address for Phase A (snapshot+seed). Used with --resume.
        #[arg(long)]
        pub provider_a: Option<String>,

        /// Provider address for Phase B (tackles). Used with --resume.
        #[arg(long)]
        pub provider_b: Option<String>,

        /// Provider address for Phase C (forwards). Used with --resume.
        #[arg(long)]
        pub provider_c: Option<String>,

        /// Use an external validator instead of deploying one (skip Phase V).
        /// Sentries sync from genesis independently; wire validator persistent_peers after deploy.
        /// Format: <RPC_URL> e.g. https://rpc-testnet.terp.network
        #[arg(long)]
        pub validator_rpc: Option<String>,

        /// External validator P2P peer address. Required with --validator-rpc.
        /// Format: <node_id>@<host>:<port>
        #[arg(long)]
        pub validator_peer: Option<String>,
        /// Dseq
        #[arg(long)]
        pub dseq: u64,
    }
    => "../../docs/examples/testnet.md"
}

pub async fn cmd_testnet_deploy(args: &TestnetDeployArgs) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== O-Line Testnet Deploy ===\n");
    tracing::info!("  Chain ID:       {}", args.chain_id);
    tracing::info!("  Localterp:      {}", args.localterp_image);
    tracing::info!("  Fast blocks:    {}", args.fast_blocks);

    // ── 1. Unlock mnemonic + build config ────────────────────────────────────
    // AuthZ check first (passwordless)
    let no_authz = std::env::var("OLINE_NO_AUTHZ").is_ok();
    let authz_state = if !no_authz {
        crate::authz::load_authz_state()
    } else {
        None
    };

    let non_interactive = args.non_interactive
        || std::env::var("OLINE_NON_INTERACTIVE").is_ok()
        || authz_state.is_some();

    let (mnemonic, password, authz_granter) = if let Some(ref state) = authz_state {
        let m =
            crate::authz::load_deployer_mnemonic().map_err(|e| -> Box<dyn Error> { e.into() })?;
        tracing::info!(
            "Using AuthZ delegation (deployer → {})",
            state.granter_address
        );
        (m, String::new(), Some(state.granter_address.clone()))
    } else if non_interactive {
        let p = std::env::var("OLINE_PASSWORD").unwrap_or_else(|_| "oline-test".to_string());
        let m = if let Some(raw) = std::env::var("OLINE_MNEMONIC")
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
            raw.trim().to_string()
        } else {
            use crate::crypto::decrypt_mnemonic;
            let blob = crate::config::read_encrypted_mnemonic()
                .map_err(|_| "OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC or an encrypted mnemonic at ~/.oline/mnemonic.enc")?;
            decrypt_mnemonic(&blob, &p)
                .map_err(|e| format!("Failed to decrypt mnemonic: {}. Check OLINE_PASSWORD.", e))?
        };
        println!("boom");
        (m, p, None)
    } else if args.raw {
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        let p = rpassword::prompt_password("Enter password: ")?;
        (m.trim().to_string(), p, None)
    } else {
        let (m, p) = crate::cli::unlock_mnemonic()?;
        (m, p, None)
    };

    let config = if non_interactive {
        build_config_from_env(mnemonic, Some(&args.profile))
    } else {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        let cfg = collect_config(&password, mnemonic, &mut lines, Some(&args.profile)).await?;
        drop(lines);
        cfg
    };
    println!("bap");
    // ── 2. Create deployer + preflight ───────────────────────────────────────
    let deployer = if let Some(granter) = authz_granter {
        OLineDeployer::new_authz(config.clone(), granter).await
    } else {
        OLineDeployer::new(config.clone(), password.clone()).await
    }
    .map_err(|e| -> Box<dyn Error> { e.into() })?;

    deployer
        .preflight_check()
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    println!("brup");
    // ── 3. Shared setup ──────────────────────────────────────────────────────────────────────
    // In AuthZ mode, derive a deterministic password from the deployer mnemonic
    // for SSH key encryption (since no user password is available).
    let effective_password = if password.is_empty() {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(deployer.config.mnemonic.as_bytes());
        hex::encode(&hash[..16])
    } else {
        password.clone()
    };
    std::env::set_var("OLINE_PASSWORD", &effective_password);
    println!("bop");
    // TODO: needs conditionals for when using/not using authz
    let secrets_path = crate::config::oline_config_dir();
    let ssh_key_path: PathBuf = secrets_path.join("oline-testnet-key");
    let ssh_key = ensure_ssh_key_encrypted(&ssh_key_path, &effective_password)?;
    let ssh_pubkey = ssh_key.public_key().to_string();
    println!("bip");
    // ── 4. Validator: external or deploy Phase V ────────────────────────────────
    if let Some(ref ext_rpc) = args.validator_rpc {
        tracing::info!("\n── Using external validator (skip Phase V) ──");
        tracing::info!("  RPC: {}", ext_rpc);
        if let Some(ref peer) = args.validator_peer {
            tracing::info!("  Peer: {}", peer);
        }

        // Verify validator is reachable
        let status: serde_json::Value =
            reqwest::get(&format!("{}/status", ext_rpc.trim_end_matches('/')))
                .await?
                .json()
                .await
                .map_err(|e| format!("Cannot reach validator RPC: {}", e))?;
        let height = status["result"]["sync_info"]["latest_block_height"]
            .as_str()
            .unwrap_or("0");
        let catching_up = status["result"]["sync_info"]["catching_up"]
            .as_bool()
            .unwrap_or(true);
        tracing::info!(
            "  Validator height: {}, catching_up: {}",
            height,
            catching_up
        );
        if catching_up {
            return Err(
                "Validator is still catching up — wait until synced before deploying sentries."
                    .into(),
            );
        }
    }

    let genesis_url = config.val("GENESIS_URL");
    if genesis_url.is_empty() {
        return Err("genesis_url not set in config.toml testnet profile ([profiles.testnet.chain] genesis_url = ...)".into());
    }
    tracing::info!("  Genesis URL: {}", genesis_url);
    println!("banp");
    // ── 5. Build LB var set ───────────────────────────────────────────────────
    let sdl_lb = config
        .load_sdl("testnet-lb.yml")
        .map_err(|e| -> Box<dyn Error> { e })?;
    let lb_vars = build_testnet_lb_vars(&config, &args.chain_id, &genesis_url, &ssh_pubkey);

    // ── 8. Two-pass deployment: single LB deployment ─────────────────────���────
    let mut store = FileDeploymentStore::new_default()
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    let lb_endpoints;

    if args.resume {
        let dseq = args.dseq;
        // ── Pass 2: Resume — load saved state and accept lease ───────────────
        let pa = args
            .provider_a
            .as_deref()
            .ok_or("--resume requires --provider-a")?;

        // find by dseq
        let all_records: Vec<DeploymentRecord> = store
            .list()
            .await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        let lb_rec = all_records
            .iter()
            .find(|r| r.dseq == dseq && matches!(r.step, Step::SelectProvider))
            .ok_or("No saved LB deployment at SelectProvider step. Run without --resume first.")?;

        tracing::info!("\n── Resuming LB deployment ──");
        tracing::info!("  LB: dseq={}", lb_rec.dseq);

        let mut state_lb = lb_rec
            .clone()
            .to_state("testnet-lb", &effective_password)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        DeploymentWorkflow::<AkashClient>::select_provider(&mut state_lb, pa)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;

        // Create lease
        tracing::info!("\n── Lease acceptance ──");
        // alwaswy set owner to granter if present
        let owner = match &deployer.authz_context {
            Some(az) => az.granter_address.clone(),
            None => deployer.client.address(),
        };

        let bid = find_bid_for_provider(&state_lb.bids, pa)?;
        let bid_id = BidId::from_bid(
            &owner,
            state_lb.dseq.unwrap(),
            state_lb.gseq,
            state_lb.oseq,
            &bid,
        );
        println!("{:#?}", bid);
        println!("{:#?}", bid_id);

        let querier = &deployer.client.signing_client().querier;
        let acct = querier
            .base_account(&layer_climb_address::Address::new_cosmos_string(
                &owner, None,
            )?)
            .await
            .map_err(|e| format!("base_account: {}", e))?;
        let chain_id = querier.chain_config.chain_id.as_str();
        println!("{:#?}", acct);
        let lease_msg = build_create_lease_msg(&bid_id);
        println!("{:#?}", lease_msg);
        let signer_entries = vec![SignerEntry {
            signer: &deployer.signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: vec![lease_msg],
        }];

        let lease_tx = broadcast_multi_signer(
            querier,
            chain_id,
            signer_entries,
            1.5,
            std::time::Duration::from_secs(60),
        )
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

        tracing::info!(
            "  Lease tx: hash={}, height={}",
            lease_tx.hash,
            lease_tx.height
        );

        state_lb.record_tx(&lease_tx.hash);
        state_lb.lease_id = Some(bid_id.into());
        state_lb.transition(Step::SendManifest);

        // Regenerate JWT auth
        let jwt = deployer
            .client
            .generate_jwt(&deployer.client.address())
            .await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        state_lb.jwt_token = Some(jwt);

        // Send manifest + get endpoints
        tracing::info!("\n── Sending manifest ──");
        lb_endpoints = deployer
            .deploy_phase_complete(&mut state_lb, "testnet-lb")
            .await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;

        // Save completed state (with lease_id + endpoints) back to store
        let record = DeploymentRecord::from_state(&state_lb, &effective_password)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        store
            .save(&record)
            .await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        tracing::info!(
            "  State saved (dseq={}, step=Complete)",
            state_lb.dseq.unwrap_or(0)
        );
    } else {
        // ── Pass 1: Create deployment, collect bids, save state, exit ─────────
        tracing::info!("\n── Creating LB deployment (LB + 2 sentries) ──");

        let (state_lb, bids_lb) = deployer
            .deploy_phase_until_bids(&sdl_lb, &lb_vars, "testnet-lb")
            .await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        tracing::info!(
            "  LB: {} bid(s), dseq={}",
            bids_lb.len(),
            state_lb.dseq.unwrap_or(0)
        );

        // Save state
        let record = DeploymentRecord::from_state(&state_lb, &effective_password)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        store
            .save(&record)
            .await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;

        // Display bids
        tracing::info!("\n════════════════════════════════════════════════���═════════════");
        tracing::info!("  BIDS RECEIVED — review and re-run with --resume");
        tracing::info!("═════════���════════════════════════════════════════════════════");

        display_phase_bids(&deployer, "LB", state_lb.dseq.unwrap_or(0), &bids_lb).await;

        tracing::info!("\n── Resume command ──");
        tracing::info!("  oline testnet-deploy \\");
        tracing::info!("    --profile {} \\", args.profile);
        tracing::info!("    --chain-id {} \\", args.chain_id);
        tracing::info!("    --resume \\");
        tracing::info!("    --provider-a <PROVIDER_ADDRESS>");

        tracing::info!("\nState saved. Deployment will remain open and accepting bids.");
        return Ok(());
    }

    // ── 9. Bootstrap LB + sentries via SSH ─────────────────��─────────────────
    tracing::info!("\n── Bootstrapping LB + sentries ──");
    let scripts_home = crate::config::oline_config_dir().join("scripts");
    let scripts_path = if scripts_home.exists() {
        scripts_home.to_string_lossy().into_owned()
    } else {
        "plays/audible".into()
    };

    let sentry_a_svc = lb_vars
        .get("SENTRY_A_SVC")
        .map(|s| s.as_str())
        .unwrap_or("testnet-sentry-a");
    let sentry_b_svc = lb_vars
        .get("SENTRY_B_SVC")
        .map(|s| s.as_str())
        .unwrap_or("testnet-sentry-b");

    // LB (nginx:alpine) init is fully inline via SDL env vars — no SSH bootstrap needed.
    tracing::info!("  [testnet-lb] LB init is inline (nginx:alpine) — skipping SSH bootstrap");

    // Bootstrap sentry-a
    let sentry_a_eps: Vec<_> = lb_endpoints
        .iter()
        .filter(|e| e.service == sentry_a_svc)
        .cloned()
        .collect();
    if !sentry_a_eps.is_empty() {
        bootstrap_sentry(
            "testnet-sentry-a",
            &sentry_a_eps,
            &ssh_key_path,
            &scripts_path,
            None,
            &lb_vars,
        )
        .await?;
    }

    // Bootstrap sentry-b
    let sentry_b_eps: Vec<_> = lb_endpoints
        .iter()
        .filter(|e| e.service == sentry_b_svc)
        .cloned()
        .collect();
    if !sentry_b_eps.is_empty() {
        bootstrap_sentry(
            "testnet-sentry-b",
            &sentry_b_eps,
            &ssh_key_path,
            &scripts_path,
            None,
            &lb_vars,
        )
        .await?;
    }

    // ── 10. Summary + validator wiring instructions ───────────────────────────
    let sentry_a_p2p = lb_endpoints
        .iter()
        .find(|e| e.service == sentry_a_svc && e.internal_port == 26656)
        .map(|e| format!("{}:{}", e.uri, e.port))
        .unwrap_or_default();
    let sentry_b_p2p = lb_endpoints
        .iter()
        .find(|e| e.service == sentry_b_svc && e.internal_port == 26656)
        .map(|e| format!("{}:{}", e.uri, e.port))
        .unwrap_or_default();

    tracing::info!("\n════════════════════════════════════════════════════════════");
    tracing::info!("  TESTNET DEPLOYED SUCCESSFULLY (LB mode)");
    tracing::info!("════════════════════════════════════════════════════════════");
    tracing::info!("  Chain ID:    {}", args.chain_id);
    tracing::info!("  Genesis URL: {}", genesis_url);

    tracing::info!("\n  ── LB Endpoints ──");
    for ep in &lb_endpoints {
        tracing::info!(
            "    {}:{} → {}:{}",
            ep.service,
            ep.internal_port,
            ep.uri,
            ep.port
        );
    }

    tracing::info!("\n  ── Wire your local validator to the sentries ──");
    tracing::info!("  After terpd init, get sentry node IDs:");
    tracing::info!(
        "    ssh -p <PORT> root@{} terpd tendermint show-node-id",
        sentry_a_p2p.split(':').next().unwrap_or("SENTRY_A_HOST")
    );
    tracing::info!(
        "    ssh -p <PORT> root@{} terpd tendermint show-node-id",
        sentry_b_p2p.split(':').next().unwrap_or("SENTRY_B_HOST")
    );
    tracing::info!("  Then start your validator with:");
    tracing::info!(
        "    terpd start --p2p.persistent_peers <A_NODE_ID>@{},<B_NODE_ID>@{}",
        sentry_a_p2p,
        sentry_b_p2p
    );
    tracing::info!("════════════════════════════════════════════════════════════\n");

    Ok(())
}

fn build_testnet_lb_vars(
    config: &OLineConfig,
    chain_id: &str,
    genesis_url: &str,
    ssh_pubkey: &str,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    // Service names
    vars.insert("LB_SVC".into(), "testnet-lb".into());
    vars.insert("SENTRY_A_SVC".into(), "testnet-sentry-a".into());
    vars.insert("SENTRY_B_SVC".into(), "testnet-sentry-b".into());

    // Chain
    vars.insert("TESTNET_CHAIN_ID".into(), chain_id.to_string());
    vars.insert("GENESIS_URL".into(), genesis_url.to_string());

    // Monikers
    vars.insert("SENTRY_A_MONIKER".into(), generate_credential(12));
    vars.insert("SENTRY_B_MONIKER".into(), generate_credential(12));

    // Sentry image — use testnet-specific terp-core image (with ZK wasmvm + hashmerchant + faucet)
    let sentry_image = config.val("TESTNET_SENTRY_IMAGE");
    let sentry_image = if sentry_image.is_empty() {
        panic!("need sentry image set: TESTNET_SENTRY_IMAGE ")
    } else {
        sentry_image
    };
    vars.insert("TESTNET_SENTRY_IMAGE".into(), sentry_image);

    // Faucet keys — funded accounts in genesis; each sentry uses a distinct key
    // to avoid tx sequence conflicts when both serve faucet requests concurrently.
    let fa_mnemonic = config.val("TESTNET_SENTRY_A_FAUCET_MNEMONIC");
    let fb_mnemonic = config.val("TESTNET_SENTRY_B_FAUCET_MNEMONIC");
    vars.insert("SENTRY_A_FAUCET_MNEMONIC".into(), fa_mnemonic);
    vars.insert("SENTRY_B_FAUCET_MNEMONIC".into(), fb_mnemonic);

    // LB domains (the unified public endpoints)
    let lb_domain = vars
        .get("nodes.snapshot.domain")
        .cloned()
        .unwrap_or_else(|| "testnet.terp.network".into());
    vars.insert("RPC_D_LB".into(), format!("rpc-{}", lb_domain));
    vars.insert("API_D_LB".into(), format!("api-{}", lb_domain));
    vars.insert("GRPC_D_LB".into(), format!("grpc-{}", lb_domain));

    // LB port 80 accept items
    let rpc_d = vars.get("RPC_D_LB").cloned().unwrap_or_default();
    let api_d = vars.get("API_D_LB").cloned().unwrap_or_default();
    let mut accepts = Vec::new();
    if !rpc_d.is_empty() {
        accepts.push(format!("          - {}", rpc_d));
    }
    if !api_d.is_empty() {
        accepts.push(format!("          - {}", api_d));
    }
    vars.insert("LB_80_ACCEPTS".into(), accepts.join("\n"));

    // SSH
    vars.insert("SSH_PUBKEY".into(), ssh_pubkey.to_string());

    vars
}

/// Display bids for a deployment phase (no stdin interaction).
async fn display_phase_bids(deployer: &OLineDeployer, phase_name: &str, dseq: u64, bids: &[Bid]) {
    tracing::info!(
        "\n  ── {} (dseq={}) — {} bid(s) ──",
        phase_name,
        dseq,
        bids.len()
    );

    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price as f64 / 1_000_000.0;
        tracing::info!(
            "    [{}] {:.6} AKT/block ({} uakt)",
            i + 1,
            price_akt,
            bid.price,
        );
        tracing::info!("        address: {}", bid.provider);

        match deployer.client.query_provider_info(&bid.provider).await {
            Ok(Some(info)) => {
                tracing::info!("        host:    {}", info.host_uri);
                if !info.email.is_empty() {
                    tracing::info!("        email:   {}", info.email);
                }
                if !info.website.is_empty() {
                    tracing::info!("        website: {}", info.website);
                }
            }
            _ => {
                tracing::info!("        host:    (could not query)");
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Join non-empty peer strings with commas. Filters out empty entries
/// to avoid producing ",abc@host:26656" or "abc@host:26656,".

/// Find the bid from a specific provider in a bid list.
fn find_bid_for_provider(
    bids: &[akash_deploy_rs::Bid],
    provider: &str,
) -> Result<akash_deploy_rs::Bid, Box<dyn Error>> {
    bids.iter()
        .find(|b| b.provider == provider)
        .cloned()
        .ok_or_else(|| format!("no bid from provider {}", provider).into())
}

/// Push genesis + scripts to a sentry node, then signal it to start.
/// Returns an error if any step fails after retries — callers should abort.
async fn bootstrap_sentry(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    scripts_path: &str,
    nginx_path: Option<&str>,
    refresh_vars: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("  [{}] Pushing genesis + scripts...", label);

    let mut attempt = 0u32;
    loop {
        match push_scripts_sftp(label, endpoints, ssh_key_path, scripts_path, nginx_path).await {
            Ok(_) => break,
            Err(e) => {
                attempt += 1;
                if attempt >= MAX_RETRIES as u32 {
                    return Err(format!(
                        "[{}] Script push failed after {} attempts: {}",
                        label, attempt, e
                    )
                    .into());
                }
                tracing::info!(
                    "  [{}] SSH not ready ({}/{}): {} — retrying in 5s",
                    label,
                    attempt,
                    MAX_RETRIES,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    verify_files_and_signal_start(label, endpoints, ssh_key_path, &[], refresh_vars)
        .await
        .map_err(|e| -> Box<dyn Error> { format!("[{}] Signal failed: {}", label, e).into() })?;

    tracing::info!("  [{}] Signaled — node starting.", label);
    Ok(())
}
