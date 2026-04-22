//! `oline testnet-deploy` — bootstrap a fresh testnet on Akash Network.
//!
//! Deploys a localterp validator + faucet alongside the full o-line sentry array
//! (snapshot, seed, tackles, forwards) as Akash deployments. The validator's genesis
//! is fetched via RPC and distributed to all sentries via SFTP. The validator is
//! configured as a private peer on all sentries (never gossiped).
//!
//! Architecture:
//! ```text
//! Phase A (single Akash deployment):
//!   [Validator+Faucet (localterp)]  ← never publicly exposed beyond P2P
//!   [Snapshot node (omnibus)]       ← OLINE_OFFLINE=1, genesis via SFTP
//!   [Seed node (omnibus)]           ← OLINE_OFFLINE=1, genesis via SFTP
//!
//! Phase B (separate Akash deployment):
//!   [Left Tackle (omnibus)]         ← OLINE_OFFLINE=1, genesis via SFTP
//!   [Right Tackle (omnibus)]        ← OLINE_OFFLINE=1, genesis via SFTP
//!
//! Phase C (separate Akash deployment):
//!   [Left Forward (omnibus)]        ← OLINE_OFFLINE=1, genesis via SFTP
//!   [Right Forward (omnibus)]       ← OLINE_OFFLINE=1, genesis via SFTP
//! ```
//!
//! All three lease acceptances (MsgCreateLease) are batched into a single
//! signed transaction. Sentries deploy with empty peer placeholders; real
//! peer configuration is injected at bootstrap time via SFTP.

use crate::{
    akash::{build_accept_items, endpoint_hostname, node_refresh_vars},
    config::{build_config_from_env, collect_config, OLineConfig},
    crypto::{
        ensure_ssh_key, generate_credential, push_pre_start_files,
        push_scripts_sftp, verify_files_and_signal_start, FileSource, PreStartFile,
    },
    deployer::OLineDeployer,
    with_examples, MAX_RETRIES,
};
use akash_deploy_rs::{AkashBackend, 
    build_create_lease_msg, broadcast_multi_signer, AkashClient, Bid, BidId,
    DeploymentRecord, DeploymentStore, DeploymentWorkflow, FileDeploymentStore,
    ServiceEndpoint, SignerEntry, Step,
};
use std::{collections::HashMap, env::var, error::Error, io::{self, BufRead}, path::PathBuf};

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

        /// Use an external validator instead of deploying one (skip Phase V).
        /// Format: <RPC_URL> e.g. https://rpc-testnet.terp.network
        #[arg(long)]
        pub validator_rpc: Option<String>,

        /// External validator P2P peer address. Required with --validator-rpc.
        /// Format: <node_id>@<host>:<port>
        #[arg(long)]
        pub validator_peer: Option<String>,

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
    }
    => "../../docs/examples/testnet.md"
}

pub async fn cmd_testnet_deploy(args: &TestnetDeployArgs) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== O-Line Testnet Deploy ===\n");
    tracing::info!("  Chain ID:       {}", args.chain_id);
    tracing::info!("  Localterp:      {}", args.localterp_image);
    tracing::info!("  Fast blocks:    {}", args.fast_blocks);

    // ── 1. Unlock mnemonic + build config ────────────────────────────────────
    let non_interactive = args.non_interactive || std::env::var("OLINE_NON_INTERACTIVE").is_ok();

    let (mnemonic, password) = if non_interactive {
        let p = std::env::var("OLINE_PASSWORD").unwrap_or_else(|_| "oline-test".to_string());
        let m = if let Some(raw) = std::env::var("OLINE_MNEMONIC").ok().filter(|s| !s.trim().is_empty()) {
            raw.trim().to_string()
        } else {
            // Fall back to encrypted mnemonic + OLINE_PASSWORD (same as SDL deploy)
            use crate::crypto::decrypt_mnemonic;
            let blob = crate::config::read_encrypted_mnemonic_from_env()
                .map_err(|_| "OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC or OLINE_ENCRYPTED_MNEMONIC")?;
            decrypt_mnemonic(&blob, &p)
                .map_err(|e| format!("Failed to decrypt mnemonic: {}. Check OLINE_PASSWORD.", e))?
        };
        (m, p)
    } else if args.raw {
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        let p = rpassword::prompt_password("Enter password: ")?;
        (m.trim().to_string(), p)
    } else {
        crate::cli::unlock_mnemonic()?
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

    // ── 2. Create deployer + preflight ───────────────────────────────────────
    let deployer = OLineDeployer::new(config.clone(), password.clone())
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    deployer
        .preflight_check()
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    // ── 3. Shared setup ──────────────────────────────────────────────────────────────────────
    let secrets_path = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let ssh_key_path: PathBuf = format!("{}/oline-testnet-key", secrets_path).into();
    let ssh_key = ensure_ssh_key(&ssh_key_path)?;
    let ssh_pubkey = ssh_key.public_key().to_string();

    // ── 4. Validator: external or deploy Phase V ──────────────────────────────────
    let (validator_peer, genesis_url, validator_node_id) = if let (Some(ext_rpc), Some(ext_peer)) =
        (&args.validator_rpc, &args.validator_peer)
    {
        tracing::info!("\n── Using external validator (skip Phase V) ──");
        tracing::info!("  RPC:  {}", ext_rpc);
        tracing::info!("  Peer: {}", ext_peer);

        let genesis_url = format!("{}/genesis", ext_rpc.trim_end_matches('/'));

        // Verify validator is reachable
        let status: serde_json::Value = reqwest::get(&format!("{}/status", ext_rpc.trim_end_matches('/')))
            .await?
            .json()
            .await
            .map_err(|e| format!("Cannot reach validator RPC: {}", e))?;
        let height = status["result"]["sync_info"]["latest_block_height"]
            .as_str().unwrap_or("0");
        tracing::info!("  Validator height: {}", height);

        let node_id = ext_peer.split('@').next().unwrap_or("").to_string();
        (ext_peer.clone(), genesis_url, node_id)
    } else {
        tracing::info!("\n── Phase V: deploying validator ──");
        let v_vars = build_testnet_v_vars(&config, &args.localterp_image, &args.chain_id, args.fast_blocks);
        let sdl_v = config.load_sdl("testnet-v.yml").map_err(|e| -> Box<dyn Error> { e })?;

        let (_state_v, v_endpoints) = deployer
            .deploy_phase_auto(&sdl_v, &v_vars, "testnet-phase-v")
            .await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;

        let validator_svc = v_vars.get("VALIDATOR_SVC").map(|s| s.as_str()).unwrap_or("testnet-v-validator");
        let validator_rpc_ep = OLineDeployer::find_endpoint_by_internal_port(&v_endpoints, validator_svc, 26657);
        let validator_p2p_ep = OLineDeployer::find_endpoint_by_internal_port(&v_endpoints, validator_svc, 26656);

        let validator_rpc_url = validator_rpc_ep
            .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port))
            .ok_or("No validator RPC endpoint found")?;
        let validator_p2p_addr = validator_p2p_ep
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port))
            .ok_or("No validator P2P endpoint found")?;

        tracing::info!("\n── Waiting for validator to produce blocks ──");
        tracing::info!("  RPC: {}", validator_rpc_url);

        let validator_peer = OLineDeployer::extract_peer_id_with_boot_wait(
            &validator_rpc_url, &validator_p2p_addr, 60, 30, 10,
        )
        .await
        .ok_or("Validator did not come up within timeout")?;
        tracing::info!("  Validator peer: {}", validator_peer);

        let genesis_url = format!("{}/genesis", validator_rpc_url.trim_end_matches('/'));

        let genesis_resp: serde_json::Value = reqwest::get(&genesis_url)
            .await?
            .json()
            .await
            .map_err(|e| format!("Failed to fetch genesis: {}", e))?;
        let genesis_json = genesis_resp
            .get("result")
            .and_then(|r| r.get("genesis"))
            .ok_or("Missing .result.genesis in /genesis response")?;
        let genesis_bytes = serde_json::to_vec_pretty(genesis_json)?;
        let genesis_local: PathBuf = format!("{}/testnet-genesis.json", secrets_path).into();
        std::fs::write(&genesis_local, &genesis_bytes)?;
        tracing::info!("  Genesis saved: {:?} ({} bytes)", genesis_local, genesis_bytes.len());

        let node_id = validator_peer.split('@').next().unwrap_or("").to_string();
        (validator_peer, genesis_url, node_id)
    };

    // ── 7. Build LB var set with real peer info + genesis URL ────────────────
    let sdl_lb = config.load_sdl("testnet-lb.yml").map_err(|e| -> Box<dyn Error> { e })?;
    let lb_vars = build_testnet_lb_vars(
        &config, &args.chain_id, &genesis_url,
        &validator_peer, &validator_node_id, &ssh_pubkey,
    );

    // ── 8. Two-pass deployment: single LB deployment ─────────────────────���────
    let mut store = FileDeploymentStore::new_default().await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    let lb_endpoints;

    if args.resume {
        // ── Pass 2: Resume — load saved state and accept lease ───────────────
        let pa = args.provider_a.as_deref()
            .ok_or("--resume requires --provider-a")?;

        let all_records: Vec<DeploymentRecord> = store.list().await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        let lb_rec = all_records.iter()
            .find(|r| r.label == "testnet-lb" && matches!(r.step, Step::SelectProvider))
            .ok_or("No saved LB deployment at SelectProvider step. Run without --resume first.")?;

        tracing::info!("\n── Resuming LB deployment ──");
        tracing::info!("  LB: dseq={}", lb_rec.dseq);

        let mut state_lb = lb_rec.clone().to_state("testnet-lb", &password)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        DeploymentWorkflow::<AkashClient>::select_provider(&mut state_lb, pa)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;

        // Create lease
        tracing::info!("\n── Lease acceptance ──");
        let owner = deployer.client.address().to_string();
        let bid = find_bid_for_provider(&state_lb.bids, pa)?;
        let bid_id = BidId::from_bid(&owner, state_lb.dseq.unwrap(), state_lb.gseq, state_lb.oseq, &bid);
        let lease_msg = build_create_lease_msg(&bid_id);

        let querier = &deployer.client.signing_client().querier;
        let acct = querier
            .base_account(deployer.client.address_ref())
            .await
            .map_err(|e| format!("base_account: {}", e))?;
        let chain_id = querier.chain_config.chain_id.as_str();

        let signer_entries = vec![SignerEntry {
            signer: &deployer.signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: vec![lease_msg],
        }];

        let lease_tx = broadcast_multi_signer(
            querier, chain_id, signer_entries, 1.5,
            std::time::Duration::from_secs(60),
        ).await.map_err(|e| -> Box<dyn Error> { e.into() })?;

        tracing::info!("  Lease tx: hash={}, height={}", lease_tx.hash, lease_tx.height);

        state_lb.record_tx(&lease_tx.hash);
        state_lb.lease_id = Some(bid_id.into());
        state_lb.transition(Step::SendManifest);

        // Regenerate JWT auth
        let jwt = deployer.client.generate_jwt(&deployer.client.address()).await
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        state_lb.jwt_token = Some(jwt);

        // Send manifest + get endpoints
        tracing::info!("\n── Sending manifest ──");
        lb_endpoints = deployer.deploy_phase_complete(&mut state_lb, "testnet-lb")
            .await.map_err(|e| -> Box<dyn Error> { e.into() })?;

    } else {
        // ── Pass 1: Create deployment, collect bids, save state, exit ─────────
        tracing::info!("\n── Creating LB deployment (LB + 2 sentries) ──");

        let (state_lb, bids_lb) = deployer
            .deploy_phase_until_bids(&sdl_lb, &lb_vars, "testnet-lb")
            .await.map_err(|e| -> Box<dyn Error> { e.into() })?;
        tracing::info!("  LB: {} bid(s), dseq={}", bids_lb.len(), state_lb.dseq.unwrap_or(0));

        // Save state
        let record = DeploymentRecord::from_state(&state_lb, &password)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
        store.save(&record).await
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
        if let Some(ref rpc) = args.validator_rpc {
            tracing::info!("    --validator-rpc {} \\", rpc);
        }
        if let Some(ref peer) = args.validator_peer {
            tracing::info!("    --validator-peer {} \\", peer);
        }
        tracing::info!("    --resume \\");
        tracing::info!("    --provider-a <PROVIDER_ADDRESS>");

        tracing::info!("\nState saved. Deployment will remain open and accepting bids.");
        return Ok(());
    }

    // ── 9. Bootstrap LB + sentries via SSH ─────────────────��─────────────────
    tracing::info!("\n── Bootstrapping LB + sentries ──");
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());

    let lb_svc = lb_vars.get("LB_SVC").map(|s| s.as_str()).unwrap_or("testnet-lb");
    let sentry_a_svc = lb_vars.get("SENTRY_A_SVC").map(|s| s.as_str()).unwrap_or("testnet-sentry-a");
    let sentry_b_svc = lb_vars.get("SENTRY_B_SVC").map(|s| s.as_str()).unwrap_or("testnet-sentry-b");

    // Push lb-init.sh to the LB container via SFTP
    let lb_eps: Vec<_> = lb_endpoints
        .iter()
        .filter(|e| e.service == lb_svc)
        .cloned()
        .collect();
    if !lb_eps.is_empty() {
        bootstrap_sentry(
            "testnet-lb", &lb_eps, &ssh_key_path, &scripts_path,
            None, &lb_vars,
        )
        .await?;
    }

    // Bootstrap sentry-a
    let sentry_a_eps: Vec<_> = lb_endpoints
        .iter()
        .filter(|e| e.service == sentry_a_svc)
        .cloned()
        .collect();
    if !sentry_a_eps.is_empty() {
        bootstrap_sentry(
            "testnet-sentry-a", &sentry_a_eps, &ssh_key_path, &scripts_path,
            None, &lb_vars,
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
            "testnet-sentry-b", &sentry_b_eps, &ssh_key_path, &scripts_path,
            None, &lb_vars,
        )
        .await?;
    }

    // ── 10. Summary ──────────────���───────────────────────────────────────────
    let batch_tx_hash = lb_endpoints.first()
        .map(|_| "see lease tx above".to_string())
        .unwrap_or_default();

    tracing::info!("\n═══════════════���══════════════════════════════════════════════");
    tracing::info!("  TESTNET DEPLOYED SUCCESSFULLY (LB mode)");
    tracing::info!("═════════════��══════════════════��═════════════════════════════");
    tracing::info!("  Chain ID:       {}", args.chain_id);
    tracing::info!("  Validator Peer: {}", validator_peer);
    tracing::info!("  Genesis URL:    {}", genesis_url);

    if let Some(ref ext_rpc) = args.validator_rpc {
        tracing::info!("  Validator RPC:  {}", ext_rpc);
    }

    tracing::info!("\n  ── LB Endpoints ──");
    for ep in &lb_endpoints {
        tracing::info!("    {}:{} → {}:{}", ep.service, ep.internal_port, ep.uri, ep.port);
    }
    tracing::info!("════════��════════════════════════════════════════��════════════\n");

    Ok(())
}
fn build_testnet_v_vars(
    config: &OLineConfig,
    localterp_image: &str,
    chain_id: &str,
    fast_blocks: bool,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();
    vars.insert("VALIDATOR_SVC".into(), "testnet-v-validator".into());
    vars.insert("LOCALTERP_IMAGE".into(), localterp_image.to_string());
    vars.insert("TESTNET_CHAIN_ID".into(), chain_id.to_string());
    vars.insert(
        "TESTNET_FAST_BLOCKS".into(),
        if fast_blocks { "true" } else { "false" }.into(),
    );

    // Faucet domain — route HTTP port 80 → container port 5000
    let faucet_d = config.val("FAUCET_D");
    let validator_accepts = if faucet_d.is_empty() {
        String::new()
    } else {
        format!("          - {}", faucet_d)
    };
    vars.insert("VALIDATOR_80_ACCEPTS".into(), validator_accepts);
    vars
}

fn build_testnet_a_vars(
    config: &OLineConfig,
    chain_id: &str,
    genesis_url: &str,
    validator_peer: &str,
    ssh_pubkey: &str,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    vars.insert("SNAPSHOT_SVC".into(), "testnet-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "testnet-a-seed".into());
    vars.insert("TESTNET_CHAIN_ID".into(), chain_id.to_string());
    vars.insert("GENESIS_URL".into(), genesis_url.to_string());

    vars.insert("SNAPSHOT_MONIKER".into(), generate_credential(12));
    vars.insert("SEED_MONIKER".into(), generate_credential(12));

    vars.insert("SSH_PUBKEY".into(), ssh_pubkey.to_string());

    // Tailnet: sentries join headscale tailnet for private P2P access
    if let Ok(hs_store) = crate::cmd::vpn::HeadscaleStore::load_optional() {
        if let Ok(server) = hs_store.get(None) {
            vars.insert("HEADSCALE_URL".into(), server.control_url.clone());
            vars.insert("HEADSCALE_PREAUTH_KEY".into(), server.preauth_key.clone());
        }
    }

    // Cloudflare TCP tunnel for P2P (peer-{domain})
    let snap_domain = vars.get("P2P_D_SNAP").or(vars.get("P2P_D_TL")).or(vars.get("P2P_D_FL")).cloned().unwrap_or_default();
    if !snap_domain.is_empty() {
        vars.insert("P2P_TUNNEL_HOST".into(), snap_domain);
    }

    let validator_node_id = validator_peer.split('@').next().unwrap_or("").to_string();
    vars.insert("TERPD_P2P_PERSISTENT_PEERS".into(), validator_peer.to_string());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), validator_node_id.clone());
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), validator_node_id);

    vars.insert("SNAPSHOT_80_ACCEPTS".into(), build_accept_items(&vars, "SNAP"));
    vars.insert("SEED_80_ACCEPTS".into(), build_accept_items(&vars, "SEED"));

    vars
}

fn build_testnet_b_vars(
    config: &OLineConfig,
    chain_id: &str,
    genesis_url: &str,
    snapshot_peer: &str,
    validator_peer: &str,
    validator_node_id: &str,
    statesync_rpc: &str,
    ssh_pubkey: &str,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    vars.insert("LT_SVC".into(), "oline-b-left-tackle".into());
    vars.insert("RT_SVC".into(), "oline-b-right-tackle".into());
    vars.insert("TESTNET_CHAIN_ID".into(), chain_id.to_string());
    vars.insert("GENESIS_URL".into(), genesis_url.to_string());
    vars.insert("LEFT_TACKLE_MONIKER".into(), generate_credential(12));
    vars.insert("RIGHT_TACKLE_MONIKER".into(), generate_credential(12));

    // SSH key — reuse Phase A's keypair so bootstrap_sentry can SFTP in
    vars.insert("SSH_PUBKEY".into(), ssh_pubkey.to_string());

    // Tailnet: sentries join headscale tailnet for private P2P access
    if let Ok(hs_store) = crate::cmd::vpn::HeadscaleStore::load_optional() {
        if let Ok(server) = hs_store.get(None) {
            vars.insert("HEADSCALE_URL".into(), server.control_url.clone());
            vars.insert("HEADSCALE_PREAUTH_KEY".into(), server.preauth_key.clone());
        }
    }

    // Cloudflare TCP tunnel for P2P (peer-{domain})
    let snap_domain = vars.get("P2P_D_SNAP").or(vars.get("P2P_D_TL")).or(vars.get("P2P_D_FL")).cloned().unwrap_or_default();
    if !snap_domain.is_empty() {
        vars.insert("P2P_TUNNEL_HOST".into(), snap_domain);
    }

    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        comma_join(&[snapshot_peer, validator_peer]),
    );
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), validator_node_id.to_string());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), validator_node_id.to_string());
    vars.insert("STATESYNC_RPC_SERVERS".into(), statesync_rpc.to_string());

    vars.insert("LT_80_ACCEPTS".into(), build_accept_items(&vars, "TL"));
    vars.insert("RT_80_ACCEPTS".into(), build_accept_items(&vars, "TR"));

    vars
}

fn build_testnet_c_vars(
    config: &OLineConfig,
    chain_id: &str,
    genesis_url: &str,
    seed_peer: &str,
    snapshot_peer: &str,
    left_tackle_peer: &str,
    right_tackle_peer: &str,
    validator_peer: &str,
    validator_node_id: &str,
    statesync_rpc: &str,
    ssh_pubkey: &str,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    vars.insert("LF_SVC".into(), "oline-c-left-forward".into());
    vars.insert("RF_SVC".into(), "oline-c-right-forward".into());
    vars.insert("TESTNET_CHAIN_ID".into(), chain_id.to_string());
    vars.insert("GENESIS_URL".into(), genesis_url.to_string());
    vars.insert("LEFT_FMONIKER".into(), generate_credential(12));
    vars.insert("RIGHT_FMONIKER".into(), generate_credential(12));

    // SSH key — reuse Phase A's keypair so bootstrap_sentry can SFTP in
    vars.insert("SSH_PUBKEY".into(), ssh_pubkey.to_string());

    // Tailnet: sentries join headscale tailnet for private P2P access
    if let Ok(hs_store) = crate::cmd::vpn::HeadscaleStore::load_optional() {
        if let Ok(server) = hs_store.get(None) {
            vars.insert("HEADSCALE_URL".into(), server.control_url.clone());
            vars.insert("HEADSCALE_PREAUTH_KEY".into(), server.preauth_key.clone());
        }
    }

    // Cloudflare TCP tunnel for P2P (peer-{domain})
    let snap_domain = vars.get("P2P_D_SNAP").or(vars.get("P2P_D_TL")).or(vars.get("P2P_D_FL")).cloned().unwrap_or_default();
    if !snap_domain.is_empty() {
        vars.insert("P2P_TUNNEL_HOST".into(), snap_domain);
    }

    vars.insert("TERPD_P2P_SEEDS".into(), seed_peer.to_string());
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        comma_join(&[snapshot_peer, validator_peer]),
    );

    let lt_id = left_tackle_peer.split('@').next().unwrap_or("");
    let rt_id = right_tackle_peer.split('@').next().unwrap_or("");
    let private_ids = comma_join(&[lt_id, rt_id, validator_node_id]);
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), private_ids.clone());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), private_ids);
    vars.insert("STATESYNC_RPC_SERVERS".into(), statesync_rpc.to_string());

    vars.insert("LF_80_ACCEPTS".into(), build_accept_items(&vars, "FL"));
    vars.insert("RF_80_ACCEPTS".into(), build_accept_items(&vars, "FR"));

    vars
}


fn build_testnet_lb_vars(
    config: &OLineConfig,
    chain_id: &str,
    genesis_url: &str,
    validator_peer: &str,
    validator_node_id: &str,
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

    // Validator peer (full peer string for sentries — P2P handled per-sentry, not via LB)
    vars.insert("VALIDATOR_PEER".into(), validator_peer.to_string());
    vars.insert("VALIDATOR_PEER_ID".into(), validator_node_id.to_string());

    // LB domains (the unified public endpoints)
    let lb_domain = vars.get("nodes.snapshot.domain")
        .cloned()
        .unwrap_or_else(|| "testnet.terp.network".into());
    vars.insert("RPC_D_LB".into(), format!("rpc-{}", lb_domain));
    vars.insert("API_D_LB".into(), format!("api-{}", lb_domain));
    vars.insert("GRPC_D_LB".into(), format!("grpc-{}", lb_domain));

    // LB port 80 accept items
    let rpc_d = vars.get("RPC_D_LB").cloned().unwrap_or_default();
    let api_d = vars.get("API_D_LB").cloned().unwrap_or_default();
    let mut accepts = Vec::new();
    if !rpc_d.is_empty() { accepts.push(format!("          - {}", rpc_d)); }
    if !api_d.is_empty() { accepts.push(format!("          - {}", api_d)); }
    vars.insert("LB_80_ACCEPTS".into(), accepts.join("\n"));

    // SSH
    vars.insert("SSH_PUBKEY".into(), ssh_pubkey.to_string());

    vars
}

/// Display bids for a deployment phase (no stdin interaction).
async fn display_phase_bids(
    deployer: &OLineDeployer,
    phase_name: &str,
    dseq: u64,
    bids: &[Bid],
) {
    tracing::info!("\n  ── {} (dseq={}) — {} bid(s) ──", phase_name, dseq, bids.len());

    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price as f64 / 1_000_000.0;
        tracing::info!(
            "    [{}] {:.6} AKT/block ({} uakt)",
            i + 1, price_akt, bid.price,
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
fn comma_join(peers: &[&str]) -> String {
    peers
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(",")
}

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
                    label, attempt, MAX_RETRIES, e
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    verify_files_and_signal_start(
        label, endpoints, ssh_key_path,
        &[], refresh_vars,
    )
    .await
    .map_err(|e| -> Box<dyn Error> {
        format!("[{}] Signal failed: {}", label, e).into()
    })?;

    tracing::info!("  [{}] Signaled — node starting.", label);
    Ok(())
}

