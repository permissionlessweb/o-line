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
use akash_deploy_rs::{
    build_create_lease_msg, broadcast_multi_signer, AkashClient, BidId,
    DeploymentWorkflow, ServiceEndpoint, SignerEntry, Step,
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
        let m = std::env::var("OLINE_MNEMONIC")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .ok_or("OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC to be set")?;
        let p = std::env::var("OLINE_PASSWORD").unwrap_or_else(|_| "oline-test".to_string());
        (m.trim().to_string(), p)
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
        build_config_from_env(mnemonic)
    } else {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        let cfg = collect_config(&password, mnemonic, &mut lines).await?;
        drop(lines);
        cfg
    };

    // ── 2. Create deployer + preflight ───────────────────────────────────────
    let deployer = OLineDeployer::new(config.clone(), password)
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    deployer
        .preflight_check()
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    // ── 3. Build ALL 3 SDL var sets upfront ──────────────────────────────────
    // Phase B and C deploy with empty peer placeholders. Real peer config is
    // injected at bootstrap time via SFTP (verify_files_and_signal_start writes
    // refresh_vars to /tmp/oline-env.sh which the container sources at start).
    let secrets_path = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let mut a_vars = build_testnet_a_vars(
        &config,
        &secrets_path,
        &args.localterp_image,
        &args.chain_id,
        args.fast_blocks,
    )
    .await?;

    let ssh_key_path: PathBuf = a_vars
        .get("SSH_KEY_PATH")
        .map(|p| PathBuf::from(p))
        .unwrap_or_else(|| format!("{}/oline-testnet-key", secrets_path).into());

    let ssh_pubkey = a_vars
        .get("SSH_PUBKEY")
        .cloned()
        .unwrap_or_default();

    // Phase B/C with empty peer placeholders (peers injected at bootstrap via SFTP)
    let b_deploy_vars = build_testnet_b_vars(
        &config, &args.chain_id, "", "", "", "", &ssh_pubkey,
    );
    let c_deploy_vars = build_testnet_c_vars(
        &config, &args.chain_id, "", "", "", "", "", "", "", &ssh_pubkey,
    );

    // ── 4. Create all 3 deployments + collect bids ───────────────────────────
    let sdl_a = config.load_sdl("testnet-a.yml").map_err(|e| -> Box<dyn Error> { e })?;
    let sdl_b = config.load_sdl("testnet-b.yml").map_err(|e| -> Box<dyn Error> { e })?;
    let sdl_c = config.load_sdl("testnet-c.yml").map_err(|e| -> Box<dyn Error> { e })?;

    tracing::info!("\n── Creating all 3 deployments ──");

    let (mut state_a, bids_a) = deployer
        .deploy_phase_until_bids(&sdl_a, &a_vars, "testnet-phase-a")
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    tracing::info!("  Phase A: {} bid(s), dseq={}", bids_a.len(), state_a.dseq.unwrap_or(0));

    let (mut state_b, bids_b) = deployer
        .deploy_phase_until_bids(&sdl_b, &b_deploy_vars, "testnet-phase-b")
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    tracing::info!("  Phase B: {} bid(s), dseq={}", bids_b.len(), state_b.dseq.unwrap_or(0));

    let (mut state_c, bids_c) = deployer
        .deploy_phase_until_bids(&sdl_c, &c_deploy_vars, "testnet-phase-c")
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    tracing::info!("  Phase C: {} bid(s), dseq={}", bids_c.len(), state_c.dseq.unwrap_or(0));

    // ── 5. Select providers for all 3 ────────────────────────────────────────
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    tracing::info!("\n── Provider selection: Phase A ──");
    let provider_a = deployer.interactive_select_provider(&bids_a, &mut lines).await?;
    DeploymentWorkflow::<AkashClient>::select_provider(&mut state_a, &provider_a)
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    tracing::info!("\n── Provider selection: Phase B ──");
    let provider_b = deployer.interactive_select_provider(&bids_b, &mut lines).await?;
    DeploymentWorkflow::<AkashClient>::select_provider(&mut state_b, &provider_b)
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    tracing::info!("\n── Provider selection: Phase C ──");
    let provider_c = deployer.interactive_select_provider(&bids_c, &mut lines).await?;
    DeploymentWorkflow::<AkashClient>::select_provider(&mut state_c, &provider_c)
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    // ── 6. Batch lease creation (3 MsgCreateLease in 1 signed tx) ────────────
    tracing::info!("\n── Batch lease acceptance: 3 MsgCreateLease in 1 tx ──");

    let owner = deployer.client.address().to_string();

    let bid_a = find_bid_for_provider(&bids_a, &provider_a)?;
    let bid_b = find_bid_for_provider(&bids_b, &provider_b)?;
    let bid_c = find_bid_for_provider(&bids_c, &provider_c)?;

    let bid_id_a = BidId::from_bid(&owner, state_a.dseq.unwrap(), state_a.gseq, state_a.oseq, &bid_a);
    let bid_id_b = BidId::from_bid(&owner, state_b.dseq.unwrap(), state_b.gseq, state_b.oseq, &bid_b);
    let bid_id_c = BidId::from_bid(&owner, state_c.dseq.unwrap(), state_c.gseq, state_c.oseq, &bid_c);

    let lease_msgs = vec![
        build_create_lease_msg(&bid_id_a),
        build_create_lease_msg(&bid_id_b),
        build_create_lease_msg(&bid_id_c),
    ];

    // Query account for current sequence
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
        messages: lease_msgs,
    }];

    let batch_tx = broadcast_multi_signer(
        querier,
        chain_id,
        signer_entries,
        1.5,
        std::time::Duration::from_secs(60),
    )
    .await
    .map_err(|e| -> Box<dyn Error> { e.into() })?;

    tracing::info!(
        "  Batch lease tx confirmed: hash={}, height={}",
        batch_tx.hash,
        batch_tx.height
    );

    // Record lease on each state and skip to SendManifest
    state_a.record_tx(&batch_tx.hash);
    state_a.lease_id = Some(bid_id_a.into());
    state_a.transition(Step::SendManifest);

    state_b.record_tx(&batch_tx.hash);
    state_b.lease_id = Some(bid_id_b.into());
    state_b.transition(Step::SendManifest);

    state_c.record_tx(&batch_tx.hash);
    state_c.lease_id = Some(bid_id_c.into());
    state_c.transition(Step::SendManifest);

    // ── 7. Send manifests + get endpoints ────────────────────────────────────
    tracing::info!("\n── Sending manifests ──");

    let a_endpoints = deployer
        .deploy_phase_complete(&mut state_a, "testnet-phase-a")
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    let b_endpoints = deployer
        .deploy_phase_complete(&mut state_b, "testnet-phase-b")
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    let c_endpoints = deployer
        .deploy_phase_complete(&mut state_c, "testnet-phase-c")
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    // ── 8. Wait for validator to produce blocks ──────────────────────────────
    let validator_rpc_ep = OLineDeployer::find_endpoint_by_internal_port(
        &a_endpoints, "testnet-a-validator", 26657,
    );
    let validator_p2p_ep = OLineDeployer::find_endpoint_by_internal_port(
        &a_endpoints, "testnet-a-validator", 26656,
    );

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

    // ── 9. Fetch genesis from validator RPC ──────────────────────────────────
    tracing::info!("\n── Fetching genesis from validator ──");
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

    // ── 10. Bootstrap Phase A sentries ────────────────────────────────────────
    tracing::info!("\n── Bootstrapping Phase A sentries ──");
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let nginx_path = var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

    let genesis_file = PreStartFile {
        source: FileSource::Bytes(genesis_bytes.clone()),
        remote_path: "/tmp/genesis.json".into(),
    };

    // Inject explicit snapshot URL so sentries don't rely on chain-registry resolution.
    // OLINE_SNAPSHOT_FULL_URL → SNAPSHOT_URL (operator override, survives OFFLINE mode).
    let snapshot_full_url = var("OLINE_SNAPSHOT_FULL_URL").unwrap_or_default();
    if !snapshot_full_url.is_empty() {
        a_vars.insert("SNAPSHOT_URL".into(), snapshot_full_url.clone());
        a_vars.insert("OLINE_SNAPSHOT_FULL_URL".into(), snapshot_full_url);
        tracing::info!("  Snapshot URL: {}", a_vars["SNAPSHOT_URL"]);
    }

    // Snapshot node
    let snapshot_eps: Vec<_> = a_endpoints
        .iter()
        .filter(|e| e.service == "testnet-a-snapshot")
        .cloned()
        .collect();
    if !snapshot_eps.is_empty() {
        bootstrap_sentry(
            "testnet-snapshot", &snapshot_eps, &ssh_key_path, &scripts_path,
            Some(&nginx_path), &genesis_file, &node_refresh_vars(&a_vars, "SNAPSHOT"),
        )
        .await?;
    }

    // Seed node
    let seed_eps: Vec<_> = a_endpoints
        .iter()
        .filter(|e| e.service == "testnet-a-seed")
        .cloned()
        .collect();
    if !seed_eps.is_empty() {
        bootstrap_sentry(
            "testnet-seed", &seed_eps, &ssh_key_path, &scripts_path,
            Some(&nginx_path), &genesis_file, &node_refresh_vars(&a_vars, "SEED"),
        )
        .await?;
    }

    // ── 11. Extract Phase A peer IDs ─────────────────────────────────────────
    let snap_rpc_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "testnet-a-snapshot", 26657);
    let snap_p2p_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "testnet-a-snapshot", 26656);
    let seed_rpc_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "testnet-a-seed", 26657);
    let seed_p2p_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "testnet-a-seed", 26656);

    tracing::info!("\n── Waiting for Phase A sentries to sync ──");
    let snapshot_peer = if let (Some(rpc), Some(p2p)) = (snap_rpc_ep, snap_p2p_ep) {
        let rpc_url = format!("http://{}:{}", endpoint_hostname(&rpc.uri), rpc.port);
        let p2p_addr = format!("{}:{}", endpoint_hostname(&p2p.uri), p2p.port);
        OLineDeployer::extract_peer_id_with_boot_wait(&rpc_url, &p2p_addr, 120, 60, 30).await
    } else {
        None
    };
    let seed_peer = if let (Some(rpc), Some(p2p)) = (seed_rpc_ep, seed_p2p_ep) {
        let rpc_url = format!("http://{}:{}", endpoint_hostname(&rpc.uri), rpc.port);
        let p2p_addr = format!("{}:{}", endpoint_hostname(&p2p.uri), p2p.port);
        OLineDeployer::extract_peer_id_with_boot_wait(&rpc_url, &p2p_addr, 0, 60, 30).await
    } else {
        None
    };

    if let Some(ref p) = snapshot_peer {
        tracing::info!("  Snapshot peer: {}", p);
    }
    if let Some(ref p) = seed_peer {
        tracing::info!("  Seed peer: {}", p);
    }

    let validator_node_id = validator_peer.split('@').next().unwrap_or("").to_string();

    let statesync_rpc = [snap_rpc_ep, seed_rpc_ep]
        .iter()
        .filter_map(|ep| ep.map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port)))
        .collect::<Vec<_>>()
        .join(",");

    // ── 12. Bootstrap Phase B tackles with REAL peer config ──────────────────
    // Sentries deployed with empty peers; inject real config via SFTP refresh_vars.
    tracing::info!("\n── Bootstrapping Phase B tackles ──");
    let mut b_refresh_base = b_deploy_vars.clone();
    b_refresh_base.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        comma_join(&[
            snapshot_peer.as_deref().unwrap_or(""),
            &validator_peer,
        ]),
    );
    b_refresh_base.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), validator_node_id.clone());
    b_refresh_base.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), validator_node_id.clone());
    b_refresh_base.insert("STATESYNC_RPC_SERVERS".into(), statesync_rpc.clone());

    for (label, svc) in [
        ("testnet-left-tackle", "oline-b-left-tackle"),
        ("testnet-right-tackle", "oline-b-right-tackle"),
    ] {
        let eps: Vec<_> = b_endpoints
            .iter()
            .filter(|e| e.service == svc)
            .cloned()
            .collect();
        if !eps.is_empty() {
            let suffix = if svc.contains("left") { "TACKLE_L" } else { "TACKLE_R" };
            bootstrap_sentry(
                label, &eps, &ssh_key_path, &scripts_path, None,
                &genesis_file, &node_refresh_vars(&b_refresh_base, suffix),
            )
            .await?;
        }
    }

    // Wait for tackle peer IDs
    tracing::info!("\n── Waiting for tackle peer IDs ──");
    let lt_rpc =
        OLineDeployer::find_endpoint_by_internal_port(&b_endpoints, "oline-b-left-tackle", 26657);
    let lt_p2p =
        OLineDeployer::find_endpoint_by_internal_port(&b_endpoints, "oline-b-left-tackle", 26656);
    let rt_rpc =
        OLineDeployer::find_endpoint_by_internal_port(&b_endpoints, "oline-b-right-tackle", 26657);
    let rt_p2p =
        OLineDeployer::find_endpoint_by_internal_port(&b_endpoints, "oline-b-right-tackle", 26656);

    let left_tackle_peer = if let (Some(rpc), Some(p2p)) = (lt_rpc, lt_p2p) {
        let rpc_url = format!("http://{}:{}", endpoint_hostname(&rpc.uri), rpc.port);
        let p2p_addr = format!("{}:{}", endpoint_hostname(&p2p.uri), p2p.port);
        OLineDeployer::extract_peer_id_with_boot_wait(&rpc_url, &p2p_addr, 120, 20, 30).await
    } else {
        None
    };
    let right_tackle_peer = if let (Some(rpc), Some(p2p)) = (rt_rpc, rt_p2p) {
        let rpc_url = format!("http://{}:{}", endpoint_hostname(&rpc.uri), rpc.port);
        let p2p_addr = format!("{}:{}", endpoint_hostname(&p2p.uri), p2p.port);
        OLineDeployer::extract_peer_id_with_boot_wait(&rpc_url, &p2p_addr, 0, 20, 30).await
    } else {
        None
    };

    if let Some(ref p) = left_tackle_peer {
        tracing::info!("  Left tackle peer: {}", p);
    }
    if let Some(ref p) = right_tackle_peer {
        tracing::info!("  Right tackle peer: {}", p);
    }

    // ── 13. Bootstrap Phase C forwards with REAL peer config ─────────────────
    tracing::info!("\n── Bootstrapping Phase C forwards ──");
    let mut c_refresh_base = c_deploy_vars.clone();
    c_refresh_base.insert("TERPD_P2P_SEEDS".into(),
        seed_peer.as_deref().unwrap_or("").to_string());
    c_refresh_base.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        comma_join(&[
            snapshot_peer.as_deref().unwrap_or(""),
            &validator_peer,
        ]),
    );
    let lt_id = left_tackle_peer.as_deref().unwrap_or("").split('@').next().unwrap_or("");
    let rt_id = right_tackle_peer.as_deref().unwrap_or("").split('@').next().unwrap_or("");
    let private_ids = comma_join(&[lt_id, rt_id, &validator_node_id]);
    c_refresh_base.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), private_ids.clone());
    c_refresh_base.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), private_ids);
    c_refresh_base.insert("STATESYNC_RPC_SERVERS".into(), statesync_rpc.clone());

    for (label, svc) in [
        ("testnet-left-forward", "oline-c-left-forward"),
        ("testnet-right-forward", "oline-c-right-forward"),
    ] {
        let eps: Vec<_> = c_endpoints
            .iter()
            .filter(|e| e.service == svc)
            .cloned()
            .collect();
        if !eps.is_empty() {
            let suffix = if svc.contains("left") { "FORWARD_L" } else { "FORWARD_R" };
            bootstrap_sentry(
                label, &eps, &ssh_key_path, &scripts_path, None,
                &genesis_file, &node_refresh_vars(&c_refresh_base, suffix),
            )
            .await?;
        }
    }

    // ── 14. Summary ──────────────────────────────────────────────────────────
    let faucet_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "testnet-a-validator", 5000);
    let val_api_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "testnet-a-validator", 1317);

    tracing::info!("\n══════════════════════════════════════════════════════════════");
    tracing::info!("  TESTNET DEPLOYED SUCCESSFULLY");
    tracing::info!("══════════════════════════════════════════════════════════════");
    tracing::info!("  Chain ID:       {}", args.chain_id);
    tracing::info!("  Validator Peer: {}", validator_peer);
    tracing::info!("  Batch Lease TX: {}", batch_tx.hash);

    if let Some(ep) = &validator_rpc_ep {
        tracing::info!("  Validator RPC:  http://{}:{}", endpoint_hostname(&ep.uri), ep.port);
    }
    if let Some(ep) = val_api_ep {
        tracing::info!("  Validator API:  http://{}:{}", endpoint_hostname(&ep.uri), ep.port);
    }
    if let Some(ep) = faucet_ep {
        tracing::info!("  Faucet:         http://{}:{}/faucet?address=terp1...",
            endpoint_hostname(&ep.uri), ep.port);
    }
    if let Some(ref p) = snapshot_peer {
        tracing::info!("  Snapshot Peer:  {}", p);
    }
    if let Some(ref p) = seed_peer {
        tracing::info!("  Seed Peer:      {}", p);
    }
    if let Some(ref p) = left_tackle_peer {
        tracing::info!("  Left Tackle:    {}", p);
    }
    if let Some(ref p) = right_tackle_peer {
        tracing::info!("  Right Tackle:   {}", p);
    }

    tracing::info!("\n  ── Phase A Endpoints ──");
    for ep in &a_endpoints {
        tracing::info!("    {}:{} → {}:{}", ep.service, ep.internal_port, ep.uri, ep.port);
    }
    tracing::info!("\n  ── Phase B Endpoints ──");
    for ep in &b_endpoints {
        tracing::info!("    {}:{} → {}:{}", ep.service, ep.internal_port, ep.uri, ep.port);
    }
    tracing::info!("\n  ── Phase C Endpoints ──");
    for ep in &c_endpoints {
        tracing::info!("    {}:{} → {}:{}", ep.service, ep.internal_port, ep.uri, ep.port);
    }
    tracing::info!("══════════════════════════════════════════════════════════════\n");

    Ok(())
}

// ── Variable builders ────────────────────────────────────────────────────────

async fn build_testnet_a_vars(
    config: &OLineConfig,
    secrets_path: &str,
    localterp_image: &str,
    chain_id: &str,
    fast_blocks: bool,
) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut vars = config.to_sdl_vars();

    vars.insert("VALIDATOR_SVC".into(), "testnet-a-validator".into());
    vars.insert("SNAPSHOT_SVC".into(), "testnet-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "testnet-a-seed".into());

    vars.insert("LOCALTERP_IMAGE".into(), localterp_image.to_string());
    vars.insert("TESTNET_CHAIN_ID".into(), chain_id.to_string());
    vars.insert(
        "TESTNET_FAST_BLOCKS".into(),
        if fast_blocks { "true" } else { "false" }.into(),
    );

    vars.insert("SNAPSHOT_MONIKER".into(), generate_credential(12));
    vars.insert("SEED_MONIKER".into(), generate_credential(12));

    let key_path: PathBuf = format!("{}/oline-testnet-key", secrets_path).into();
    let ssh_key = ensure_ssh_key(&key_path)?;
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());
    vars.insert(
        "SSH_PRIVKEY".into(),
        ssh_key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
    );
    vars.insert("SSH_KEY_PATH".into(), key_path.to_string_lossy().into());

    // Empty peer placeholders — injected via SFTP signal after validator boots
    vars.insert("TERPD_P2P_PERSISTENT_PEERS".into(), String::new());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), String::new());
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), String::new());

    vars.insert("SNAPSHOT_80_ACCEPTS".into(), build_accept_items(&vars, "SNAPSHOT"));
    vars.insert("SEED_80_ACCEPTS".into(), build_accept_items(&vars, "SEED"));

    Ok(vars)
}

fn build_testnet_b_vars(
    config: &OLineConfig,
    chain_id: &str,
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
    vars.insert("LEFT_TACKLE_MONIKER".into(), generate_credential(12));
    vars.insert("RIGHT_TACKLE_MONIKER".into(), generate_credential(12));

    // SSH key — reuse Phase A's keypair so bootstrap_sentry can SFTP in
    vars.insert("SSH_PUBKEY".into(), ssh_pubkey.to_string());

    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        comma_join(&[snapshot_peer, validator_peer]),
    );
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), validator_node_id.to_string());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), validator_node_id.to_string());
    vars.insert("STATESYNC_RPC_SERVERS".into(), statesync_rpc.to_string());

    vars.insert("LT_80_ACCEPTS".into(), build_accept_items(&vars, "TACKLE_L"));
    vars.insert("RT_80_ACCEPTS".into(), build_accept_items(&vars, "TACKLE_R"));

    vars
}

fn build_testnet_c_vars(
    config: &OLineConfig,
    chain_id: &str,
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
    vars.insert("LEFT_FORWARD_MONIKER".into(), generate_credential(12));
    vars.insert("RIGHT_FORWARD_MONIKER".into(), generate_credential(12));

    // SSH key — reuse Phase A's keypair so bootstrap_sentry can SFTP in
    vars.insert("SSH_PUBKEY".into(), ssh_pubkey.to_string());

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

    vars.insert("LF_80_ACCEPTS".into(), build_accept_items(&vars, "FORWARD_L"));
    vars.insert("RF_80_ACCEPTS".into(), build_accept_items(&vars, "FORWARD_R"));

    vars
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
    genesis_file: &PreStartFile,
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

    push_pre_start_files(label, endpoints, ssh_key_path, &[genesis_file.clone()], MAX_RETRIES)
        .await
        .map_err(|e| -> Box<dyn Error> {
            format!("[{}] Genesis push failed: {}", label, e).into()
        })?;

    verify_files_and_signal_start(
        label, endpoints, ssh_key_path,
        &["/tmp/genesis.json".to_string()], refresh_vars,
    )
    .await
    .map_err(|e| -> Box<dyn Error> {
        format!("[{}] Signal failed: {}", label, e).into()
    })?;

    tracing::info!("  [{}] Signaled — node starting.", label);
    Ok(())
}
