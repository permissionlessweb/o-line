//! `oline node` — Deploy and manage a dedicated Akash full node on Akash.
//!
//! Provides private RPC/gRPC/REST endpoints for oline itself, eliminating
//! reliance on public endpoints that are often rate-limited or unreliable.

use crate::{
    cli::*,
    config::*,
    crypto::{check_rpc_health, gen_ssh_key, generate_credential, verify_files_and_signal_start},
    deployer::OLineDeployer,
    nodes::{NodeRecord, NodeStore},
    with_examples,
};
use akash_deploy_rs::{AkashBackend, DeploymentRecord, DeploymentStore, FileDeploymentStore, KeySigner};
use std::{
    collections::HashMap,
    error::Error,
    io::{self, BufRead},
    path::PathBuf,
};

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct NodeArgs {
        #[command(subcommand)]
        pub cmd: NodeSubcommand,
    }
    => "../../docs/examples/node.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum NodeSubcommand {
    /// Deploy a dedicated Akash full node and save endpoints to .env
    Deploy,
    /// Check RPC health of the deployed Akash node
    Status,
    /// Close the Akash node deployment and remove from store
    Close,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn cmd_node(args: &NodeArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        NodeSubcommand::Deploy => cmd_node_deploy().await,
        NodeSubcommand::Status => cmd_node_status().await,
        NodeSubcommand::Close => cmd_node_close().await,
    }
}

// ── deploy ────────────────────────────────────────────────────────────────────

async fn cmd_node_deploy() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Deploy Akash Full Node ===\n");

    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok();

    let (mnemonic, password) = if non_interactive {
        let m = std::env::var("OLINE_MNEMONIC")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .ok_or("OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC to be set")?;
        let p = std::env::var("OLINE_PASSWORD").unwrap_or_else(|_| "oline-test".to_string());
        (m.trim().to_string(), p)
    } else {
        unlock_mnemonic()?
    };

    let config = if non_interactive {
        build_config_from_env(mnemonic, None)
    } else {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        let cfg = collect_config(&password, mnemonic, &mut lines, None).await?;
        drop(lines);
        cfg
    };

    let mut deployer = OLineDeployer::new(config, password.clone())
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    // Build SDL variables
    let vars = build_node_vars(&deployer.config);

    // Save SSH private key for post-deploy operations
    let key_name = "oline-node-ssh-key";
    let key_path = crate::config::oline_config_dir().join(key_name);
    if let Some(privkey_pem) = vars.get("SSH_PRIVKEY") {
        let privkey = ssh_key::PrivateKey::from_openssh(privkey_pem)
            .map_err(|e| format!("Failed to parse generated SSH key: {}", e))?;
        crate::crypto::save_ssh_key_encrypted(&privkey, &key_path, &password)?;
        tracing::info!("  SSH key saved to {}", key_path.display());
    }

    // Load and deploy SDL
    let sdl_template = deployer.config.load_sdl("node.yml")?;
    let label = "oline-akash-node";

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let (state, endpoints) = deployer
        .deploy_phase_with_selection(&sdl_template, &vars, label, &mut lines)
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    // Save deployment record
    let record = DeploymentRecord::from_state(&state, &password)
        .map_err(|e| -> Box<dyn Error> { format!("Failed to create deployment record: {}", e).into() })?;
    deployer.deployment_store.save(&record).await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    let dseq = state.dseq.ok_or("Deployment completed but no DSEQ assigned")?;
    tracing::info!("  Deployment saved (DSEQ {})", dseq);

    // Push TLS certs as startup sync signal + launch node
    verify_files_and_signal_start(
        label,
        &endpoints,
        &key_path,
        &[],  // no pre-start files to verify
        &vars,
    )
    .await?;

    // Wait for RPC to come up
    tracing::info!("\n  Waiting for Akash node RPC to become available...");
    let rpc_ep = OLineDeployer::find_endpoint_by_internal_port(&endpoints, label, 26657);
    let rpc_url = rpc_ep
        .map(|ep| format!("http://{}:{}", crate::akash::endpoint_hostname(&ep.uri), ep.port))
        .ok_or("No RPC endpoint found in deployment")?;

    let mut rpc_ready = false;
    for attempt in 1..=30 {
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        match check_rpc_health(&rpc_url).await {
            Ok(status) => {
                tracing::info!("  RPC ready: {}", status);
                rpc_ready = true;
                break;
            }
            Err(e) => {
                if attempt % 5 == 0 {
                    tracing::info!("  RPC attempt {}/30: {}", attempt, e);
                }
            }
        }
    }

    if !rpc_ready {
        tracing::info!("  Warning: RPC did not become available within 5 minutes.");
        tracing::info!("  The node may still be syncing. Check with `oline node status` later.");
    }

    // Extract all endpoint URIs
    let grpc_ep = OLineDeployer::find_endpoint_by_internal_port(&endpoints, label, 9090);
    let rest_ep = OLineDeployer::find_endpoint_by_internal_port(&endpoints, label, 1317);
    let ssh_ep = {
        let ssh_port: u16 = std::env::var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        OLineDeployer::find_endpoint_by_internal_port(&endpoints, label, ssh_port)
    };

    let grpc_url = grpc_ep
        .map(|ep| format!("http://{}:{}", crate::akash::endpoint_hostname(&ep.uri), ep.port))
        .unwrap_or_default();
    let rest_url = rest_ep
        .map(|ep| format!("http://{}:{}", crate::akash::endpoint_hostname(&ep.uri), ep.port))
        .unwrap_or_default();

    // Print summary
    tracing::info!("\n  === Akash Node Endpoints ===");
    tracing::info!("  RPC:  {}", rpc_url);
    tracing::info!("  gRPC: {}", grpc_url);
    tracing::info!("  REST: {}", rest_url);

    // Register in node store
    let store = NodeStore::open(NodeStore::default_path(), &password);
    let ssh_host = ssh_ep
        .map(|ep| crate::akash::endpoint_hostname(&ep.uri).to_string())
        .unwrap_or_default();
    let ssh_port = ssh_ep.map(|ep| ep.port).unwrap_or(22);

    let record = NodeRecord::new(
        "Akash Node",
        dseq,
        label,
        &ssh_host,
        ssh_port,
        &rpc_url,
        key_name,
        "N",
    );
    store.add(record)?;
    tracing::info!("  Node registered in store (DSEQ {})", dseq);

    // Save endpoints to .env
    let should_save = if non_interactive {
        true
    } else {
        prompt_continue(&mut lines, "Save endpoints to .env?")?
    };

    if should_save {
        upsert_env_key("OLINE_RPC_ENDPOINT", &rpc_url)?;
        upsert_env_key("OLINE_GRPC_ENDPOINT", &grpc_url)?;
        upsert_env_key("OLINE_REST_ENDPOINT", &rest_url)?;
        tracing::info!("  Endpoints saved to .env");
    }

    tracing::info!("\n  Akash node deployment complete.");
    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

async fn cmd_node_status() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Akash Node Status ===\n");

    let password = rpassword::prompt_password("Node store password: ")?;
    let store = NodeStore::open(NodeStore::default_path(), &password);
    let records = store.load()?;

    let node_records: Vec<_> = records.iter().filter(|r| r.phase == "N").collect();

    if node_records.is_empty() {
        tracing::info!("  No Akash node deployed. Run `oline node deploy` first.");
        return Ok(());
    }

    for r in &node_records {
        tracing::info!("  DSEQ:  {}", r.dseq);
        tracing::info!("  Host:  {}:{}", r.host, r.ssh_port);
        let status = if r.rpc_url.is_empty() {
            "no RPC URL".to_string()
        } else {
            match check_rpc_health(&r.rpc_url).await {
                Ok(s) => s,
                Err(e) => format!("ERROR: {}", e),
            }
        };
        tracing::info!("  RPC:   {} → {}", r.rpc_url, status);
    }

    Ok(())
}

// ── close ─────────────────────────────────────────────────────────────────────

async fn cmd_node_close() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Close Akash Node ===\n");

    let (mnemonic, password) = unlock_mnemonic()?;

    let node_store = NodeStore::open(NodeStore::default_path(), &password);
    let records = node_store.load()?;
    let node_records: Vec<_> = records.iter().filter(|r| r.phase == "N").collect();

    if node_records.is_empty() {
        tracing::info!("  No Akash node deployed. Nothing to close.");
        return Ok(());
    }

    // If multiple, list them; otherwise use the single one
    let dseq = if node_records.len() == 1 {
        node_records[0].dseq
    } else {
        tracing::info!("  Multiple Akash nodes found:");
        for (i, r) in node_records.iter().enumerate() {
            tracing::info!("    [{}] DSEQ {} — {}", i + 1, r.dseq, r.rpc_url);
        }
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        let choice = read_input(&mut lines, "Select node to close (number)", None)?;
        let idx: usize = choice.trim().parse().map_err(|_| "Invalid selection")?;
        if idx < 1 || idx > node_records.len() {
            return Err("Selection out of range".into());
        }
        node_records[idx - 1].dseq
    };

    tracing::info!("  Closing deployment DSEQ {}...", dseq);

    let rpc = std::env::var("OLINE_RPC_ENDPOINT")
        .unwrap_or_else(|_| "https://rpc-akash.ecostake.com:443".into());
    let grpc = std::env::var("OLINE_GRPC_ENDPOINT")
        .unwrap_or_else(|_| "https://akash.lavenderfive.com:443".into());

    let client = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        akash_deploy_rs::AkashClient::new_from_mnemonic(&mnemonic, &rpc, &grpc),
    )
    .await
    .map_err(|_| "Timed out connecting to Akash RPC")??;

    let signer = KeySigner::new_mnemonic_str(&mnemonic, None)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    let result = client
        .broadcast_close_deployment(&signer, &client.address(), dseq)
        .await?;

    tracing::info!("  Closed! TX hash: {}", result.hash);

    // Remove from deployment store
    let mut deploy_store = FileDeploymentStore::new_default().await?;
    deploy_store.delete(dseq).await?;

    // Remove from node store
    node_store.remove_by_dseq(dseq)?;
    tracing::info!("  Removed from node store.");

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build SDL template variables for the Akash full node deployment.
fn build_node_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    // Service name
    vars.insert("NODE_SVC".into(), "oline-akash-node".into());

    // Random moniker
    vars.insert("NODE_MONIKER".into(), generate_credential(12));

    // Akash chain config
    vars.insert(
        "AKASH_CHAIN_JSON".into(),
        std::env::var("AKASH_CHAIN_JSON").unwrap_or_else(|_| {
            "https://raw.githubusercontent.com/cosmos/chain-registry/master/akash/chain.json"
                .into()
        }),
    );

    vars.insert(
        "AKASH_SNAP_URL".into(),
        std::env::var("AKASH_SNAP_URL").unwrap_or_default(),
    );

    vars.insert(
        "AKASH_ADDRBOOK_URL".into(),
        std::env::var("AKASH_ADDRBOOK_URL").unwrap_or_else(|_| {
            "https://raw.githubusercontent.com/111STAVR111/props/main/Akash/addrbook.json".into()
        }),
    );

    // SSH keypair for cert delivery / post-deploy management
    let ssh_key = gen_ssh_key();
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());
    vars.insert(
        "SSH_PRIVKEY".into(),
        ssh_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string(),
    );

    vars
}
