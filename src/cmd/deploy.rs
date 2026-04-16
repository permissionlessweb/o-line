use crate::{
    cli::*, config::*, crypto::*, nodes::NodeStore, snapshots::fetch_snapshot_url_from_metadata,
    with_examples,
};
use akash_deploy_rs::{AkashBackend, AkashClient, DeploymentStore, FileDeploymentStore, KeySigner};
use std::{
    collections::HashSet,
    env::var,
    error::Error,
    io::{self, BufRead},
    path::{Path, PathBuf},
};

// ── Clap arg structs ─────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct EncryptArgs {}
    => "../../docs/examples/encrypt.md"
}

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct DeployArgs {
        /// Enter mnemonic interactively instead of reading from .env
        #[arg(long)]
        pub raw: bool,
        /// Use parallel deployment: deploy all phases before snapshot sync wait.
        /// All phases (A, B, C) are deployed up-front; B and C use SNAPSHOT_MODE=sftp
        /// and receive the snapshot archive after phase A syncs, saving ~60 min.
        #[arg(long, default_value_t = true)]
        pub parallel: bool,
        /// Use sequential deployment (legacy, one phase at a time).
        #[arg(long, conflicts_with = "parallel")]
        pub sequential: bool,
    }
    => "../../docs/examples/deploy.md"
}

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct ManageArgs {
        #[command(subcommand)]
        pub cmd: Option<ManageSubcommand>,
    }
    => "../../docs/examples/manage.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum ManageSubcommand {
    /// Query on-chain active deployments, reconcile local store
    Sync,
    /// Delete SSH key files for non-active DSEQs
    PruneKeys,
    /// SSH into node, kill process, re-run full start sequence
    Restart {
        /// Node ID (DSEQ.N) or label (from `oline refresh list`)
        label: String,
    },
    /// Stream container logs from an Akash provider via WebSocket
    Logs {
        /// Deployment sequence number
        dseq: u64,
        /// Filter to a specific service name
        #[arg(long)]
        service: Option<String>,
        /// Number of historical lines to fetch (default: 100)
        #[arg(long, default_value = "100")]
        tail: u64,
    },
    /// Reconnect to a session's TUI log viewer
    Tui {
        /// Session ID (default: latest session)
        #[arg(long)]
        session: Option<String>,
    },
    /// Check liveness of deployments in a session
    Status {
        /// Session ID (default: latest session)
        #[arg(long)]
        session: Option<String>,
    },
    /// Return remaining funds from HD child accounts back to master.
    ///
    /// Queries each child's on-chain balance, subtracts gas reserve,
    /// and sends the remainder to the master account.
    Drain {
        /// Session ID to drain (default: latest session).
        #[arg(long)]
        session: Option<String>,
        /// Gas reserve per child tx (uakt). Default: 10000.
        #[arg(long, default_value = "10000")]
        gas_reserve: u64,
        /// Actually broadcast drain txs. Without this flag, only prints balances.
        #[arg(long)]
        execute: bool,
    },
}

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct BootstrapArgs {
        /// Run commands locally instead of over SSH
        #[arg(long, short = 'l')]
        pub local: bool,

        /// SSH host IP or hostname (env: OLINE_PRIVATE_NODE_HOST)
        #[arg(long, env = "OLINE_PRIVATE_NODE_HOST")]
        pub host: Option<String>,

        /// SSH port (env: OLINE_PRIVATE_NODE_P)
        #[arg(long, env = "OLINE_PRIVATE_NODE_P", default_value = "22")]
        pub port: u16,

        /// SSH private key path (env: OLINE_PRIVATE_NODE_KEY)
        #[arg(long, env = "OLINE_PRIVATE_NODE_KEY")]
        pub key: Option<String>,

        /// Cosmos daemon binary name (env: OLINE_BINARY)
        #[arg(long, env = "OLINE_BINARY", default_value = "terpd")]
        pub binary: String,

        /// Node home directory (env: OLINE_PRIVATE_NODE_HOME)
        #[arg(long, env = "OLINE_PRIVATE_NODE_HOME")]
        pub home: Option<String>,

        /// Persistent peers id@host:port,... (env: OLINE_PERSISTENT_PEERS)
        #[arg(long, env = "OLINE_PERSISTENT_PEERS")]
        pub peers: Option<String>,

        /// Snapshot URL (env: OLINE_SNAP_BASE_URL)
        #[arg(long, env = "OLINE_SNAP_BASE_URL")]
        pub snapshot: Option<String>,

        /// Snapshot format (env: OLINE_SNAP_SAVE_FORMAT)
        #[arg(long, env = "OLINE_SNAP_SAVE_FORMAT", default_value = "tar.lz4")]
        pub format: String,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        pub yes: bool
    }
    => "../../docs/examples/bootstrap.md"
}

impl Default for BootstrapArgs {
    fn default() -> Self {
        Self {
            local: false,
            host: None,
            port: 22,
            key: None,
            binary: "terpd".into(),
            home: None,
            peers: None,
            snapshot: None,
            format: "tar.lz4".into(),
            yes: false,
            examples: false,
        }
    }
}

// ── Subcommand: manage ──
pub async fn cmd_manage_deployments() -> Result<(), Box<dyn Error>> {
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
                let pw = get_password("Enter config password: ")?;
                if let Some(cfg) = load_config(&pw) {
                    (
                        cfg.val("OLINE_RPC_ENDPOINT"),
                        cfg.val("OLINE_GRPC_ENDPOINT"),
                    )
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

// ── Subcommand: manage (dispatcher) ──
pub async fn cmd_manage(args: &ManageArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        None => cmd_manage_deployments().await,
        Some(ManageSubcommand::Sync) => cmd_manage_sync().await,
        Some(ManageSubcommand::PruneKeys) => cmd_manage_prune_keys().await,
        Some(ManageSubcommand::Restart { label }) => cmd_manage_restart(label).await,
        Some(ManageSubcommand::Logs { dseq, service, tail }) => {
            cmd_manage_logs(*dseq, service.as_deref(), *tail).await
        }
        Some(ManageSubcommand::Tui { session }) => cmd_manage_tui(session.as_deref()).await,
        Some(ManageSubcommand::Status { session }) => cmd_manage_status(session.as_deref()).await,
        Some(ManageSubcommand::Drain {
            session,
            gas_reserve,
            execute,
        }) => cmd_manage_drain(session.as_deref(), *gas_reserve, *execute).await,
    }
}

// ── manage sync ─────────────────────────────────────────────────────────────

async fn cmd_manage_sync() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Manage: Sync with Chain ===\n");

    let (mnemonic, password) = unlock_mnemonic()?;

    // Load saved config for endpoints
    let config = if std::env::var("OLINE_NON_INTERACTIVE").is_ok() {
        build_config_from_env(mnemonic.clone())
    } else {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        let cfg = collect_config(&password, mnemonic.clone(), &mut lines).await?;
        drop(lines);
        cfg
    };

    let _rpc = config.val("OLINE_RPC_ENDPOINT");
    let grpc = normalize_grpc_endpoint(&config.val("OLINE_GRPC_ENDPOINT"));
    let owner = crate::accounts::child_address_str(&mnemonic, 0, "akash")
        .map_err(|e| format!("Failed to derive address: {}", e))?;

    tracing::info!("  Owner:  {}", owner);
    tracing::info!("  gRPC:   {}", grpc);

    // Query on-chain active deployments via gRPC
    use akash_deploy_rs::gen::akash::deployment::v1beta5::{
        query_client::QueryClient as DeployQueryClient, DeploymentFilters, QueryDeploymentsRequest,
    };

    let mut deploy_client = DeployQueryClient::connect(grpc.clone())
        .await
        .map_err(|e| format!("Failed to connect deployment query client: {}", e))?;

    let resp = deploy_client
        .deployments(QueryDeploymentsRequest {
            filters: Some(DeploymentFilters {
                owner: owner.clone(),
                dseq: 0,
                state: "active".to_string(),
            }),
            pagination: None,
        })
        .await
        .map_err(|e| format!("Deployment query failed: {}", e))?;

    let on_chain: HashSet<u64> = resp
        .into_inner()
        .deployments
        .iter()
        .filter_map(|d| {
            d.deployment
                .as_ref()
                .and_then(|dep| dep.id.as_ref())
                .map(|id| id.dseq)
        })
        .collect();

    tracing::info!("  On-chain active: {} deployment(s)", on_chain.len());

    // Load local store
    let mut store = FileDeploymentStore::new_default().await?;
    let local_records = store.list().await?;
    let local_dseqs: HashSet<u64> = local_records.iter().map(|r| r.dseq).collect();

    // Load node store (best-effort — may not have password or file)
    let node_store = NodeStore::open(NodeStore::default_path(), &password);
    let node_records = node_store.load().unwrap_or_default();
    let node_dseqs: HashSet<u64> = node_records.iter().map(|r| r.dseq).collect();

    // Scan SSH key dirs
    let secrets_dir = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let key_dseqs = scan_dseq_key_dirs(Path::new(&secrets_dir));

    // Print summary table
    tracing::info!(
        "\n  {:<8} {:<25} {:<10} {:<6} {:<6}",
        "DSEQ",
        "Label",
        "On-Chain",
        "Keys",
        "SSH"
    );
    tracing::info!("  {:-<60}", "");

    // Show all known DSEQs (union of on-chain + local)
    let mut all_dseqs: Vec<u64> = on_chain.union(&local_dseqs).copied().collect();
    all_dseqs.sort();

    for dseq in &all_dseqs {
        let label = local_records
            .iter()
            .find(|r| r.dseq == *dseq)
            .map(|r| r.label.as_str())
            .unwrap_or("(untracked)");
        let chain_status = if on_chain.contains(dseq) {
            "active"
        } else {
            "CLOSED"
        };
        let has_keys = if key_dseqs.contains(dseq) { "yes" } else { "-" };
        let has_ssh = if node_dseqs.contains(dseq) {
            "yes"
        } else {
            "-"
        };

        tracing::info!(
            "  {:<8} {:<25} {:<10} {:<6} {:<6}",
            dseq,
            truncate(label, 25),
            chain_status,
            has_keys,
            has_ssh,
        );
    }

    // Remove closed: local records whose DSEQs aren't active on-chain
    let closed: Vec<u64> = local_dseqs.difference(&on_chain).copied().collect();
    if !closed.is_empty() {
        tracing::info!("\n  Removing {} closed deployment record(s):", closed.len());
        for dseq in &closed {
            let label = local_records
                .iter()
                .find(|r| r.dseq == *dseq)
                .map(|r| r.label.as_str())
                .unwrap_or("?");
            store.delete(*dseq).await?;
            tracing::info!("    DSEQ {} ({})", dseq, label);
        }
    }

    // Flag untracked on-chain DSEQs
    let untracked: Vec<u64> = on_chain.difference(&local_dseqs).copied().collect();
    if !untracked.is_empty() {
        tracing::info!(
            "\n  Warning: {} on-chain deployment(s) not in local store:",
            untracked.len()
        );
        for dseq in &untracked {
            tracing::info!("    DSEQ {} (untracked)", dseq);
        }
    }

    if closed.is_empty() && untracked.is_empty() {
        tracing::info!("\n  Local store is in sync with chain.");
    }

    Ok(())
}

// ── manage prune-keys ───────────────────────────────────────────────────────

async fn cmd_manage_prune_keys() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Manage: Prune SSH Keys ===\n");

    // Load active DSEQs from local store
    let store = FileDeploymentStore::new_default().await?;
    let records = store.list().await?;
    let active_dseqs: HashSet<u64> = records.iter().map(|r| r.dseq).collect();

    tracing::info!("  Active deployments: {}", active_dseqs.len());

    // Scan SECRETS_PATH for numeric-named dirs (DSEQ key dirs)
    let secrets_dir = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let secrets_path = Path::new(&secrets_dir);
    let all_key_dseqs = scan_dseq_key_dirs(secrets_path);

    let stale: Vec<u64> = all_key_dseqs.difference(&active_dseqs).copied().collect();

    if stale.is_empty() {
        tracing::info!("  No stale SSH key directories found.");
        return Ok(());
    }

    tracing::info!(
        "  Found {} stale key dir(s) for closed/unknown DSEQs:",
        stale.len()
    );
    for dseq in &stale {
        let dir = secrets_path.join(dseq.to_string());
        tracing::info!("    {}", dir.display());
    }

    let mut lines = io::stdin().lock().lines();
    if !prompt_continue(&mut lines, "Delete these key directories?")? {
        tracing::info!("  Cancelled.");
        return Ok(());
    }
    drop(lines);

    // Delete stale key dirs
    for dseq in &stale {
        let dir = secrets_path.join(dseq.to_string());
        if dir.is_dir() {
            std::fs::remove_dir_all(&dir)?;
            tracing::info!("  Deleted {}", dir.display());
        } else if dir.is_file() {
            std::fs::remove_file(&dir)?;
            tracing::info!("  Deleted {}", dir.display());
        }
    }

    // Also prune matching NodeStore entries (best-effort)
    let pw = if std::env::var("OLINE_NON_INTERACTIVE").is_ok() {
        std::env::var("OLINE_PASSWORD").unwrap_or_default()
    } else {
        rpassword::prompt_password("Node store password (Enter to skip): ")?
    };
    if !pw.is_empty() {
        let node_store = NodeStore::open(NodeStore::default_path(), &pw);
        let mut pruned = 0usize;
        for dseq in &stale {
            let removed = node_store.remove_by_dseq(*dseq).unwrap_or(0);
            pruned += removed;
        }
        if pruned > 0 {
            tracing::info!("  Pruned {} node store record(s).", pruned);
        }
    }

    tracing::info!("  Done.");
    Ok(())
}

// ── manage restart ──────────────────────────────────────────────────────────

async fn cmd_manage_restart(label: &str) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Manage: Restart Node '{}' ===\n", label);

    let (mnemonic, password) = unlock_mnemonic()?;

    let node_store = NodeStore::open(NodeStore::default_path(), &password);
    let record = node_store.find(label)?;

    tracing::info!("  Node:   {} (Phase {})", record.label, record.phase);
    tracing::info!("  Host:   {}:{}", record.host, record.ssh_port);
    tracing::info!("  DSEQ:   {}", record.dseq);
    tracing::info!("  Key:    {}", record.key_path().display());

    // Build current env vars for the phase (same as refresh)
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let config = collect_config(&password, mnemonic, &mut lines).await?;
    drop(lines);

    let env_vars = crate::cmd::refresh::build_phase_vars(&config, &record.phase).await;

    // Restart command: OLINE_PHASE=restart triggers full re-bootstrap
    // Route to /proc/1/fd/1 so logs are visible via `oline manage logs`
    let command = "[ -f /tmp/wrapper.sh ] || { echo 'No wrapper.sh found'; exit 1; }; \
                   OLINE_PHASE=restart nohup bash /tmp/wrapper.sh \
                   >>/proc/1/fd/1 2>&1 & echo \"Restart PID: $!\"";

    ssh_push_env_and_run(
        &record.label,
        &record.host,
        record.ssh_port,
        &record.key_path(),
        &env_vars,
        command,
    )
    .await?;

    tracing::info!("\n  Restart initiated. Stream logs:");
    tracing::info!("    oline manage logs {}", record.dseq);

    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Ensure a gRPC endpoint has an `https://` scheme so tonic uses TLS.
/// Endpoints like `host:443` fail silently without the scheme prefix.
fn normalize_grpc_endpoint(ep: &str) -> String {
    if ep.starts_with("https://") || ep.starts_with("http://") {
        ep.to_string()
    } else {
        format!("https://{}", ep)
    }
}

/// Scan a directory for numeric-named entries (files or dirs) representing DSEQ keys.
fn scan_dseq_key_dirs(dir: &Path) -> HashSet<u64> {
    let mut dseqs = HashSet::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(dseq) = name.parse::<u64>() {
                    dseqs.insert(dseq);
                }
            }
        }
    }
    dseqs
}

// ── Subcommand: bootstrap-private ──
// Bootstrap a private (non-Akash) validator node: inject persistent peers,
// stop the running daemon, clear the data directory, and install a snapshot.
pub async fn cmd_bootstrap_private(args: BootstrapArgs) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Bootstrap Private Validator ===\n");

    let yes = args.yes;
    let local_mode = args.local;

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // ── SSH connection details (skipped in local mode) ──
    let (ssh_host, ssh_port, ssh_key_path) = if local_mode {
        tracing::info!("  Mode: local (commands run on this machine)\n");
        (String::new(), 0u16, PathBuf::new())
    } else {
        tracing::info!("  Mode: SSH (commands run on remote node)\n");

        let host_default = args.host.as_deref().unwrap_or("");
        let ssh_host = read_input(
            &mut lines,
            "Remote node SSH host (IP or hostname)",
            Some(host_default),
        )?;
        if ssh_host.is_empty() {
            return Err("SSH host is required (or pass --local to run locally).".into());
        }

        let port_str = args.port.to_string();
        let ssh_port_str = read_input(&mut lines, "SSH port", Some(&port_str))?;
        let ssh_port: u16 = ssh_port_str.trim().parse().unwrap_or(22);
        let key_default = args.key.as_deref().unwrap_or("~/.ssh/id_ed25519");
        let ssh_key_str = read_input(&mut lines, "Path to SSH private key", Some(key_default))?;
        let ssh_key_path: PathBuf = if ssh_key_str.starts_with('~') {
            let home = var("HOME").unwrap_or_else(|_| ".".into());
            format!("{}{}", home, &ssh_key_str[1..]).into()
        } else {
            ssh_key_str.into()
        };

        (ssh_host, ssh_port, ssh_key_path)
    };

    // ── Node details ──
    let binary = read_input(&mut lines, "Cosmos daemon binary name", Some(&args.binary))?;

    let home_default = args.home.as_deref().unwrap_or("");
    let home_dir = read_input(
        &mut lines,
        "Node home directory (e.g. /root/.terpd)",
        Some(home_default),
    )?;
    if home_dir.is_empty() {
        return Err("Node home directory is required.".into());
    }

    // ── Peers ──
    let peers_default = args.peers.as_deref().unwrap_or("");
    let persistent_peers = read_input(
        &mut lines,
        "Persistent peers (id@host:port,...) — press Enter to skip",
        Some(peers_default),
    )?;

    // ── Snapshot — auto-resolve from configured state URL if not provided ──
    let snap_default: String = if let Some(url) = args.snapshot.clone() {
        url
    } else {
        let full = var("OLINE_SNAP_FULL_URL").unwrap_or_default();
        let state_url = var("OLINE_SNAP_STATE_URL").unwrap_or_default();
        let base_url = var("OLINE_SNAP_BASE_URL").unwrap_or_default();
        if !full.is_empty() {
            full
        } else if !state_url.is_empty() && !base_url.is_empty() {
            tracing::info!("  Resolving snapshot URL from state: {}", state_url);
            let fallback = format!("{}latest.tar.lz4", base_url.trim_end_matches('/'));
            let resolved = fetch_snapshot_url_from_metadata(&state_url, &fallback).await;
            tracing::info!("  Resolved: {}", resolved);
            resolved
        } else {
            String::new()
        }
    };
    let snapshot_url = read_input(
        &mut lines,
        "Snapshot URL (press Enter to skip snapshot installation)",
        Some(&snap_default),
    )?;

    let snapshot_format = if !snapshot_url.is_empty() {
        read_input(&mut lines, "Snapshot format", Some(&args.format))?
    } else {
        String::new()
    };

    // ── Summary ──
    tracing::info!("\n  Summary:");
    if local_mode {
        tracing::info!("    Mode:           local");
    } else {
        tracing::info!("    Host:           {}:{}", ssh_host, ssh_port);
        tracing::info!("    SSH key:        {}", ssh_key_path.display());
    }
    tracing::info!("    Binary:         {}", binary);
    tracing::info!("    Home dir:       {}", home_dir);
    if !persistent_peers.is_empty() {
        tracing::info!("    Peers:          {}", persistent_peers);
    }
    if !snapshot_url.is_empty() {
        tracing::info!("    Snapshot URL:   {}", snapshot_url);
        tracing::info!("    Format:         {}", snapshot_format);
    }

    if !yes && !prompt_continue(&mut lines, "Proceed with bootstrap?")? {
        tracing::info!("Aborted.");
        return Ok(());
    }
    drop(lines);

    if local_mode {
        bootstrap_private_node_local(
            "private-validator",
            &home_dir,
            &binary,
            &persistent_peers,
            &snapshot_url,
            &snapshot_format,
        )
        .await?;
        tracing::info!("\n  Bootstrap complete.");
        tracing::info!("  Start the node:  systemctl start {}", binary);
    } else {
        bootstrap_private_node(
            "private-validator",
            &ssh_host,
            ssh_port,
            &ssh_key_path,
            &home_dir,
            &binary,
            &persistent_peers,
            &snapshot_url,
            &snapshot_format,
        )
        .await?;
        tracing::info!("\n  Bootstrap complete.");
        tracing::info!(
            "  Start the node:  ssh -p {} root@{} 'systemctl start {}'",
            ssh_port,
            ssh_host,
            binary
        );
    }

    Ok(())
}

// ── manage logs ─────────────────────────────────────────────────────────────

async fn cmd_manage_logs(
    dseq: u64,
    service: Option<&str>,
    tail: u64,
) -> Result<(), Box<dyn Error>> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

    // 1. Load deployment record
    let store = FileDeploymentStore::new_default().await?;
    let record = store
        .load(dseq)
        .await?
        .ok_or_else(|| format!("no deployment found for dseq {dseq}"))?;

    let lease = record
        .lease_id
        .ok_or("deployment has no lease — was it fully deployed?")?;

    // 2. Check trusted provider → get host_uri
    let tp_store = crate::providers::TrustedProviderStore::open(
        crate::providers::TrustedProviderStore::default_path(),
    );
    let provider = tp_store.find(&lease.provider).ok_or_else(|| {
        format!(
            "provider {} is not trusted — add with `oline provider trust`",
            lease.provider
        )
    })?;

    // 3. Build AkashClient + generate JWT
    let (mnemonic, _password) = unlock_mnemonic()?;
    let rpc = var("OLINE_RPC_ENDPOINT")
        .unwrap_or_else(|_| "https://rpc-akash.ecostake.com:443".into());
    let grpc = var("OLINE_GRPC_ENDPOINT")
        .unwrap_or_else(|_| "https://akash.lavenderfive.com:443".into());
    let client = AkashClient::new_from_mnemonic(&mnemonic, &rpc, &grpc).await?;
    let jwt = client
        .generate_jwt(&lease.owner)
        .await
        .map_err(|e| format!("JWT generation failed: {e}"))?;

    // 4. Build WebSocket URL
    let host = provider.host_uri.trim_end_matches('/');
    let mut url = format!(
        "{}/lease/{}/{}/{}/logs?follow=true&tail={}",
        host.replace("https://", "wss://"),
        lease.dseq,
        lease.gseq,
        lease.oseq,
        tail,
    );
    if let Some(svc) = service {
        url.push_str(&format!("&service={svc}"));
    }
    tracing::info!(
        "streaming logs from {} (dseq={})",
        provider.display_name(),
        dseq
    );

    // 5. Connect with JWT auth header
    let mut req = url.into_client_request()?;
    req.headers_mut().insert(
        "Authorization",
        format!("Bearer {jwt}").parse()?,
    );
    let (ws, _) = tokio_tungstenite::connect_async(req).await?;

    // 6. Stream logs until Ctrl+C
    let (_, mut read) = ws.split();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            msg = read.next() => match msg {
                Some(Ok(Message::Text(line))) => print!("{line}"),
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(e)) => { eprintln!("ws error: {e}"); break; }
                _ => {}
            },
            _ = &mut ctrl_c => {
                eprintln!("\ninterrupted");
                break;
            }
        }
    }
    Ok(())
}

// ── manage tui ──────────────────────────────────────────────────────────────

async fn cmd_manage_tui(session_id: Option<&str>) -> Result<(), Box<dyn Error>> {
    use crate::sessions::OLineSessionStore;
    use crate::tui::{build_log_targets_from_session, TuiController, run_tui};

    tracing::info!("=== Manage: TUI Log Viewer ===\n");

    let store = OLineSessionStore::new();
    let session = match session_id {
        Some(id) => store.load(id)?,
        None => store
            .latest()?
            .ok_or("No sessions found. Run `oline deploy --parallel` first.")?,
    };

    tracing::info!("  Session:      {}", session.id);
    tracing::info!("  Master:       {}", session.master_address);
    tracing::info!("  Deployments:  {}", session.deployments.len());

    if session.deployments.is_empty() {
        tracing::info!("  No deployments recorded in session.");
        return Ok(());
    }

    let (mnemonic, password) = unlock_mnemonic()?;
    let rpc = var("OLINE_RPC_ENDPOINT")
        .unwrap_or_else(|_| "https://rpc-akash.ecostake.com:443".into());
    let grpc = var("OLINE_GRPC_ENDPOINT")
        .unwrap_or_else(|_| "https://akash.lavenderfive.com:443".into());

    let client = AkashClient::new_from_mnemonic(&mnemonic, &rpc, &grpc).await?;
    let targets = build_log_targets_from_session(&session, &client).await;

    if targets.is_empty() {
        tracing::info!("  No connectable log targets found.");
        return Ok(());
    }

    tracing::info!("  Connecting to {} log stream(s)...\n", targets.len());

    let controller = TuiController::new();
    controller.add_targets(targets).await;

    // Load SSH targets from encrypted node store for this session's deployments.
    let dseqs: Vec<u64> = session.deployments.iter().map(|d| d.dseq).filter(|d| *d > 0).collect();
    controller.load_ssh_targets_from_nodes(&password, &dseqs).await;

    run_tui(controller).await?;

    Ok(())
}

// ── manage status ───────────────────────────────────────────────────────────

async fn cmd_manage_status(session_id: Option<&str>) -> Result<(), Box<dyn Error>> {
    use crate::sessions::OLineSessionStore;
    use akash_deploy_rs::gen::akash::deployment::v1beta5::{
        query_client::QueryClient as DeployQueryClient, DeploymentFilters, QueryDeploymentsRequest,
    };

    tracing::info!("=== Manage: Session Status ===\n");

    let store = OLineSessionStore::new();
    let session = match session_id {
        Some(id) => store.load(id)?,
        None => store
            .latest()?
            .ok_or("No sessions found. Run `oline deploy --parallel` first.")?,
    };

    tracing::info!("  Session:  {}", session.id);
    tracing::info!("  Master:   {}", session.master_address);
    tracing::info!("  Chain:    {}", session.chain_id);

    if session.deployments.is_empty() {
        tracing::info!("  No deployments recorded.");
        return Ok(());
    }

    let grpc = normalize_grpc_endpoint(
        &var("OLINE_GRPC_ENDPOINT")
            .unwrap_or_else(|_| "https://akash.lavenderfive.com:443".into()),
    );

    let mut deploy_client = DeployQueryClient::connect(grpc)
        .await
        .map_err(|e| format!("Failed to connect gRPC: {}", e))?;

    let resp = deploy_client
        .deployments(QueryDeploymentsRequest {
            filters: Some(DeploymentFilters {
                owner: session.master_address.clone(),
                dseq: 0,
                state: "active".to_string(),
            }),
            pagination: None,
        })
        .await
        .map_err(|e| format!("Deployment query failed: {}", e))?;

    let on_chain: HashSet<u64> = resp
        .into_inner()
        .deployments
        .iter()
        .filter_map(|d| {
            d.deployment
                .as_ref()
                .and_then(|dep| dep.id.as_ref())
                .map(|id| id.dseq)
        })
        .collect();

    tracing::info!("\n  {:<8} {:<16} {:<20} {:<10}", "DSEQ", "Phase", "Provider", "Status");
    tracing::info!("  {:-<60}", "");

    for dep in &session.deployments {
        let provider = dep
            .provider
            .as_deref()
            .map(|p| {
                if p.len() > 18 {
                    format!("{}..{}", &p[..8], &p[p.len() - 4..])
                } else {
                    p.to_string()
                }
            })
            .unwrap_or_else(|| "-".into());

        let status = if dep.dseq == 0 {
            "no-dseq"
        } else if on_chain.contains(&dep.dseq) {
            "active"
        } else {
            "CLOSED"
        };

        tracing::info!(
            "  {:<8} {:<16} {:<20} {:<10}",
            dep.dseq,
            dep.phase,
            provider,
            status,
        );
    }

    let active_count = session
        .deployments
        .iter()
        .filter(|d| d.dseq > 0 && on_chain.contains(&d.dseq))
        .count();
    tracing::info!(
        "\n  {}/{} deployment(s) active on-chain.",
        active_count,
        session.deployments.len()
    );

    Ok(())
}

// ── manage drain ────────────────────────────────────────────────────────────

/// Return remaining funds from HD child accounts back to the master account.
///
/// For each child in the session:
///   1. Query on-chain balance via gRPC
///   2. Subtract gas_reserve (for the drain tx itself)
///   3. If --execute: broadcast bank_send from child → master
///   4. Print summary
async fn cmd_manage_drain(
    session_id: Option<&str>,
    gas_reserve: u64,
    execute: bool,
) -> Result<(), Box<dyn Error>> {
    use crate::{
        accounts::child_address_str,
        sessions::{FundingMethod, OLineSessionStore},
    };
    use akash_deploy_rs::{AkashBackend, AkashClient};

    tracing::info!("=== Manage: Drain Child Accounts ===\n");

    let store = OLineSessionStore::new();
    let session = match session_id {
        Some(id) => store.load(id)?,
        None => store
            .latest()?
            .ok_or("No sessions found. Run `oline deploy --parallel` first.")?,
    };

    tracing::info!("  Session:  {}", session.id);
    tracing::info!("  Master:   {}", session.master_address);
    tracing::info!("  Chain:    {}", session.chain_id);
    tracing::info!("  Funding:  {:?}", session.funding);

    let _child_count = match &session.funding {
        FundingMethod::HdDerived { count, .. } => *count,
        FundingMethod::Master | FundingMethod::Direct => {
            tracing::info!("  Session uses master account — nothing to drain.");
            return Ok(());
        }
    };

    if session.accounts.is_empty() {
        tracing::info!("  No child accounts recorded in session.");
        return Ok(());
    }

    // We need a mnemonic to sign child drain txs.
    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok();
    let mnemonic = if non_interactive {
        std::env::var("OLINE_MNEMONIC")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .ok_or("OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC")?
            .trim()
            .to_string()
    } else {
        rpassword::prompt_password("Enter mnemonic: ")?
    };

    // Resolve RPC/gRPC endpoints.
    let rpc = var("OLINE_RPC_ENDPOINT")
        .or_else(|_| var("AKASH_NODE"))
        .unwrap_or_default();
    let grpc = var("OLINE_GRPC_ENDPOINT").unwrap_or_default();

    if rpc.is_empty() || grpc.is_empty() {
        return Err(
            "Set OLINE_RPC_ENDPOINT and OLINE_GRPC_ENDPOINT (or run `oline endpoints` first)."
                .into(),
        );
    }

    let denom = var("OLINE_DENOM").unwrap_or_else(|_| "uakt".into());
    let master_addr = &session.master_address;

    tracing::info!("  Gas reserve: {} {}", gas_reserve, denom);
    if !execute {
        tracing::info!("  Mode: DRY RUN (pass --execute to broadcast)\n");
    } else {
        tracing::info!("  Mode: EXECUTE\n");
    }

    let mut total_returned: u128 = 0;
    let mut total_remaining: u128 = 0;

    for acct in &session.accounts {
        let addr = &acct.address;
        let idx = acct.hd_index;
        let label = acct.assigned_to.as_deref().unwrap_or("unassigned");

        // Create a client for this child to query balance and sign drain tx.
        let child_client =
            match AkashClient::new_from_mnemonic_at_index(&mnemonic, idx, &rpc, &grpc).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("  [child {}] failed to connect: {} — skipping.", idx, e);
                    continue;
                }
            };

        // Verify derived address matches session record.
        let derived_addr = child_address_str(&mnemonic, idx, "akash").unwrap_or_default();
        if derived_addr != *addr {
            tracing::warn!(
                "  [child {}] address mismatch: session={} derived={} — skipping.",
                idx,
                addr,
                derived_addr
            );
            continue;
        }

        let balance = match child_client.query_balance(addr, &denom).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("  [child {}] balance query failed: {} — skipping.", idx, e);
                continue;
            }
        };

        let act_balance = match child_client.query_balance(addr, "uact").await {
            Ok(b) => b,
            Err(_) => 0, // ACT balance might be 0 if never funded
        };

        let returnable = balance.saturating_sub(gas_reserve as u128);
        tracing::info!(
            "  [child {} / {}]  akt_balance={} uakt  act_balance={} uact  returnable={} {}",
            idx,
            label,
            balance,
            act_balance,
            returnable,
            denom
        );

        if returnable == 0 {
            tracing::info!("    → nothing to return (balance ≤ gas reserve).");
            total_remaining += balance;
            continue;
        }

        if execute {
            match child_client
                .bank_send(master_addr, returnable, &denom)
                .await
            {
                Ok(r) if r.code == 0 => {
                    tracing::info!(
                        "    → sent {} {} to master (tx={})",
                        returnable,
                        denom,
                        r.hash
                    );
                    total_returned += returnable;
                }
                Ok(r) => {
                    tracing::warn!("    → drain tx rejected: code={} log={}", r.code, r.raw_log);
                    total_remaining += balance;
                }
                Err(e) => {
                    tracing::warn!("    → drain tx error: {}", e);
                    total_remaining += balance;
                }
            }
        } else {
            tracing::info!(
                "    → would send {} {} to master (dry run).",
                returnable,
                denom
            );
            total_returned += returnable;
            total_remaining += gas_reserve as u128;
        }

        // Drain ACT balance too
        if act_balance > 0 && execute {
            match child_client
                .bank_send(master_addr, act_balance, "uact")
                .await
            {
                Ok(r) if r.code == 0 => {
                    tracing::info!("    → sent {} uact to master (tx={})", act_balance, r.hash);
                }
                Ok(r) => {
                    tracing::warn!(
                        "    → ACT drain tx rejected: code={} log={}",
                        r.code,
                        r.raw_log
                    );
                }
                Err(e) => {
                    tracing::warn!("    → ACT drain tx error: {}", e);
                }
            }
        } else if act_balance > 0 {
            tracing::info!("    → would send {} uact to master (dry run).", act_balance);
        }
    }

    tracing::info!("\n  ── Summary ──");
    tracing::info!("  Returned:  {} {}", total_returned, denom);
    tracing::info!("  Remaining: {} {} (gas reserves)", total_remaining, denom);
    if !execute && total_returned > 0 {
        tracing::info!("  Run with --execute to broadcast drain transactions.");
    }

    Ok(())
}
