//! `oline refresh` — SSH-based config update for running Akash nodes.
//!
//! Allows pushing updated environment variables to running nodes and re-running
//! entrypoint scripts without closing and redeploying.  All sensitive config
//! stays encrypted on the orchestrator device; vars are decrypted in memory,
//! transferred via SSH, and applied to the node's `/tmp/oline-env.sh`.

use crate::{
    akash::{build_phase_a_vars, build_phase_b_vars, build_phase_c_vars, build_phase_rly_vars},
    cli::*,
    config::*,
    crypto::{check_rpc_health, ssh_push_env_and_run},
    nodes::{NodeRecord, NodeStore},
    with_examples,
};
use std::{
    error::Error,
    io::{self, BufRead},
};

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct RefreshArgs {
        #[command(subcommand)]
        pub cmd: RefreshSubcommand,
    }
    => "../../docs/examples/refresh.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum RefreshSubcommand {
    /// Push updated env vars to a saved node and run a command
    Run {
        /// Node ID (DSEQ.N) or label (from `oline refresh list`)
        label: String,
        /// Shell command to run on the node after env update
        /// (default: re-run the bootstrap entrypoint with OLINE_PHASE=refresh)
        #[arg(long)]
        command: Option<String>,
    },
    /// Register a node in the encrypted store
    Add,
    /// List saved nodes
    List,
    /// Check RPC health of all saved nodes
    Status,
    /// Remove a node from the store by DSEQ
    Remove {
        /// Deployment sequence number to remove
        dseq: u64,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn cmd_refresh(args: &RefreshArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        RefreshSubcommand::Run { label, command } => cmd_refresh_run(label, command.as_deref()).await,
        RefreshSubcommand::Add => cmd_refresh_add(),
        RefreshSubcommand::List => cmd_refresh_list(),
        RefreshSubcommand::Status => cmd_refresh_status().await,
        RefreshSubcommand::Remove { dseq } => cmd_refresh_remove(*dseq),
    }
}

// ── run ───────────────────────────────────────────────────────────────────────

async fn cmd_refresh_run(label: &str, override_cmd: Option<&str>) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== SSH Refresh: {} ===\n", label);

    // Load credentials
    let (mnemonic, password) = unlock_mnemonic()?;
    let store = NodeStore::open(NodeStore::default_path(), &password);
    let record = store.find(label)?;

    tracing::info!("  Node:   {} (Phase {})", record.label, record.phase);
    tracing::info!("  Host:   {}:{}", record.host, record.ssh_port);
    tracing::info!("  DSEQ:   {}", record.dseq);
    tracing::info!("  Key:    {}", record.key_path().display());

    // Build current env vars for the phase
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let config = collect_config(&password, mnemonic, &mut lines).await?;
    drop(lines);

    let env_vars = build_phase_vars(&config, &record.phase).await;

    // Default command: re-run wrapper with OLINE_PHASE=refresh
    // Route to /proc/1/fd/1 so logs are visible via `oline manage logs`
    let default_cmd = "[ -f /tmp/wrapper.sh ] || echo 'No wrapper.sh — skipping restart'; \
                       [ -f /tmp/wrapper.sh ] && OLINE_PHASE=refresh nohup bash /tmp/wrapper.sh \
                       >>/proc/1/fd/1 2>&1 & echo \"Refresh PID: $!\"";
    let command = override_cmd.unwrap_or(default_cmd);

    ssh_push_env_and_run(
        &record.label,
        &record.host,
        record.ssh_port,
        &record.key_path(),
        &env_vars,
        command,
    )
    .await?;

    tracing::info!("\n  Refresh complete.");
    Ok(())
}

// ── add ───────────────────────────────────────────────────────────────────────

fn cmd_refresh_add() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Register Node ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let password = rpassword::prompt_password("Node store password: ")?;
    let store = NodeStore::open(NodeStore::default_path(), &password);

    let node_label = read_input(&mut lines, "Label (e.g. 'Phase A - Snapshot')", None)?;
    if node_label.is_empty() {
        return Err("Label is required.".into());
    }

    let dseq_str = read_input(&mut lines, "DSEQ", None)?;
    let dseq: u64 = dseq_str.trim().parse().map_err(|_| "Invalid DSEQ")?;

    let phase = read_input(&mut lines, "Phase (A / B / C / E)", Some("A"))?;
    let service = read_input(&mut lines, "Service name (e.g. oline-a-snapshot)", None)?;

    let host = read_input(&mut lines, "SSH host (provider hostname, no port)", None)?;
    if host.is_empty() {
        return Err("SSH host is required.".into());
    }

    let port_str = read_input(&mut lines, "SSH external port (from provider)", None)?;
    let ssh_port: u16 = port_str.trim().parse().unwrap_or(22);

    let rpc_url = read_input(
        &mut lines,
        "RPC URL for health check (e.g. http://provider.host:26XXX)",
        None,
    )?;

    let key_name_default = "oline-ssh-key".to_string();
    let key_name = read_input(
        &mut lines,
        &format!("SSH key filename in $SECRETS_PATH (default: {})", key_name_default),
        Some(&key_name_default),
    )?;
    let key_name = if key_name.is_empty() { key_name_default } else { key_name };

    let record = NodeRecord::new(
        node_label.clone(),
        dseq,
        service,
        host,
        ssh_port,
        rpc_url,
        key_name,
        phase,
    );

    store.add(record)?;
    tracing::info!("\n  Saved node '{}' to {:?}", node_label, NodeStore::default_path());

    Ok(())
}

// ── list ──────────────────────────────────────────────────────────────────────

fn cmd_refresh_list() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Saved Nodes ===\n");

    let password = rpassword::prompt_password("Node store password: ")?;
    let store = NodeStore::open(NodeStore::default_path(), &password);
    let records = store.load()?;

    if records.is_empty() {
        tracing::info!("  No nodes saved. Run `oline refresh add` to register one.");
        return Ok(());
    }

    tracing::info!(
        "  {:<10}  {:<8}  {:<35}  {}",
        "ID", "Phase", "Label", "SSH Host:Port"
    );
    tracing::info!("  {:-<85}", "");

    // Group by DSEQ to assign index within each deployment
    let mut dseq_idx: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for r in &records {
        let idx = dseq_idx.entry(r.dseq).or_insert(0);
        let composite = format!("{}.{}", r.dseq, idx);
        tracing::info!(
            "  {:<10}  {:<8}  {:<35}  {}:{}",
            composite,
            r.phase,
            r.label,
            r.host,
            r.ssh_port,
        );
        *idx += 1;
    }

    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

async fn cmd_refresh_status() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Node Health Status ===\n");

    let password = rpassword::prompt_password("Node store password: ")?;
    let store = NodeStore::open(NodeStore::default_path(), &password);
    let records = store.load()?;

    if records.is_empty() {
        tracing::info!("  No nodes saved. Run `oline refresh add` to register one.");
        return Ok(());
    }

    tracing::info!(
        "  {:<10}  {:<35}  {:<8}  {}",
        "ID", "Label", "Phase", "RPC Status"
    );
    tracing::info!("  {:-<90}", "");

    let mut dseq_idx: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for r in &records {
        let idx = dseq_idx.entry(r.dseq).or_insert(0);
        let composite = format!("{}.{}", r.dseq, idx);
        let status = if r.rpc_url.is_empty() {
            "no RPC URL".to_string()
        } else {
            match check_rpc_health(&r.rpc_url).await {
                Ok(s) => s,
                Err(e) => format!("ERROR: {}", e),
            }
        };
        tracing::info!("  {:<10}  {:<35}  {:<8}  {}", composite, r.label, r.phase, status);
        *idx += 1;
    }

    Ok(())
}

// ── remove ────────────────────────────────────────────────────────────────────

fn cmd_refresh_remove(dseq: u64) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Remove Node (DSEQ {}) ===\n", dseq);
    let password = rpassword::prompt_password("Node store password: ")?;
    let store = NodeStore::open(NodeStore::default_path(), &password);
    let removed = store.remove_by_dseq(dseq)?;
    if removed > 0 {
        tracing::info!("  Removed {} node record(s) for DSEQ {}.", removed, dseq);
    } else {
        tracing::info!("  No records found for DSEQ {}.", dseq);
    }
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build env vars for the given phase from the current config.
/// This mirrors what the deploy workflow does — ensuring the refresh pushes
/// consistent vars without redeploying.
pub async fn build_phase_vars(
    config: &crate::config::OLineConfig,
    phase: &str,
) -> std::collections::HashMap<String, String> {
    match phase.to_uppercase().as_str() {
        "B" => build_phase_b_vars(config, "", ""),
        "C" => build_phase_c_vars(config, "", "", "", "", ""),
        "E" => build_phase_rly_vars(config),
        _ => {
            // Phase A (default)
            build_phase_a_vars(config, &std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into()))
                .await
                .expect("build_phase_a_vars failed")
        }
    }
}
