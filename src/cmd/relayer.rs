//! `oline relayer` — Manage a Cosmos IBC relayer running in a Docker container
//! (on Akash or any SSH-accessible host).
//!
//! The relayer container (tools/rly-docker) exposes SSH/SFTP for live management:
//!
//!   update-binary  — SFTP a new `rly` binary to /tmp/rly-new; the supervisor
//!                    loop atomically swaps it and restarts rly.
//!   update-config  — SFTP config.yaml to the relayer config path and signal
//!                    a restart via /tmp/rly-reload.
//!   keys           — SFTP a mnemonic file to /home/relayer/.keys/<chain_id>.
//!   logs           — SSH tail of /tmp/rly.log.
//!   status         — SSH query of the rly debug API + process check.

use crate::with_examples;
use openssh::{KnownHosts, Session, SessionBuilder};
use openssh_sftp_client::Sftp;
use std::{error::Error, path::Path, path::PathBuf};

// ── Clap arg structs ──────────────────────────────────────────────────────────

/// Connection args shared across all subcommands.
#[derive(clap::Args, Debug, Clone)]
pub struct RelayerConnArgs {
    /// SSH host (hostname or IP)
    #[arg(long, env = "RLY_SSH_HOST")]
    pub host: String,

    /// SSH port
    #[arg(long, env = "RLY_SSH_PORT", default_value = "22")]
    pub port: u16,

    /// SSH user
    #[arg(long, env = "RLY_SSH_USER", default_value = "relayer")]
    pub user: String,

    /// Path to SSH private key
    #[arg(long, env = "RLY_SSH_KEY")]
    pub key: PathBuf,
}

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct RelayerArgs {
        #[command(subcommand)]
        pub cmd: RelayerSubcommand,
    }
    => "../../docs/manage.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum RelayerSubcommand {
    /// Show relayer process status and rly API health
    Status {
        #[command(flatten)]
        conn: RelayerConnArgs,
    },
    /// Tail relayer logs (/tmp/rly.log)
    Logs {
        #[command(flatten)]
        conn: RelayerConnArgs,
        /// Number of tail lines (default: 50)
        #[arg(long, default_value = "50")]
        lines: u32,
    },
    /// Hot-swap the rly binary without restarting the container
    UpdateBinary {
        #[command(flatten)]
        conn: RelayerConnArgs,
        /// Path to the new rly binary on this machine
        binary: PathBuf,
    },
    /// Upload a new config.yaml and signal a relayer restart
    UpdateConfig {
        #[command(flatten)]
        conn: RelayerConnArgs,
        /// Path to the new config.yaml on this machine
        config: PathBuf,
    },
    /// Install a relayer key mnemonic into the container's key directory
    Keys {
        #[command(flatten)]
        conn: RelayerConnArgs,
        /// Chain ID (determines filename under /home/relayer/.keys/)
        #[arg(long, env = "RLY_CHAIN_ID")]
        chain_id: String,
        /// Path to a file containing the mnemonic (one line)
        #[arg(long)]
        mnemonic_file: PathBuf,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn cmd_relayer(args: &RelayerArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        RelayerSubcommand::Status { conn } => cmd_relayer_status(conn).await,
        RelayerSubcommand::Logs { conn, lines } => cmd_relayer_logs(conn, *lines).await,
        RelayerSubcommand::UpdateBinary { conn, binary } => {
            cmd_relayer_update_binary(conn, binary).await
        }
        RelayerSubcommand::UpdateConfig { conn, config } => {
            cmd_relayer_update_config(conn, config).await
        }
        RelayerSubcommand::Keys {
            conn,
            chain_id,
            mnemonic_file,
        } => cmd_relayer_keys(conn, chain_id, mnemonic_file).await,
    }
}

// ── SSH helpers ───────────────────────────────────────────────────────────────

async fn connect(conn: &RelayerConnArgs) -> Result<Session, Box<dyn Error>> {
    let dest = format!("ssh://{}@{}:{}", conn.user, conn.host, conn.port);
    let session = SessionBuilder::default()
        .keyfile(&conn.key)
        .known_hosts_check(KnownHosts::Add)
        .connect_mux(&dest)
        .await
        .map_err(|e| format!("SSH connect to {} failed: {}", dest, e))?;
    Ok(session)
}

/// Run a command and return stdout as a String (stderr swallowed).
async fn ssh_output(session: &Session, cmd: &str) -> Result<String, Box<dyn Error>> {
    let out = session.command("sh").arg("-c").arg(cmd).output().await?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn sftp_upload(conn: &RelayerConnArgs, content: &[u8], remote_path: &str) -> Result<(), Box<dyn Error>> {
    let session = connect(conn).await?;
    let sftp = Sftp::from_session(session, Default::default()).await?;
    sftp.options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(Path::new(remote_path))
        .await?
        .write_all(content)
        .await?;
    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

async fn cmd_relayer_status(conn: &RelayerConnArgs) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Relayer Status ===\n");
    tracing::info!("  Host: {}:{} (user: {})", conn.host, conn.port, conn.user);

    let session = connect(conn).await?;

    // Check if rly process is running
    let pid = ssh_output(&session, "pgrep -x rly 2>/dev/null | head -1").await?;
    if pid.is_empty() {
        tracing::info!("  Process: NOT RUNNING");
    } else {
        tracing::info!("  Process: running (PID {})", pid);
    }

    // Last few lines of log
    let tail = ssh_output(&session, "tail -5 /tmp/rly.log 2>/dev/null || echo '(no log)'").await?;
    tracing::info!("\n  Recent log:\n{}", indent(&tail, "    "));

    // Check rly debug API
    let api = ssh_output(
        &session,
        "curl -sf http://localhost:7597/api/v1/chains 2>/dev/null || echo '(API unreachable)'",
    )
    .await?;
    tracing::info!("\n  Debug API chains:\n{}", indent(&api, "    "));

    Ok(())
}

// ── logs ──────────────────────────────────────────────────────────────────────

async fn cmd_relayer_logs(conn: &RelayerConnArgs, lines: u32) -> Result<(), Box<dyn Error>> {
    let session = connect(conn).await?;
    let output = ssh_output(
        &session,
        &format!("tail -{} /tmp/rly.log 2>/dev/null || echo '(no log file)'", lines),
    )
    .await?;
    println!("{}", output);
    Ok(())
}

// ── update-binary ─────────────────────────────────────────────────────────────

async fn cmd_relayer_update_binary(
    conn: &RelayerConnArgs,
    binary: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Relayer: Hot-Swap Binary ===\n");

    let content = std::fs::read(binary)
        .map_err(|e| format!("Cannot read binary {:?}: {}", binary, e))?;
    let size = content.len();

    tracing::info!("  Binary: {:?} ({} bytes)", binary, size);
    tracing::info!("  Uploading to /tmp/rly-new ...");
    sftp_upload(conn, &content, "/tmp/rly-new").await?;

    tracing::info!("  Uploaded. The supervisor will atomically swap the binary and restart rly.");
    tracing::info!("  Run `oline relayer status` in a few seconds to verify.");
    Ok(())
}

// ── update-config ─────────────────────────────────────────────────────────────

async fn cmd_relayer_update_config(
    conn: &RelayerConnArgs,
    config: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Relayer: Update Config ===\n");

    let content = std::fs::read(config)
        .map_err(|e| format!("Cannot read config {:?}: {}", config, e))?;

    tracing::info!("  Config: {:?} ({} bytes)", config, content.len());
    tracing::info!("  Uploading to /home/relayer/.relayer/config/config.yaml ...");
    sftp_upload(conn, &content, "/home/relayer/.relayer/config/config.yaml").await?;

    tracing::info!("  Signalling restart via /tmp/rly-reload ...");
    sftp_upload(conn, b"", "/tmp/rly-reload").await?;

    tracing::info!("  Config updated. Relayer will restart shortly.");
    Ok(())
}

// ── keys ──────────────────────────────────────────────────────────────────────

async fn cmd_relayer_keys(
    conn: &RelayerConnArgs,
    chain_id: &str,
    mnemonic_file: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Relayer: Install Key ===\n");

    let mnemonic = std::fs::read(mnemonic_file)
        .map_err(|e| format!("Cannot read mnemonic file {:?}: {}", mnemonic_file, e))?;
    let remote_path = format!("/home/relayer/.keys/{}", chain_id);

    tracing::info!("  Chain:  {}", chain_id);
    tracing::info!("  Remote: {}", remote_path);
    sftp_upload(conn, &mnemonic, &remote_path).await?;

    tracing::info!("  Key mnemonic installed.");
    tracing::info!("  The relayer will import it on next restart.");
    tracing::info!("  To trigger a restart: `oline relayer update-config --conn ... <config.yaml>`");
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn indent(s: &str, prefix: &str) -> String {
    s.lines()
        .map(|l| format!("{}{}", prefix, l))
        .collect::<Vec<_>>()
        .join("\n")
}

