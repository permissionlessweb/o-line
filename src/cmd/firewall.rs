//! `oline firewall` — pfSense SSH key provisioning and management.

use crate::{
    cli::*,
    crypto::{gen_ssh_key, save_ssh_key},
    firewall::{
        pfsense::{
            forward_ssh_key_via_jump, install_ssh_key, install_ssh_key_copy_id, resolve_method,
            revoke_ssh_key_via_jump, ssh_dest, ssh_with_password, verify_key_auth,
            verify_key_auth_via_jump, KeyInstallMethod,
        },
        ClientAccess, ClientStore, ForwardTarget, FirewallRecord, FirewallStore,
    },
    with_examples,
};
use std::{error::Error, fs, io, path::PathBuf};

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct FirewallArgs {
        #[command(subcommand)]
        pub cmd: FirewallSubcommand,
    }
    => "../../docs/examples/firewall.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum FirewallSubcommand {
    /// Install SSH key on a pfSense firewall for passwordless management
    Bootstrap {
        /// pfSense IP or hostname
        #[arg(long, env = "PFSENSE_HOST")]
        host: Option<String>,

        /// SSH port
        #[arg(long, env = "PFSENSE_SSH_PORT", default_value = "22")]
        port: u16,

        /// SSH username
        #[arg(long, env = "PFSENSE_USER", default_value = "admin")]
        user: String,

        /// Path to an existing public key file (skip key generation)
        #[arg(long)]
        pubkey: Option<PathBuf>,

        /// Path to the SSH private key for this firewall.
        /// Overrides the auto-generated key path ($SECRETS_PATH/<label>-ssh-key).
        #[arg(long)]
        key_path: Option<PathBuf>,

        /// Key install method: auto (default), ssh-copy-id, sshpass
        #[arg(long, env = "PFSENSE_METHOD", default_value = "auto")]
        method: String,

        /// Skip key-based auth verification after install
        #[arg(long)]
        skip_verify: bool,

        /// Key is already installed on the firewall — skip password-based
        /// connectivity test and key installation, just save the record.
        /// Requires --pubkey.
        #[arg(long)]
        key_installed: bool,

        /// Label for this firewall in the store
        #[arg(long, default_value = "pfSense")]
        label: String,

        /// Forward the same SSH key to internal servers via pfSense jump host.
        /// Format: [user@]host[:port] (default user: root, default port: 22).
        /// Can be specified multiple times.
        #[arg(long, value_name = "TARGET")]
        forward_to: Vec<String>,
    },
    /// Show saved firewall connections
    List,
    /// Check SSH connectivity to saved firewalls
    Status,
    /// Grant a client SSH access to internal servers via pfSense jump host
    GrantAccess {
        /// Client identifier (e.g. "alice", "ci-bot")
        #[arg(long)]
        name: String,

        /// Path to the client's SSH public key file
        #[arg(long)]
        pubkey: PathBuf,

        /// Target servers to install the key on. Format: [user@]host[:port].
        /// Can be specified multiple times.
        #[arg(long, value_name = "TARGET")]
        target: Vec<String>,

        /// Also install the client key on the pfSense firewall itself
        #[arg(long)]
        include_firewall: bool,

        /// Firewall label to use as jump host (auto-selects if only one exists)
        #[arg(long)]
        firewall: Option<String>,

        /// Path to the jump host SSH private key (overrides stored key path)
        #[arg(long)]
        key_path: Option<PathBuf>,

        /// SSH password for target servers
        #[arg(long, env = "CLIENT_TARGET_PASSWORD", hide_env_values = true)]
        target_password: Option<String>,

        /// Skip post-install key verification
        #[arg(long)]
        skip_verify: bool,
    },
    /// Show all granted client access records
    ListClients,
    /// Revoke a client's SSH access from all their target servers
    RevokeAccess {
        /// Client name to revoke
        #[arg(long)]
        name: String,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn cmd_firewall(args: &FirewallArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        FirewallSubcommand::Bootstrap {
            host,
            port,
            user,
            pubkey,
            key_path,
            method,
            skip_verify,
            key_installed,
            label,
            forward_to,
        } => {
            let method_choice = KeyInstallMethod::parse(method)
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            let targets: Vec<ForwardTarget> = forward_to
                .iter()
                .map(|s| ForwardTarget::parse(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            cmd_firewall_bootstrap(
                host.clone(),
                *port,
                user,
                pubkey.as_deref(),
                key_path.as_deref(),
                method_choice,
                *skip_verify,
                *key_installed,
                label,
                &targets,
            )
            .await
        }
        FirewallSubcommand::List => cmd_firewall_list(),
        FirewallSubcommand::Status => cmd_firewall_status().await,
        FirewallSubcommand::GrantAccess {
            name,
            pubkey,
            target,
            include_firewall,
            firewall,
            key_path,
            target_password,
            skip_verify,
        } => {
            let targets: Vec<ForwardTarget> = target
                .iter()
                .map(|s| ForwardTarget::parse(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            if targets.is_empty() && !include_firewall {
                return Err("At least one --target or --include-firewall is required".into());
            }
            cmd_grant_access(name, pubkey, &targets, *include_firewall, firewall.as_deref(), key_path.as_deref(), target_password.as_deref(), *skip_verify).await
        }
        FirewallSubcommand::ListClients => cmd_list_clients(),
        FirewallSubcommand::RevokeAccess { name } => cmd_revoke_access(name).await,
    }
}

// ── bootstrap ─────────────────────────────────────────────────────────────────

async fn cmd_firewall_bootstrap(
    host_arg: Option<String>,
    port: u16,
    user: &str,
    pubkey_path: Option<&std::path::Path>,
    key_path_override: Option<&std::path::Path>,
    method_choice: Option<KeyInstallMethod>,
    skip_verify: bool,
    key_installed: bool,
    label: &str,
    forward_targets: &[ForwardTarget],
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== pfSense SSH Bootstrap ===\n");

    if key_installed && pubkey_path.is_none() && key_path_override.is_none() {
        return Err("--key-installed requires --pubkey or --key-path to identify the existing key".into());
    }

    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok();

    // 1. Resolve host
    let host = if let Some(h) = host_arg {
        h
    } else if non_interactive {
        return Err("PFSENSE_HOST required in non-interactive mode".into());
    } else {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        use io::BufRead;
        read_input(&mut lines, "pfSense host (IP or hostname)", None)?
    };

    if host.is_empty() {
        return Err("Host cannot be empty".into());
    }

    // 2. Resolve key paths
    let secrets_dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let default_key_name = format!("{}-ssh-key", label.to_lowercase().replace(' ', "-"));

    // --key-path overrides the private key location (and what gets stored as key_name)
    let (key_name, key_path) = if let Some(kp) = key_path_override {
        // Use the path as-is for new keys; canonicalize only if it already exists
        let resolved = fs::canonicalize(kp).unwrap_or_else(|_| kp.to_path_buf());
        let name = resolved.to_str().unwrap_or("").to_string();
        (name, resolved)
    } else {
        let path = PathBuf::from(&secrets_dir).join(&default_key_name);
        (default_key_name.clone(), path)
    };

    let pub_path = if let Some(pk) = pubkey_path {
        pk.to_path_buf()
    } else {
        // Derive .pub path from key_path (works for both default and --key-path)
        PathBuf::from(format!("{}.pub", key_path.display()))
    };

    // Generate or read public key
    let (pubkey_str, pubkey_file) = if let Some(pk_path) = pubkey_path {
        let content = fs::read_to_string(pk_path)
            .map_err(|e| format!("Cannot read pubkey file {:?}: {}", pk_path, e))?;
        tracing::info!("  Using existing pubkey from {:?}", pk_path);
        (content.trim().to_string(), pk_path.to_path_buf())
    } else if key_installed {
        return Err("--key-installed requires --pubkey".into());
    } else {
        let privkey = gen_ssh_key();
        let pubkey = privkey.public_key().to_string();
        save_ssh_key(&privkey, &key_path)?;
        fs::write(&pub_path, &pubkey)
            .map_err(|e| format!("Failed to write pubkey file: {}", e))?;
        tracing::info!("  Generated SSH key → {}", key_path.display());
        (pubkey, pub_path.clone())
    };

    // 3. Get password — for store encryption (always needed), and for SSH if not --key-installed
    let password = if key_installed {
        // Only need a store encryption password, not an SSH password
        if let Ok(pw) = std::env::var("PFSENSE_PASSWORD") {
            pw
        } else if non_interactive {
            return Err("PFSENSE_PASSWORD required in non-interactive mode".into());
        } else {
            rpassword::prompt_password("  Store encryption password: ")?
        }
    } else {
        if let Ok(pw) = std::env::var("PFSENSE_PASSWORD") {
            pw
        } else if non_interactive {
            return Err("PFSENSE_PASSWORD required in non-interactive mode".into());
        } else {
            rpassword::prompt_password(&format!(
                "  SSH password for {}: ",
                ssh_dest(&host, port, user)
            ))?
        }
    };

    if !key_installed {
        // Resolve install method
        let method = resolve_method(method_choice)?;
        tracing::info!("  Method: {}", method);

        // Verify connectivity (uses sshpass for the quick test regardless of method)
        tracing::info!("  Connecting to {} ...", ssh_dest(&host, port, user));
        let output = ssh_with_password(&host, port, user, &password, "uname -a")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("SSH connection failed: {}", stderr.trim()).into());
        }
        let uname = String::from_utf8_lossy(&output.stdout);
        tracing::info!("  Connected: {}", uname.trim());

        // Install pubkey on pfSense
        tracing::info!("  Installing SSH key via {} ...", method);
        tracing::info!("  Pubkey file: {}", pubkey_file.display());
        tracing::info!("  Private key: {}", key_path.display());
        match method {
            KeyInstallMethod::SshCopyId => {
                let pw_for_copy = Some(password.as_str());
                install_ssh_key_copy_id(&host, port, user, pw_for_copy, &pubkey_file)?;
            }
            KeyInstallMethod::Sshpass => {
                install_ssh_key(&host, port, user, &password, &pubkey_str)?;
            }
        }
        tracing::info!("  SSH key installed.");
    } else {
        tracing::info!("  Key already installed — skipping connectivity test and install.");
    }

    // 7. Verify key-based auth
    if !skip_verify {
        let verify_path = if pubkey_path.is_some() {
            let pk = pubkey_path.unwrap();
            let pk_str = pk.to_str().unwrap_or("");
            if pk_str.ends_with(".pub") {
                PathBuf::from(&pk_str[..pk_str.len() - 4])
            } else {
                tracing::info!("  Cannot determine private key path — skipping verification.");
                tracing::info!("  Use `oline firewall status` to verify later.\n");
                save_record(label, &host, port, user, &key_name, &password, &[])?;
                return Ok(());
            }
        } else {
            key_path.clone()
        };

        tracing::info!("  Verifying key-based auth...");
        match verify_key_auth(&host, port, user, &verify_path).await {
            Ok(()) => tracing::info!("  Key-based SSH auth verified."),
            Err(e) => {
                tracing::info!("  Warning: key verification failed: {}", e);
                tracing::info!("  The key may still work — check with `oline firewall status`.");
            }
        }
    }

    // 8. Forward key to internal servers via pfSense jump host
    let mut completed_forwards: Vec<ForwardTarget> = Vec::new();
    if !forward_targets.is_empty() {
        tracing::info!("\n  === Forwarding SSH Key ===");

        // Determine the pfSense private key path for ProxyJump
        let jump_key = if pubkey_path.is_some() {
            let pk = pubkey_path.unwrap();
            let pk_str = pk.to_str().unwrap_or("");
            if pk_str.ends_with(".pub") {
                PathBuf::from(&pk_str[..pk_str.len() - 4])
            } else {
                key_path.clone()
            }
        } else {
            key_path.clone()
        };

        // Get target password
        let target_password =
            if let Ok(pw) = std::env::var("FORWARD_TARGET_PASSWORD") {
                pw
            } else if non_interactive {
                return Err(
                    "FORWARD_TARGET_PASSWORD required in non-interactive mode with --forward-to"
                        .into(),
                );
            } else {
                rpassword::prompt_password("  SSH password for forward targets: ")?
            };

        for target in forward_targets {
            tracing::info!(
                "  Forwarding key to {} via {} ...",
                target,
                ssh_dest(&host, port, user)
            );

            forward_ssh_key_via_jump(
                &host,
                port,
                user,
                &jump_key,
                &target.host,
                target.port,
                &target.user,
                &target_password,
                &pubkey_str,
            )?;
            tracing::info!("  Key installed on {}.", target);

            // Verify key-based auth via jump
            if !skip_verify {
                tracing::info!("  Verifying key-based auth to {} via jump...", target);
                match verify_key_auth_via_jump(
                    &host,
                    port,
                    user,
                    &jump_key,
                    &target.host,
                    target.port,
                    &target.user,
                    &jump_key,
                )
                .await
                {
                    Ok(()) => tracing::info!("  Key-based auth to {} verified.", target),
                    Err(e) => {
                        tracing::info!(
                            "  Warning: verification to {} failed: {}",
                            target,
                            e
                        );
                    }
                }
            }

            completed_forwards.push(target.clone());
        }
    }

    // 9. Save record to encrypted store
    save_record(
        label,
        &host,
        port,
        user,
        &key_name,
        &password,
        &completed_forwards,
    )?;

    // 10. Summary
    tracing::info!("\n  === Bootstrap Complete ===");
    tracing::info!("  Host:     {}:{}", host, port);
    tracing::info!("  User:     {}", user);
    if key_installed {
        tracing::info!("  Mode:     key-installed (skipped install)");
    }
    tracing::info!("  Key:      {}", key_path.display());
    if !completed_forwards.is_empty() {
        tracing::info!(
            "  Forwards: {}",
            completed_forwards
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    tracing::info!("  Store:    {}", FirewallStore::default_path().display());
    tracing::info!(
        "\n  Test:     ssh -i {} -p {} {}@{} '/bin/sh -c \"echo ok\"'",
        key_path.display(),
        port,
        user,
        host
    );

    Ok(())
}

fn save_record(
    label: &str,
    host: &str,
    port: u16,
    user: &str,
    key_name: &str,
    password: &str,
    forward_targets: &[ForwardTarget],
) -> Result<(), Box<dyn Error>> {
    let store = FirewallStore::open(FirewallStore::default_path(), password);
    let mut record = FirewallRecord::new(label, host, port, user, key_name);
    record.forward_targets = forward_targets.to_vec();
    store.add(record)?;
    tracing::info!("  Saved to firewall store.");
    Ok(())
}

// ── list ──────────────────────────────────────────────────────────────────────

fn cmd_firewall_list() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Saved Firewalls ===\n");

    let password = rpassword::prompt_password("  Store password: ")?;
    let store = FirewallStore::open(FirewallStore::default_path(), &password);
    let records = store.load()?;

    if records.is_empty() {
        tracing::info!("  No firewalls saved. Run `oline firewall bootstrap` first.");
        return Ok(());
    }

    for (i, r) in records.iter().enumerate() {
        tracing::info!(
            "  [{}] {} — {}@{}:{} (key: {})",
            i + 1,
            r.label,
            r.user,
            r.host,
            r.ssh_port,
            r.key_name
        );
        if !r.forward_targets.is_empty() {
            let fwd: Vec<String> = r.forward_targets.iter().map(|t| t.to_string()).collect();
            tracing::info!("      Forwards: {}", fwd.join(", "));
        }
        let ts = chrono_format_timestamp(r.added_at);
        tracing::info!("      Added: {}", ts);
    }

    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

async fn cmd_firewall_status() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Firewall Status ===\n");

    let password = rpassword::prompt_password("  Store password: ")?;
    let store = FirewallStore::open(FirewallStore::default_path(), &password);
    let records = store.load()?;

    if records.is_empty() {
        tracing::info!("  No firewalls saved. Run `oline firewall bootstrap` first.");
        return Ok(());
    }

    for r in &records {
        let key_path = r.key_path();
        let dest = ssh_dest(&r.host, r.ssh_port, &r.user);

        let status = if !key_path.exists() {
            format!("ERROR: key file missing ({})", key_path.display())
        } else {
            match verify_key_auth(&r.host, r.ssh_port, &r.user, &key_path).await {
                Ok(()) => "OK — key auth works".to_string(),
                Err(e) => format!("FAIL: {}", e),
            }
        };

        tracing::info!("  {} ({}) → {}", r.label, dest, status);
    }

    Ok(())
}

// ── grant-access ─────────────────────────────────────────────────────────────

async fn cmd_grant_access(
    name: &str,
    pubkey_path: &std::path::Path,
    targets: &[ForwardTarget],
    include_firewall: bool,
    firewall_label: Option<&str>,
    key_path_override: Option<&std::path::Path>,
    target_password_arg: Option<&str>,
    skip_verify: bool,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Grant Client Access ===\n");

    // 1. Read client pubkey
    let pubkey_str = fs::read_to_string(pubkey_path)
        .map_err(|e| format!("Cannot read pubkey file {:?}: {}", pubkey_path, e))?;
    let pubkey_str = pubkey_str.trim().to_string();
    tracing::info!("  Client: {}", name);
    tracing::info!(
        "  Pubkey: {}...{}",
        &pubkey_str[..20.min(pubkey_str.len())],
        &pubkey_str[pubkey_str.len().saturating_sub(10)..]
    );

    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok();

    // 2. Prompt for store password
    let password = if let Ok(pw) = std::env::var("PFSENSE_PASSWORD") {
        pw
    } else if non_interactive {
        return Err("PFSENSE_PASSWORD required in non-interactive mode".into());
    } else {
        rpassword::prompt_password("  Store password: ")?
    };

    // 3. Load firewall store → resolve jump host
    let fw_store = FirewallStore::open(FirewallStore::default_path(), &password);
    let firewalls = fw_store.load()?;
    if firewalls.is_empty() {
        return Err("No firewalls saved. Run `oline firewall bootstrap` first.".into());
    }

    let fw = if let Some(label) = firewall_label {
        firewalls
            .iter()
            .find(|r| r.label == label)
            .ok_or_else(|| format!("No firewall with label '{}' found", label))?
    } else if firewalls.len() == 1 {
        &firewalls[0]
    } else {
        let labels: Vec<&str> = firewalls.iter().map(|r| r.label.as_str()).collect();
        return Err(format!(
            "Multiple firewalls found ({}). Use --firewall <LABEL> to choose.",
            labels.join(", ")
        )
        .into());
    };

    tracing::info!(
        "  Firewall: {} ({})",
        fw.label,
        ssh_dest(&fw.host, fw.ssh_port, &fw.user)
    );

    let jump_key = if let Some(kp) = key_path_override {
        kp.to_path_buf()
    } else {
        fw.key_path()
    };
    if !jump_key.exists() {
        return Err(format!("Jump host key missing: {}", jump_key.display()).into());
    }

    let mut completed: Vec<ForwardTarget> = Vec::new();

    // 4. Install client key on pfSense itself (direct SSH with oline's key)
    if include_firewall {
        tracing::info!(
            "  Installing client key on firewall {} ...",
            ssh_dest(&fw.host, fw.ssh_port, &fw.user)
        );

        use crate::firewall::pfsense::build_install_key_command;
        let install_cmd = build_install_key_command(&pubkey_str);
        let output = std::process::Command::new("ssh")
            .args([
                "-i",
                jump_key.to_str().unwrap_or(""),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                &fw.ssh_port.to_string(),
                &format!("{}@{}", fw.user, fw.host),
                &format!("/bin/sh -c '{}'", install_cmd.replace('\'', "'\\''")),
            ])
            .output()
            .map_err(|e| format!("Failed to SSH to firewall: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "Failed to install client key on firewall: {}",
                stderr.trim()
            )
            .into());
        }
        tracing::info!("  Client key installed on firewall.");

        completed.push(ForwardTarget {
            host: fw.host.clone(),
            port: fw.ssh_port,
            user: fw.user.clone(),
        });
    }

    // 5. Install client's pubkey on each target via jump host
    if !targets.is_empty() {
        // Get target password (only needed when there are internal targets)
        let target_password = if let Some(pw) = target_password_arg {
            pw.to_string()
        } else if let Ok(pw) = std::env::var("CLIENT_TARGET_PASSWORD") {
            pw
        } else if non_interactive {
            return Err("CLIENT_TARGET_PASSWORD required in non-interactive mode".into());
        } else {
            rpassword::prompt_password("  SSH password for target servers: ")?
        };

        for target in targets {
            tracing::info!(
                "  Installing key on {} via {} ...",
                target,
                ssh_dest(&fw.host, fw.ssh_port, &fw.user)
            );

            forward_ssh_key_via_jump(
                &fw.host,
                fw.ssh_port,
                &fw.user,
                &jump_key,
                &target.host,
                target.port,
                &target.user,
                &target_password,
                &pubkey_str,
            )?;
            tracing::info!("  Key installed on {}.", target);

            if !skip_verify {
                tracing::info!("  Verifying key auth to {} via jump...", target);
                match verify_key_auth_via_jump(
                    &fw.host,
                    fw.ssh_port,
                    &fw.user,
                    &jump_key,
                    &target.host,
                    target.port,
                    &target.user,
                    &jump_key,
                )
                .await
                {
                    Ok(()) => tracing::info!("  Verified."),
                    Err(e) => tracing::info!("  Warning: verification failed: {}", e),
                }
            }

            completed.push(target.clone());
        }
    }

    // 6. Save to client store (merge targets if name already exists)
    let client_store = ClientStore::open(ClientStore::default_path(), &password);
    if let Some(mut existing) = client_store.find_by_name(name)? {
        client_store.remove_by_name(name)?;
        for t in &completed {
            let already = existing
                .targets
                .iter()
                .any(|e| e.host == t.host && e.port == t.port && e.user == t.user);
            if !already {
                existing.targets.push(t.clone());
            }
        }
        client_store.add(existing)?;
        tracing::info!("  Updated existing client record '{}'.", name);
    } else {
        let record = ClientAccess {
            name: name.to_string(),
            pubkey: pubkey_str,
            firewall_label: fw.label.clone(),
            targets: completed.clone(),
            granted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        client_store.add(record)?;
        tracing::info!("  Saved new client record '{}'.", name);
    }

    tracing::info!("\n  === Grant Complete ===");
    tracing::info!(
        "  Targets: {}",
        completed
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(())
}

// ── list-clients ─────────────────────────────────────────────────────────────

fn cmd_list_clients() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Client Access Records ===\n");

    let password = rpassword::prompt_password("  Store password: ")?;
    let store = ClientStore::open(ClientStore::default_path(), &password);
    let records = store.load()?;

    if records.is_empty() {
        tracing::info!("  No client access records. Use `oline firewall grant-access` to add one.");
        return Ok(());
    }

    for (i, r) in records.iter().enumerate() {
        tracing::info!("  [{}] {}", i + 1, r.name);
        tracing::info!("      Firewall: {}", r.firewall_label);
        let targets: Vec<String> = r.targets.iter().map(|t| t.to_string()).collect();
        tracing::info!("      Targets:  {}", targets.join(", "));
        tracing::info!(
            "      Pubkey:   {}...",
            &r.pubkey[..40.min(r.pubkey.len())]
        );
        let ts = chrono_format_timestamp(r.granted_at);
        tracing::info!("      Granted:  {}", ts);
    }

    Ok(())
}

// ── revoke-access ────────────────────────────────────────────────────────────

async fn cmd_revoke_access(name: &str) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Revoke Client Access ===\n");

    let password = rpassword::prompt_password("  Store password: ")?;

    // 1. Find client record
    let client_store = ClientStore::open(ClientStore::default_path(), &password);
    let client = client_store
        .find_by_name(name)?
        .ok_or_else(|| format!("No client record found for '{}'", name))?;

    let key_data = client
        .key_data()
        .ok_or_else(|| format!("Cannot extract key data from pubkey for '{}'", name))?
        .to_string();

    // 2. Find the firewall used as jump host
    let fw_store = FirewallStore::open(FirewallStore::default_path(), &password);
    let firewalls = fw_store.load()?;
    let fw = firewalls
        .iter()
        .find(|r| r.label == client.firewall_label)
        .ok_or_else(|| {
            format!(
                "Firewall '{}' not found in store (needed as jump host)",
                client.firewall_label
            )
        })?;

    let jump_key = fw.key_path();
    if !jump_key.exists() {
        return Err(format!("Jump host key missing: {}", jump_key.display()).into());
    }

    tracing::info!("  Client: {}", name);
    tracing::info!(
        "  Jump host: {} ({})",
        fw.label,
        ssh_dest(&fw.host, fw.ssh_port, &fw.user)
    );

    // 3. Remove key from each target
    let mut failures: Vec<String> = Vec::new();
    for target in &client.targets {
        tracing::info!("  Revoking key from {} ...", target);
        match revoke_ssh_key_via_jump(
            &fw.host,
            fw.ssh_port,
            &fw.user,
            &jump_key,
            &target.host,
            target.port,
            &target.user,
            &key_data,
        ) {
            Ok(()) => tracing::info!("  Revoked from {}.", target),
            Err(e) => {
                tracing::info!("  Warning: failed to revoke from {}: {}", target, e);
                failures.push(target.to_string());
            }
        }
    }

    // 4. Remove record from store (even on partial failure)
    client_store.remove_by_name(name)?;
    tracing::info!("  Removed client record '{}'.", name);

    if !failures.is_empty() {
        tracing::info!(
            "\n  Warning: key removal failed on: {}",
            failures.join(", ")
        );
        tracing::info!(
            "  The client record has been removed, but the key may still be present on those servers."
        );
    }

    tracing::info!("\n  === Revocation Complete ===");
    Ok(())
}
