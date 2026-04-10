//! `oline vpn` — WireGuard VPN provisioning on pfSense.

use crate::{
    cli::chrono_format_timestamp,
    firewall::{FirewallRecord, FirewallStore},
    vpn::{
        keygen::{generate_wg_keypair, wg_client_conf, wg_server_conf},
        pfsense::{
            add_fw_rule, add_peer_hot, check_wg_available, push_client_conf, reload_wg,
            remove_client_conf, remove_peer_hot, wg_status, write_wg_config,
        },
        VpnStore, WgPeer, WgServer,
    },
    with_examples,
};
use std::error::Error;

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct VpnArgs {
        #[command(subcommand)]
        pub cmd: VpnSubcommand,
    }
    => "../../docs/examples/vpn.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum VpnSubcommand {
    /// Bootstrap WireGuard on a pfSense firewall
    Bootstrap {
        /// pfSense label from firewall store (auto-selects if only one)
        #[arg(long)]
        firewall: Option<String>,

        /// VPN subnet address for the server (e.g. "10.0.0.1/24")
        #[arg(long, default_value = "10.99.0.1/24")]
        server_addr: String,

        /// WireGuard UDP listen port
        #[arg(long, default_value_t = 51820)]
        port: u16,

        /// WireGuard interface name
        #[arg(long, default_value = "wg0")]
        iface: String,

        /// WAN endpoint for clients (e.g. "1.2.3.4:51820"). Auto-uses pfSense host if omitted.
        #[arg(long)]
        endpoint: Option<String>,

        /// Skip adding the UDP firewall pass rule on pfSense WAN
        #[arg(long)]
        skip_fw_rule: bool,
    },
    /// Add a WireGuard peer (client device)
    AddPeer {
        /// Peer name (e.g. "laptop", "alice")
        name: String,

        /// pfSense label from firewall store (auto-selects if only one)
        #[arg(long)]
        firewall: Option<String>,

        /// VPN address for this peer (auto-assigned if omitted, e.g. "10.99.0.2/32")
        #[arg(long)]
        peer_addr: Option<String>,

        /// Traffic to route through VPN (default: all traffic)
        #[arg(long, default_value = "0.0.0.0/0")]
        allowed_ips: String,

        /// SSH-push the .conf file to a remote machine (format: [user@]host[:port])
        #[arg(long, value_name = "TARGET")]
        push_to: Option<String>,
    },
    /// Revoke a WireGuard peer
    RevokePeer {
        /// Peer name to revoke
        name: String,

        /// pfSense label from firewall store (auto-selects if only one)
        #[arg(long)]
        firewall: Option<String>,
    },
    /// List all VPN peers
    List {
        /// pfSense label from firewall store (auto-selects if only one)
        #[arg(long)]
        firewall: Option<String>,
    },
    /// Show WireGuard interface status from pfSense
    Status {
        /// pfSense label from firewall store (auto-selects if only one)
        #[arg(long)]
        firewall: Option<String>,
    },
    /// Configure DDNS for the WireGuard endpoint
    Ddns {
        /// DDNS provider (duckdns or cloudflare)
        #[arg(long)]
        provider: String,

        /// Domain / subdomain for DDNS
        #[arg(long)]
        domain: String,

        /// API token for the DDNS provider
        #[arg(long, env = "DDNS_TOKEN", hide_env_values = true)]
        token: String,

        /// pfSense label from firewall store (auto-selects if only one)
        #[arg(long)]
        firewall: Option<String>,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn cmd_vpn(args: &VpnArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        VpnSubcommand::Bootstrap {
            firewall,
            server_addr,
            port,
            iface,
            endpoint,
            skip_fw_rule,
        } => {
            cmd_vpn_bootstrap(
                firewall.as_deref(),
                server_addr,
                *port,
                iface,
                endpoint.as_deref(),
                *skip_fw_rule,
            )
            .await
        }
        VpnSubcommand::AddPeer {
            name,
            firewall,
            peer_addr,
            allowed_ips,
            push_to,
        } => {
            cmd_vpn_add_peer(
                name,
                firewall.as_deref(),
                peer_addr.as_deref(),
                allowed_ips,
                push_to.as_deref(),
            )
            .await
        }
        VpnSubcommand::RevokePeer { name, firewall } => {
            cmd_vpn_revoke_peer(name, firewall.as_deref()).await
        }
        VpnSubcommand::List { firewall } => cmd_vpn_list(firewall.as_deref()),
        VpnSubcommand::Status { firewall } => cmd_vpn_status(firewall.as_deref()).await,
        VpnSubcommand::Ddns {
            provider,
            domain,
            token,
            firewall,
        } => cmd_vpn_ddns(provider, domain, token, firewall.as_deref()).await,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Prompt for store password and resolve a FirewallRecord by label (or auto-select).
fn load_firewall_record(
    label: Option<&str>,
    password: &str,
) -> Result<FirewallRecord, Box<dyn Error>> {
    let fw_store = FirewallStore::open(FirewallStore::default_path(), password);
    let firewalls = fw_store.load()?;
    if firewalls.is_empty() {
        return Err("No firewalls saved. Run `oline firewall bootstrap` first.".into());
    }

    let fw = if let Some(lbl) = label {
        firewalls
            .into_iter()
            .find(|r| r.label == lbl)
            .ok_or_else(|| format!("No firewall with label '{}' found", lbl))?
    } else if firewalls.len() == 1 {
        firewalls.into_iter().next().unwrap()
    } else {
        let labels: Vec<&str> = firewalls.iter().map(|r| r.label.as_str()).collect();
        return Err(format!(
            "Multiple firewalls found ({}). Use --firewall <LABEL>.",
            labels.join(", ")
        )
        .into());
    };

    Ok(fw)
}

fn prompt_password() -> Result<String, Box<dyn Error>> {
    if let Ok(pw) = std::env::var("PFSENSE_PASSWORD") {
        return Ok(pw);
    }
    if std::env::var("OLINE_NON_INTERACTIVE").is_ok() {
        return Err("PFSENSE_PASSWORD required in non-interactive mode".into());
    }
    Ok(rpassword::prompt_password("  Store password: ")?)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── bootstrap ─────────────────────────────────────────────────────────────────

async fn cmd_vpn_bootstrap(
    firewall_label: Option<&str>,
    server_addr: &str,
    listen_port: u16,
    iface: &str,
    endpoint_override: Option<&str>,
    skip_fw_rule: bool,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== WireGuard VPN Bootstrap ===\n");

    let password = prompt_password()?;
    let fw = load_firewall_record(firewall_label, &password)?;
    let key_path = fw.key_path();

    if !key_path.exists() {
        return Err(format!("Firewall SSH key missing: {}", key_path.display()).into());
    }

    tracing::info!("  Firewall: {} ({}@{}:{})", fw.label, fw.user, fw.host, fw.ssh_port);

    // 1. Check WireGuard availability
    tracing::info!("  Checking WireGuard availability...");
    let wg_ver = check_wg_available(&fw, &key_path)?;
    tracing::info!("  WireGuard: {}", wg_ver);

    // 2. Generate server keypair
    tracing::info!("  Generating server X25519 keypair...");
    let (server_priv, server_pub) = generate_wg_keypair();
    tracing::info!("  Server public key: {}", server_pub);

    // 3. Determine WAN endpoint
    let wan_endpoint = if let Some(ep) = endpoint_override {
        Some(ep.to_string())
    } else {
        Some(format!("{}:{}", fw.host, listen_port))
    };

    // 4. Build and write server config (no peers yet)
    let server = WgServer {
        firewall_label: fw.label.clone(),
        interface: iface.to_string(),
        listen_port,
        server_address: server_addr.to_string(),
        private_key: server_priv,
        public_key: server_pub.clone(),
        wan_endpoint: wan_endpoint.clone(),
        peers: vec![],
        created_at: now_secs(),
    };

    tracing::info!("  Writing {}.conf to pfSense...", iface);
    let conf = wg_server_conf(&server);
    write_wg_config(&fw, &key_path, iface, &conf)?;

    // 5. Add UDP firewall pass rule
    if !skip_fw_rule {
        tracing::info!("  Adding UDP pass rule for port {}...", listen_port);
        add_fw_rule(&fw, &key_path, listen_port)?;
        tracing::info!("  Firewall rule added.");
    }

    // 6. Start WireGuard interface
    tracing::info!("  Starting WireGuard interface {}...", iface);
    reload_wg(&fw, &key_path, iface)?;

    // 7. Save to VpnStore
    let vpn_store = VpnStore::open(VpnStore::default_path(), &password);
    vpn_store.update(server)?;
    tracing::info!("  Saved to VPN store: {}", VpnStore::default_path().display());

    tracing::info!("\n  === Bootstrap Complete ===");
    tracing::info!("  Interface:   {}", iface);
    tracing::info!("  Address:     {}", server_addr);
    tracing::info!("  Port:        {}", listen_port);
    tracing::info!("  Public key:  {}", server_pub);
    if let Some(ep) = &wan_endpoint {
        tracing::info!("  Endpoint:    {}", ep);
    }
    tracing::info!("\n  Add a peer:  oline vpn add-peer <name>");

    Ok(())
}

// ── add-peer ──────────────────────────────────────────────────────────────────

async fn cmd_vpn_add_peer(
    peer_name: &str,
    firewall_label: Option<&str>,
    peer_addr_override: Option<&str>,
    allowed_ips: &str,
    push_to: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Add VPN Peer: {} ===\n", peer_name);

    let password = prompt_password()?;
    let fw = load_firewall_record(firewall_label, &password)?;
    let key_path = fw.key_path();

    if !key_path.exists() {
        return Err(format!("Firewall SSH key missing: {}", key_path.display()).into());
    }

    // 1. Load VPN store → find server
    let vpn_store = VpnStore::open(VpnStore::default_path(), &password);
    let mut server = vpn_store
        .find_by_label(&fw.label)?
        .ok_or_else(|| format!("No WireGuard server for firewall '{}'. Run `oline vpn bootstrap` first.", fw.label))?;

    // Check peer name not already taken
    if server.peers.iter().any(|p| p.name == peer_name) {
        return Err(format!("Peer '{}' already exists.", peer_name).into());
    }

    // 2. Assign peer address
    let peer_addr = if let Some(addr) = peer_addr_override {
        addr.to_string()
    } else {
        server.next_peer_address()?
    };

    // 3. Generate peer keypair
    let (peer_priv, peer_pub) = generate_wg_keypair();
    tracing::info!("  Peer address:     {}", peer_addr);
    tracing::info!("  Peer public key:  {}", peer_pub);

    // 4. Hot-add peer to running WireGuard interface
    tracing::info!("  Adding peer to WireGuard interface...");
    add_peer_hot(&fw, &key_path, &server.interface, &peer_pub, &peer_addr)?;

    // 5. Rewrite full wg0.conf with new peer (for persistence across reboots)
    let peer = WgPeer {
        name: peer_name.to_string(),
        private_key: peer_priv.clone(),
        public_key: peer_pub.clone(),
        peer_address: peer_addr.clone(),
        allowed_ips: allowed_ips.to_string(),
        pushed_to: push_to.map(|s| s.to_string()),
        added_at: now_secs(),
    };
    server.peers.push(peer);

    let conf = wg_server_conf(&server);
    write_wg_config(&fw, &key_path, &server.interface, &conf)?;
    tracing::info!("  Updated {}.conf on pfSense.", server.interface);

    // 6. Generate client config
    let wan_endpoint = server
        .wan_endpoint
        .clone()
        .unwrap_or_else(|| format!("{}:{}", fw.host, server.listen_port));

    let client_conf = wg_client_conf(
        &peer_priv,
        &peer_addr,
        &server.public_key,
        &wan_endpoint,
        allowed_ips,
    );

    // 7. Push to remote machine if requested
    if let Some(target) = push_to {
        tracing::info!("  Pushing .conf to {}...", target);
        push_client_conf(target, &server.interface, &client_conf)?;
        tracing::info!("  Config pushed to {}:~/{}.conf", target, server.interface);
    }

    // 8. Save updated server to VpnStore
    vpn_store.update(server.clone())?;
    tracing::info!("  VPN store updated.");

    // 9. Print client config
    tracing::info!("\n  === Client Config for '{}' ===", peer_name);
    tracing::info!("  Save as ~/{}.conf and run: wg-quick up {}", server.interface, server.interface);
    tracing::info!("\n{}", client_conf);

    Ok(())
}

// ── revoke-peer ───────────────────────────────────────────────────────────────

async fn cmd_vpn_revoke_peer(
    peer_name: &str,
    firewall_label: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Revoke VPN Peer: {} ===\n", peer_name);

    let password = prompt_password()?;
    let fw = load_firewall_record(firewall_label, &password)?;
    let key_path = fw.key_path();

    if !key_path.exists() {
        return Err(format!("Firewall SSH key missing: {}", key_path.display()).into());
    }

    let vpn_store = VpnStore::open(VpnStore::default_path(), &password);
    let mut server = vpn_store
        .find_by_label(&fw.label)?
        .ok_or_else(|| format!("No WireGuard server for firewall '{}'.", fw.label))?;

    let peer = server
        .peers
        .iter()
        .find(|p| p.name == peer_name)
        .ok_or_else(|| format!("No peer '{}' found.", peer_name))?
        .clone();

    tracing::info!("  Removing peer from WireGuard interface...");
    remove_peer_hot(&fw, &key_path, &server.interface, &peer.public_key)?;

    // Rewrite config without this peer
    server.peers.retain(|p| p.name != peer_name);
    let conf = wg_server_conf(&server);
    write_wg_config(&fw, &key_path, &server.interface, &conf)?;
    tracing::info!("  Updated {}.conf on pfSense.", server.interface);

    // Remove config from client machine if it was pushed
    if let Some(target) = &peer.pushed_to {
        tracing::info!("  Removing config from {}...", target);
        remove_client_conf(target, &server.interface)?;
    }

    vpn_store.update(server.clone())?;
    tracing::info!("  Peer '{}' revoked.", peer_name);

    Ok(())
}

// ── list ──────────────────────────────────────────────────────────────────────

fn cmd_vpn_list(firewall_label: Option<&str>) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== VPN Peers ===\n");

    let password = prompt_password()?;
    let vpn_store = VpnStore::open(VpnStore::default_path(), &password);
    let servers = vpn_store.load()?;

    if servers.is_empty() {
        tracing::info!("  No VPN servers configured. Run `oline vpn bootstrap` first.");
        return Ok(());
    }

    for server in &servers {
        if let Some(lbl) = firewall_label {
            if server.firewall_label != lbl {
                continue;
            }
        }

        tracing::info!(
            "  Firewall: {}  |  {}  port {}  iface {}",
            server.firewall_label,
            server.server_address,
            server.listen_port,
            server.interface,
        );
        if let Some(ep) = &server.wan_endpoint {
            tracing::info!("  Endpoint: {}", ep);
        }
        tracing::info!("  Peers ({}):", server.peers.len());
        if server.peers.is_empty() {
            tracing::info!("    (none)");
        }
        for peer in &server.peers {
            let push_info = peer
                .pushed_to
                .as_deref()
                .map(|t| format!(" → pushed to {}", t))
                .unwrap_or_default();
            let added = chrono_format_timestamp(peer.added_at);
            tracing::info!(
                "    {:16}  {}  allowed: {}{}  (added: {})",
                peer.name,
                peer.peer_address,
                peer.allowed_ips,
                push_info,
                added,
            );
        }
        tracing::info!("");
    }

    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

async fn cmd_vpn_status(firewall_label: Option<&str>) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== WireGuard Status ===\n");

    let password = prompt_password()?;
    let fw = load_firewall_record(firewall_label, &password)?;
    let key_path = fw.key_path();

    if !key_path.exists() {
        return Err(format!("Firewall SSH key missing: {}", key_path.display()).into());
    }

    let vpn_store = VpnStore::open(VpnStore::default_path(), &password);
    let server = vpn_store
        .find_by_label(&fw.label)?
        .ok_or_else(|| format!("No WireGuard server for firewall '{}'.", fw.label))?;

    let status = wg_status(&fw, &key_path, &server.interface)?;
    tracing::info!("{}", status);

    Ok(())
}

// ── ddns ──────────────────────────────────────────────────────────────────────

async fn cmd_vpn_ddns(
    provider: &str,
    domain: &str,
    token: &str,
    firewall_label: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Configure DDNS for WireGuard Endpoint ===\n");

    let password = prompt_password()?;
    let fw = load_firewall_record(firewall_label, &password)?;
    let key_path = fw.key_path();

    if !key_path.exists() {
        return Err(format!("Firewall SSH key missing: {}", key_path.display()).into());
    }

    let vpn_store = VpnStore::open(VpnStore::default_path(), &password);
    let mut server = vpn_store
        .find_by_label(&fw.label)?
        .ok_or_else(|| format!("No WireGuard server for firewall '{}'.", fw.label))?;

    // Build the DDNS endpoint string
    let ddns_host = match provider {
        "duckdns" => format!("{}.duckdns.org", domain),
        "cloudflare" | _ => domain.to_string(),
    };
    let new_endpoint = format!("{}:{}", ddns_host, server.listen_port);

    tracing::info!("  Provider:     {}", provider);
    tracing::info!("  Domain:       {}", ddns_host);
    tracing::info!("  New endpoint: {}", new_endpoint);

    // Configure pfSense DDNS service via pfSsh.php
    let php_script = build_ddns_php(provider, domain, token, &fw)?;
    crate::vpn::pfsense::ssh_exec_stdin(
        &fw,
        &key_path,
        "/usr/local/sbin/pfSsh.php",
        php_script.as_bytes(),
    )?;
    tracing::info!("  pfSense DDNS service configured.");

    // Update wan_endpoint in VpnStore
    server.wan_endpoint = Some(new_endpoint.clone());
    vpn_store.update(server)?;
    tracing::info!("  VPN store updated with new endpoint: {}", new_endpoint);
    tracing::info!("\n  Note: regenerate peer configs with `oline vpn add-peer` to update endpoint.");

    Ok(())
}

/// Build the pfSsh.php script to configure Dynamic DNS on pfSense.
fn build_ddns_php(
    provider: &str,
    domain: &str,
    token: &str,
    fw: &FirewallRecord,
) -> Result<String, Box<dyn Error>> {
    // Map provider name to pfSense DynDNS type
    let pf_type = match provider {
        "duckdns" => "duckdns",
        "cloudflare" => "cloudflare",
        other => return Err(format!("Unsupported DDNS provider '{}'. Use: duckdns, cloudflare", other).into()),
    };

    // Get WAN interface name from pfSense config (use "wan" as a safe default)
    let _ = fw; // future: could SSH to resolve actual WAN interface name

    Ok(format!(
        r#"parse_config(true);
if (!is_array($config["dyndnses"]["dyndns"])) {{ $config["dyndnses"]["dyndns"] = array(); }}
// Remove existing oline-managed entry for this domain
$config["dyndnses"]["dyndns"] = array_filter(
    $config["dyndnses"]["dyndns"],
    function($e) {{ return !isset($e["descr"]) || $e["descr"] !== "oline: {domain}"; }}
);
$config["dyndnses"]["dyndns"][] = array(
    "enable"    => true,
    "type"      => "{pf_type}",
    "interface" => "wan",
    "host"      => "{domain}",
    "password"  => "{token}",
    "ttl"       => "600",
    "descr"     => "oline: {domain}",
    "wildcard"  => false,
    "verboselog" => false
);
write_config("oline: DDNS {domain}");
exec
exit
"#,
        domain = domain,
        pf_type = pf_type,
        token = token,
    ))
}
