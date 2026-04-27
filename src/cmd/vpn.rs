//! `oline vpn` — Headscale tailnet management via gRPC.
//!
//! Full lifecycle management of a self-hosted Headscale VPN:
//! - Deploy control plane on Akash, extract + encrypt credentials
//! - Manage users, nodes, keys, policies via typed gRPC client
//! - Register devices, check health, rotate keys
//!
//! Credentials are encrypted at rest with OLINE_PASSWORD.
//! Keys are NEVER printed to terminal or logs.

use crate::with_examples;
use headscale_proto::headscale::v1::{
    headscale_service_client::HeadscaleServiceClient,
    *,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct VpnArgs {
        #[command(subcommand)]
        pub cmd: VpnSubcommand,

        /// Headscale server label (uses default from store if omitted)
        #[arg(long, global = true)]
        pub server: Option<String>,

        /// Override Headscale gRPC endpoint (e.g. https://admin.terp.network:443)
        #[arg(long, global = true)]
        pub endpoint: Option<String>,
    }
    => "../../docs/examples/vpn.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum VpnSubcommand {
    /// Extract credentials from deployment logs and store encrypted
    Setup {
        /// DSEQ of the Headscale deployment
        #[arg(long)]
        dseq: u64,

        /// Label for this Headscale server (default: "default")
        #[arg(long, default_value = "default")]
        label: String,

        /// Control plane URL (e.g. https://admin.terp.network)
        #[arg(long)]
        url: String,

        /// gRPC endpoint (e.g. http://provider.host:30629). If omitted, derived from --url.
        #[arg(long)]
        grpc: Option<String>,

        /// API key (skips log extraction if provided)
        #[arg(long)]
        api_key: Option<String>,

        /// Preauth key (skips log extraction if provided)
        #[arg(long)]
        preauth_key: Option<String>,
    },

    /// Register this device with the tailnet
    Register {
        /// Device hostname (defaults to system hostname)
        #[arg(long)]
        hostname: Option<String>,
    },

    /// Check Headscale server health
    Health,

    /// Manage tailnet nodes
    Nodes {
        #[command(subcommand)]
        cmd: NodesSubcommand,
    },

    /// Manage tailnet users
    Users {
        #[command(subcommand)]
        cmd: UsersSubcommand,
    },

    /// Manage preauth and API keys
    Keys {
        #[command(subcommand)]
        cmd: KeysSubcommand,
    },

    /// Manage ACL policy
    Policy {
        #[command(subcommand)]
        cmd: PolicySubcommand,
    },

    /// Install Tailscale on pfSense and register with Headscale
    PfsenseSetup {
        /// pfSense SSH host (e.g. 192.168.1.1)
        #[arg(long)]
        host: String,

        /// SSH key file authorized on pfSense
        #[arg(long)]
        ssh_key: String,

        /// SSH user (default: admin)
        ssh_user: String,

        /// SSH port (default: 22)
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,

        /// Subnets to advertise (default: 192.168.1.0/24)
        #[arg(long, default_value = "192.168.1.0/24")]
        routes: String,

        /// Hostname to register as (default: pfsense)
        #[arg(long, default_value = "pfsense")]
        hostname: String,
    },

    /// Show stored server configurations
    Servers,
}

#[derive(clap::Subcommand, Debug)]
pub enum NodesSubcommand {
    /// List all nodes
    List { #[arg(long)] user: Option<String> },
    /// Get node details
    Get { node_id: u64 },
    /// Delete a node
    Delete { node_id: u64 },
    /// Expire a node
    Expire { node_id: u64 },
    /// Rename a node
    Rename { node_id: u64, new_name: String },
    /// Set tags on a node
    Tags { node_id: u64, #[arg(num_args=1..)] tags: Vec<String> },
    /// Approve routes for a node
    Routes { node_id: u64, #[arg(num_args=1..)] routes: Vec<String> },
    /// Register a node by its machine key (`nodekey:...`). Mirrors the
    /// native `headscale nodes register --user USERNAME --key KEY` flag
    /// syntax so docs/examples transliterate 1:1.
    ///
    /// Typical mobile workflow: in the Tailscale iOS/Android app, set a
    /// custom control plane URL. The app shows a nodekey during login —
    /// paste it here.
    Register {
        /// Headscale username (not numeric user ID — e.g. "admin").
        #[arg(long)]
        user: String,
        /// Node key. Accepts both `nodekey:<hex>` and bare `<hex>` forms.
        #[arg(long)]
        key: String,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum UsersSubcommand {
    /// List all users
    List,
    /// Create a user
    Create { name: String },
    /// Delete a user
    Delete { id: u64 },
    /// Rename a user
    Rename { old_id: u64, new_name: String },
}

#[derive(clap::Subcommand, Debug)]
pub enum KeysSubcommand {
    /// List preauth keys
    ListPreauth,
    /// Create a new preauth key (stored encrypted, not printed)
    CreatePreauth {
        #[arg(long, default_value_t = 0)]
        user_id: u64,
        #[arg(long)]
        reusable: bool,
    },
    /// List API keys
    ListApi,
    /// Rotate: create new API key + preauth key, update store
    Rotate,
}

#[derive(clap::Subcommand, Debug)]
pub enum PolicySubcommand {
    /// Show current policy
    Show,
    /// Set policy from JSON file
    Set { file: String },
}

// ── Credential store ──────────────────────────────────────────────────────────

/// A single Headscale server configuration, encrypted at rest.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeadscaleServer {
    pub label: String,
    pub control_url: String,
    pub grpc_endpoint: String,
    pub api_key: String,
    pub preauth_key: String,
    pub dseq: u64,
    pub protected: bool,
}

/// Collection of Headscale server configs.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HeadscaleStore {
    pub servers: Vec<HeadscaleServer>,
    pub default_label: String,
}

const STORE_FILE: &str = "headscale.enc";

impl HeadscaleStore {
    pub fn load(password: &str) -> Result<Self, Box<dyn Error>> {
        let path = store_path();
        let encrypted = std::fs::read_to_string(&path)
            .map_err(|_| "No Headscale config found. Run `oline vpn setup` first.")?;
        let json = crate::crypto::decrypt_mnemonic(&encrypted, password)?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn save(&self, password: &str) -> Result<(), Box<dyn Error>> {
        let path = store_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(self)?;
        let encrypted = crate::crypto::encrypt_mnemonic(&json, password)?;
        std::fs::write(&path, encrypted)?;
        Ok(())
    }

    /// Load store without prompting — uses OLINE_PASSWORD env var. Returns Err silently if unavailable.
    pub fn load_optional() -> Result<Self, Box<dyn Error>> {
        let password = std::env::var("OLINE_PASSWORD")
            .map_err(|_| "OLINE_PASSWORD not set")?;
        Self::load(&password)
    }

    pub fn get(&self, label: Option<&str>) -> Result<&HeadscaleServer, Box<dyn Error>> {
        let target = label.unwrap_or(&self.default_label);
        self.servers.iter()
            .find(|s| s.label == target)
            .ok_or_else(|| format!("No Headscale server with label '{}'. Available: {}",
                target,
                self.servers.iter().map(|s| s.label.as_str()).collect::<Vec<_>>().join(", ")
            ).into())
    }

    pub fn upsert(&mut self, server: HeadscaleServer) {
        if let Some(existing) = self.servers.iter_mut().find(|s| s.label == server.label) {
            *existing = server;
        } else {
            self.servers.push(server);
        }
    }
}

fn store_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| ".".into())
        .join(".oline")
        .join(STORE_FILE)
}

// ── gRPC client builder ───────────────────────────────────────────────────────

/// Build an authenticated gRPC client to the Headscale server.
async fn build_client(
    server: &HeadscaleServer,
) -> Result<HeadscaleServiceClient<tonic::service::interceptor::InterceptedService<Channel, impl FnMut(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> + Clone>>, Box<dyn Error>> {
    let channel = Channel::from_shared(server.grpc_endpoint.clone())?
        .connect()
        .await
        .map_err(|e| format!("gRPC connect to {}: {}", server.grpc_endpoint, e))?;

    let api_key = server.api_key.clone();
    let client = HeadscaleServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
        let token: MetadataValue<_> = format!("Bearer {}", api_key)
            .parse()
            .map_err(|_| tonic::Status::internal("invalid api key"))?;
        req.metadata_mut().insert("authorization", token);
        Ok(req)
    });

    Ok(client)
}

// ── Command handlers ──────────────────────────────────────────────────────────

pub async fn cmd_vpn(args: &VpnArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        VpnSubcommand::Setup { dseq, label, url, grpc, api_key, preauth_key } => {
            cmd_vpn_setup(*dseq, label, url, grpc.as_deref(), api_key.as_deref(), preauth_key.as_deref()).await
        }
        VpnSubcommand::Register { hostname } => {
            cmd_vpn_register(&args, hostname.as_deref()).await
        }
        VpnSubcommand::Health => cmd_vpn_health(&args).await,
        VpnSubcommand::Nodes { cmd } => cmd_vpn_nodes(&args, cmd).await,
        VpnSubcommand::Users { cmd } => cmd_vpn_users(&args, cmd).await,
        VpnSubcommand::Keys { cmd } => cmd_vpn_keys(&args, cmd).await,
        VpnSubcommand::Policy { cmd } => cmd_vpn_policy(&args, cmd).await,
        VpnSubcommand::PfsenseSetup { host, ssh_key, ssh_user, ssh_port, routes, hostname } => {
            cmd_vpn_pfsense_setup(&args, host, ssh_key, ssh_user, *ssh_port, routes, hostname).await
        }
        VpnSubcommand::Servers => cmd_vpn_servers().await,
    }
}

fn get_password() -> Result<String, Box<dyn Error>> {
    std::env::var("OLINE_PASSWORD")
        .or_else(|_| rpassword::prompt_password("Enter OLINE_PASSWORD: ").map_err(|e| e.into()))
        .map_err(|e: Box<dyn Error>| format!("Need OLINE_PASSWORD: {}", e).into())
}

async fn resolve_server(args: &VpnArgs) -> Result<(HeadscaleServer, String), Box<dyn Error>> {
    let password = get_password()?;
    let store = HeadscaleStore::load(&password)?;
    let label = args.server.as_deref();

    let mut server = store.get(label)?.clone();

    // Allow endpoint override
    if let Some(ref ep) = args.endpoint {
        server.grpc_endpoint = ep.clone();
    }

    Ok((server, password))
}

// ── Setup ─────────────────────────────────────────────────────────────────────

async fn cmd_vpn_setup(dseq: u64, label: &str, url: &str, grpc_override: Option<&str>, api_key_override: Option<&str>, preauth_key_override: Option<&str>) -> Result<(), Box<dyn Error>> {
    let password = get_password()?;

    let (api_key, preauth_key) = match (api_key_override, preauth_key_override) {
        (Some(ak), Some(pk)) => (ak.to_string(), pk.to_string()),
        _ => {
            tracing::info!("Fetching logs for DSEQ {}...", dseq);
            let log_text = fetch_deployment_logs(dseq).await?;
            let ak = api_key_override.map(|s| s.to_string())
                .or_else(|| extract_line_after(&log_text, "=== API key for remote management ==="))
                .or_else(|| extract_line_after(&log_text, "API key:"))
                .ok_or("Could not find API key. Provide --api-key or ensure logs contain it.")?;
            let pk = preauth_key_override.map(|s| s.to_string())
                .or_else(|| extract_line_after(&log_text, "=== Creating preauth key (reusable, 10yr expiry) ==="))
                .or_else(|| extract_line_after(&log_text, "preauth key:"))
                .ok_or("Could not find preauth key. Provide --preauth-key or ensure logs contain it.")?;
            (ak, pk)
        }
    };

    let grpc_endpoint = match grpc_override {
        Some(ep) => ep.to_string(),
        None => if url.starts_with("https://") {
            format!("{}:443", url)
        } else {
            url.to_string()
        },
    };

    let server = HeadscaleServer {
        label: label.to_string(),
        control_url: url.to_string(),
        grpc_endpoint,
        api_key: api_key.trim().replace(|c: char| !c.is_ascii_graphic(), "").to_string(),
        preauth_key: preauth_key.trim().replace(|c: char| !c.is_ascii_graphic(), "").to_string(),
        dseq,
        protected: true, // Headscale deployments are always protected
    };

    let mut store = HeadscaleStore::load(&password).unwrap_or_default();
    store.upsert(server);
    if store.default_label.is_empty() {
        store.default_label = label.to_string();
    }
    store.save(&password)?;

    tracing::info!("Headscale server '{}' configured and encrypted", label);
    tracing::info!("  Control URL: {}", url);
    tracing::info!("  DSEQ:        {} (protected)", dseq);
    tracing::info!("  Credentials: [stored in ~/.oline/headscale.enc]");

    Ok(())
}

// ── Register ──────────────────────────────────────────────────────────────────

async fn cmd_vpn_register(args: &VpnArgs, hostname: Option<&str>) -> Result<(), Box<dyn Error>> {
    let (server, _password) = resolve_server(args).await?;

    let host = hostname
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            std::process::Command::new("hostname").output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".into())
        });

    tracing::info!("Registering '{}' with {}", host, server.control_url);

    let status = std::process::Command::new("tailscale")
        .args([
            "up",
            "--login-server", &server.control_url,
            "--authkey", &server.preauth_key,
            "--hostname", &host,
        ])
        .status()
        .map_err(|e| format!("tailscale not found or failed: {}", e))?;

    if status.success() {
        tracing::info!("Device '{}' registered successfully", host);
    } else {
        return Err(format!("tailscale up exited with {}", status).into());
    }

    Ok(())
}

// ── Health ────────────────────────────────────────────────────────────────────

async fn cmd_vpn_health(args: &VpnArgs) -> Result<(), Box<dyn Error>> {
    let (server, _) = resolve_server(args).await?;
    let mut client = build_client(&server).await?;

    let resp = client.health(HealthRequest {}).await?;
    let h = resp.into_inner();

    tracing::info!("Headscale health: database={}", if h.database_connectivity { "ok" } else { "FAIL" });
    Ok(())
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

async fn cmd_vpn_nodes(args: &VpnArgs, cmd: &NodesSubcommand) -> Result<(), Box<dyn Error>> {
    let (server, _) = resolve_server(args).await?;
    let mut client = build_client(&server).await?;

    match cmd {
        NodesSubcommand::List { user } => {
            let resp = client.list_nodes(ListNodesRequest {
                user: user.clone().unwrap_or_default(),
            }).await?;
            let nodes = resp.into_inner().nodes;
            tracing::info!("{} node(s):", nodes.len());
            for n in &nodes {
                let status = if n.online { "online" } else { "offline" };
                let ips = n.ip_addresses.join(", ");
                tracing::info!("  [{}] {} ({}) — {} — {}", n.id, n.given_name, n.name, ips, status);
            }
        }
        NodesSubcommand::Get { node_id } => {
            let resp = client.get_node(GetNodeRequest { node_id: *node_id }).await?;
            if let Some(n) = resp.into_inner().node {
                println!("{}", serde_json::to_string_pretty(&n)?);
            }
        }
        NodesSubcommand::Delete { node_id } => {
            client.delete_node(DeleteNodeRequest { node_id: *node_id }).await?;
            tracing::info!("Node {} deleted", node_id);
        }
        NodesSubcommand::Expire { node_id } => {
            client.expire_node(ExpireNodeRequest {
                node_id: *node_id,
                expiry: None,
                disable_expiry: false,
            }).await?;
            tracing::info!("Node {} expired", node_id);
        }
        NodesSubcommand::Rename { node_id, new_name } => {
            client.rename_node(RenameNodeRequest {
                node_id: *node_id,
                new_name: new_name.clone(),
            }).await?;
            tracing::info!("Node {} renamed to {}", node_id, new_name);
        }
        NodesSubcommand::Tags { node_id, tags } => {
            client.set_tags(SetTagsRequest {
                node_id: *node_id,
                tags: tags.clone(),
            }).await?;
            tracing::info!("Tags set on node {}", node_id);
        }
        NodesSubcommand::Routes { node_id, routes } => {
            client.set_approved_routes(SetApprovedRoutesRequest {
                node_id: *node_id,
                routes: routes.clone(),
            }).await?;
            tracing::info!("Routes approved on node {}", node_id);
        }
        NodesSubcommand::Register { user, key } => {
            // Pass the key through unmodified. Headscale accepts several
            // token shapes across versions (nodekey:<hex>, bare hex, and
            // newer opaque formats); the server is the source of truth.
            let resp = client.register_node(RegisterNodeRequest {
                user: user.clone(),
                key: key.clone(),
            }).await?;
            if let Some(n) = resp.into_inner().node {
                tracing::info!(
                    "Registered node {} ({}) — id={} ips=[{}]",
                    n.given_name,
                    n.name,
                    n.id,
                    n.ip_addresses.join(", "),
                );
            } else {
                tracing::warn!("register_node returned no node payload");
            }
        }
    }
    Ok(())
}

// ── Users ─────────────────────────────────────────────────────────────────────

async fn cmd_vpn_users(args: &VpnArgs, cmd: &UsersSubcommand) -> Result<(), Box<dyn Error>> {
    let (server, _) = resolve_server(args).await?;
    let mut client = build_client(&server).await?;

    match cmd {
        UsersSubcommand::List => {
            let resp = client.list_users(ListUsersRequest { id: 0, name: String::new(), email: String::new() }).await?;
            for u in resp.into_inner().users {
                tracing::info!("  {} (id: {})", u.name, u.id);
            }
        }
        UsersSubcommand::Create { name } => {
            client.create_user(CreateUserRequest { name: name.clone(), display_name: String::new(), email: String::new(), picture_url: String::new() }).await?;
            tracing::info!("User '{}' created", name);
        }
        UsersSubcommand::Delete { id } => {
            client.delete_user(DeleteUserRequest { id: *id }).await?;
            tracing::info!("User {} deleted", id);
        }
        UsersSubcommand::Rename { old_id, new_name } => {
            client.rename_user(RenameUserRequest {
                old_id: *old_id,
                new_name: new_name.clone(),
            }).await?;
            tracing::info!("User {} renamed to '{}'", old_id, new_name);
        }
    }
    Ok(())
}

// ── Keys ──────────────────────────────────────────────────────────────────────

async fn cmd_vpn_keys(args: &VpnArgs, cmd: &KeysSubcommand) -> Result<(), Box<dyn Error>> {
    let (server, password) = resolve_server(args).await?;
    let mut client = build_client(&server).await?;

    match cmd {
        KeysSubcommand::ListPreauth { .. } => {
            let resp = client.list_pre_auth_keys(ListPreAuthKeysRequest {}).await?;
            for k in resp.into_inner().pre_auth_keys {
                let reusable = if k.reusable { "reusable" } else { "single-use" };
                let used = if k.used { ", used" } else { "" };
                let user_name = k.user.as_ref().map(|u| u.name.as_str()).unwrap_or("?"); tracing::info!("  [{}] {} ({}{})", k.id, reusable, user_name, used);
            }
        }
        KeysSubcommand::CreatePreauth { user_id, reusable } => {
            let resp = client.create_pre_auth_key(CreatePreAuthKeyRequest {
                user: *user_id,
                reusable: *reusable,
                ephemeral: false,
                expiration: None,
                acl_tags: vec![],
            }).await?;
            if let Some(key) = resp.into_inner().pre_auth_key {
                // Store directly, never print
                let mut store = HeadscaleStore::load(&password)?;
                if let Some(s) = store.servers.iter_mut().find(|s| s.label == server.label) {
                    s.preauth_key = key.key;
                }
                store.save(&password)?;
                tracing::info!("New preauth key created and stored (id: {})", key.id);
            }
        }
        KeysSubcommand::ListApi => {
            let resp = client.list_api_keys(ListApiKeysRequest {}).await?;
            for k in resp.into_inner().api_keys {
                tracing::info!("  prefix={} (id: {})", k.prefix, k.id);
            }
        }
        KeysSubcommand::Rotate => {
            // Create new preauth key
            let preauth_resp = client.create_pre_auth_key(CreatePreAuthKeyRequest {
                user: 0,
                reusable: true,
                ephemeral: false,
                expiration: None,
                acl_tags: vec![],
            }).await?;

            // Create new API key
            let api_resp = client.create_api_key(CreateApiKeyRequest {
                expiration: None,
            }).await?;

            let new_preauth = preauth_resp.into_inner().pre_auth_key
                .ok_or("No preauth key in response")?;
            let new_api_key = api_resp.into_inner().api_key;

            // Update store directly, never print keys
            let mut store = HeadscaleStore::load(&password)?;
            if let Some(s) = store.servers.iter_mut().find(|s| s.label == server.label) {
                s.api_key = new_api_key;
                s.preauth_key = new_preauth.key;
            }
            store.save(&password)?;

            tracing::info!("Keys rotated and encrypted in ~/.oline/headscale.enc");
        }
    }
    Ok(())
}

// ── Policy ────────────────────────────────────────────────────────────────────

async fn cmd_vpn_policy(args: &VpnArgs, cmd: &PolicySubcommand) -> Result<(), Box<dyn Error>> {
    let (server, _) = resolve_server(args).await?;
    let mut client = build_client(&server).await?;

    match cmd {
        PolicySubcommand::Show => {
            let resp = client.get_policy(GetPolicyRequest {}).await?;
            let p = resp.into_inner();
            println!("{}", p.policy);
        }
        PolicySubcommand::Set { file } => {
            let policy = std::fs::read_to_string(file)
                .map_err(|e| format!("Read {}: {}", file, e))?;
            client.set_policy(SetPolicyRequest {
                policy,
                ..Default::default()
            }).await?;
            tracing::info!("Policy updated from {}", file);
        }
    }
    Ok(())
}

// ── Servers ───────────────────────────────────────────────────────────────────

async fn cmd_vpn_servers() -> Result<(), Box<dyn Error>> {
    let password = get_password()?;
    let store = HeadscaleStore::load(&password)?;

    tracing::info!("=== Headscale Servers ===");
    for s in &store.servers {
        let def = if s.label == store.default_label { " (default)" } else { "" };
        let prot = if s.protected { " [protected]" } else { "" };
        tracing::info!("  {} — {} (DSEQ {}){}{}", s.label, s.control_url, s.dseq, def, prot);
    }
    if store.servers.is_empty() {
        tracing::info!("  No servers configured. Run `oline vpn setup`.");
    }
    Ok(())
}

// ── PFSense Setup ─────────────────────────────────────────────────────────────

async fn cmd_vpn_pfsense_setup(
    args: &VpnArgs, host: &str, ssh_key: &str, ssh_user: &str,
    ssh_port: u16, routes: &str, hostname: &str,
) -> Result<(), Box<dyn Error>> {
    let (server, _) = resolve_server(args).await?;

    // The preauth key is passed as env var over SSH, never logged
    let script_path = find_setup_script()?;
    let script = std::fs::read_to_string(&script_path)
        .map_err(|e| format!("Read setup script {:?}: {}", script_path, e))?;

    tracing::info!("Running Tailscale setup on {}@{}:{}...", ssh_user, host, ssh_port);
    tracing::info!("  Hostname:   {}", hostname);
    tracing::info!("  Routes:     {}", routes);

    let status = std::process::Command::new("ssh")
        .args([
            "-i", ssh_key,
            "-p", &ssh_port.to_string(),
            "-o", "StrictHostKeyChecking=accept-new",
            &format!("{}@{}", ssh_user, host),
            &format!(
                "HEADSCALE_URL='{}' HEADSCALE_KEY='{}' PFSENSE_HOSTNAME='{}' ADVERTISE_ROUTES='{}' sh -s",
                server.control_url, server.preauth_key, hostname, routes,
            ),
        ])
        .stdin(std::process::Stdio::from(
            std::fs::File::open(&script_path)
                .map_err(|e| format!("open script: {}", e))?,
        ))
        .status()
        .map_err(|e| format!("SSH failed: {}", e))?;

    if status.success() {
        tracing::info!("pfSense Tailscale setup complete");
        tracing::info!("  Next: approve routes with oline vpn nodes routes <id> {}", routes);
    } else {
        return Err(format!("Setup script exited with {}", status).into());
    }

    Ok(())
}

fn find_setup_script() -> Result<std::path::PathBuf, Box<dyn Error>> {
    // Look in scripts/sh/ relative to the binary, or current dir
    let candidates = [
        std::path::PathBuf::from("scripts/sh/pfsense-tailscale-setup.sh"),
        std::path::PathBuf::from("plays/coach/pfsense-tailscale-setup.sh"),
    ];
    for p in &candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }
    // Try relative to binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("../scripts/sh/pfsense-tailscale-setup.sh");
            if p.exists() {
                return Ok(p);
            }
        }
    }
    Err("pfsense-tailscale-setup.sh not found. Place it in scripts/sh/".into())
}

/// Returns DSEQs of protected deployments (Headscale auth servers).
/// Called by manage close to prevent accidental deletion of critical infra.
pub fn load_protected_dseqs() -> Vec<u64> {
    let password = match std::env::var("OLINE_PASSWORD") {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    match HeadscaleStore::load(&password) {
        Ok(store) => store.servers
            .iter()
            .filter(|s| s.protected)
            .map(|s| s.dseq)
            .collect(),
        Err(_) => vec![],
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn fetch_deployment_logs(dseq: u64) -> Result<String, Box<dyn Error>> {
    let binary = std::env::current_exe()?;
    let output = tokio::process::Command::new("timeout")
        .arg("15")
        .arg(&binary)
        .args(["manage", "logs", &dseq.to_string(), "--tail", "200"])
        .output()
        .await
        .map_err(|e| format!("Failed to fetch logs: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format!("{}{}", stdout, stderr))
}

fn extract_between(text: &str, start_marker: &str, end_marker: &str) -> Option<String> {
    let start = text.find(start_marker)?;
    let after_start = &text[start + start_marker.len()..];
    let end = after_start.find(end_marker).unwrap_or(after_start.len());
    let extracted = after_start[..end].trim();
    if extracted.is_empty() { None } else { Some(extracted.to_string()) }
}

fn extract_line_after(text: &str, marker: &str) -> Option<String> {
    let start = text.find(marker)?;
    let after = &text[start + marker.len()..];
    after.lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .map(|s| s.to_string())
}
