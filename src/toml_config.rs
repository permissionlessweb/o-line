//! TOML-based configuration with deterministic env var derivation.
//!
//! The TOML config file is the single source of truth. Environment variables
//! are derived deterministically: `OLINE_` + `SCREAMING_SNAKE_CASE(config.path)`.
//!
//! Resolution priority: env var > config.toml[profiles.X] > config.toml[top-level] > struct default.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::Path;

// ─── Derivation helpers ───────────────────────────────────────────────────

/// Derive the canonical env var name from a TOML config path.
///
/// ```text
/// "chain.id"              → "OLINE_CHAIN_ID"
/// "images.node"           → "OLINE_IMAGES_NODE"
/// "nodes.snapshot.domain" → "OLINE_NODES_SNAPSHOT_DOMAIN"
/// ```
pub fn env_key(path: &str) -> String {
    format!("OLINE_{}", path.replace('.', "_").to_uppercase())
}

fn resolve_str(path: &str, toml_val: &str) -> String {
    let key = env_key(path);
    match std::env::var(&key) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => String::new(),
        Err(_) => toml_val.to_string(),
    }
}

fn resolve_vec(path: &str, toml_val: &[String]) -> Vec<String> {
    let key = env_key(path);
    match std::env::var(&key) {
        Ok(v) if !v.is_empty() => v.split(',').map(|s| s.trim().to_string()).collect(),
        Ok(_) => vec![],
        Err(_) => toml_val.to_vec(),
    }
}

fn resolve_u16(path: &str, toml_val: u16) -> u16 {
    let key = env_key(path);
    std::env::var(&key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(toml_val)
}

fn resolve_u32(path: &str, toml_val: u32) -> u32 {
    let key = env_key(path);
    std::env::var(&key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(toml_val)
}

fn resolve_bool(path: &str, toml_val: bool) -> bool {
    let key = env_key(path);
    match std::env::var(&key) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => toml_val,
    }
}

// ─── Config structs ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TestnetConfig {
    /// Docker image for testnet sentry nodes (terp-core with ZK wasmvm + hashmerchant + faucet).
    #[serde(default)]
    pub sentry_image: String,
    /// Faucet key mnemonic for sentry-a (funded in genesis; imported into sentry keyring).
    #[serde(default)]
    pub sentry_a_faucet_mnemonic: String,
    /// Faucet key mnemonic for sentry-b (separate key avoids tx sequence conflicts).
    #[serde(default)]
    pub sentry_b_faucet_mnemonic: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TomlConfig {
    pub chain: ChainConfig,
    #[serde(default)]
    pub images: ImagesConfig,
    #[serde(default)]
    pub akash: AkashConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub snapshot: SnapshotExportConfig,
    #[serde(default)]
    pub nodes: NodesConfig,
    #[serde(default)]
    pub relayer: RelayerConfig,
    #[serde(default)]
    pub argus: ArgusConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    #[serde(default)]
    pub sites: SitesConfig,
    #[serde(default)]
    pub minio: MinioConfig,
    #[serde(default)]
    pub testnet: TestnetConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Wrapper that deserializes a config.toml with optional `[profiles.<name>]` sections.
/// Profile values are deep-merged over the base config before env overrides apply.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfiledTomlConfig {
    #[serde(flatten)]
    pub base: TomlConfig,
    #[serde(default)]
    pub profiles: HashMap<String, toml::Value>,
}

impl ProfiledTomlConfig {
    /// Resolve a named profile by deep-merging it over the base config.
    /// Returns a plain TomlConfig with env overrides already applied.
    pub fn resolve(self, profile: &str) -> Result<TomlConfig, Box<dyn Error>> {
        let mut base_val = toml::Value::try_from(&self.base)
            .map_err(|e| format!("Failed to serialize base config: {}", e))?;

        if let Some(overlay) = self.profiles.get(profile) {
            deep_merge(&mut base_val, overlay);
        } else if !self.profiles.is_empty() {
            let available: Vec<&String> = self.profiles.keys().collect();
            tracing::warn!("  Profile '{}' not found. Available: {:?}", profile, available);
        }

        let mut config: TomlConfig = base_val.try_into()
            .map_err(|e| format!("Failed to deserialize merged config: {}", e))?;
        config.apply_env_overrides();
        Ok(config)
    }
}

/// Recursively merge overlay TOML tables into base. Scalars and arrays are replaced.
fn deep_merge(base: &mut toml::Value, overlay: &toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_map), toml::Value::Table(overlay_map)) => {
            for (key, overlay_val) in overlay_map {
                let entry = base_map
                    .entry(key.clone())
                    .or_insert_with(|| toml::Value::Table(Default::default()));
                deep_merge(entry, overlay_val);
            }
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}


// ── Chain ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChainConfig {
    #[serde(default = "d_chain_id")]
    pub id: String,
    #[serde(default = "d_binary")]
    pub binary: String,
    #[serde(default)]
    pub genesis_url: String,
    #[serde(default)]
    pub chain_json: String,
    #[serde(default)]
    pub addrbook_url: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub private_peers: Vec<String>,
    #[serde(default = "d_sync_method")]
    pub sync_method: String,
    #[serde(default)]
    pub snapshot_url: String,
    #[serde(default)]
    pub entrypoint_url: String,
    #[serde(default)]
    pub faucet_domain: String,
}

fn d_chain_id() -> String { "morocco-1".into() }
fn d_binary() -> String { "terpd".into() }
fn d_sync_method() -> String { "snapshot".into() }

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            id: d_chain_id(),
            binary: d_binary(),
            genesis_url: String::new(),
            chain_json: String::new(),
            addrbook_url: String::new(),
            peers: vec![],
            private_peers: vec![],
            sync_method: d_sync_method(),
            snapshot_url: String::new(),
            entrypoint_url: String::new(),
            faucet_domain: String::new(),
        }
    }
}

// ── Images ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImagesConfig {
    #[serde(default = "d_node_image")]
    pub node: String,
    #[serde(default = "d_minio_image")]
    pub minio: String,
    #[serde(default)]
    pub relayer: String,
    #[serde(default)]
    pub argus: String,
}

fn d_node_image() -> String { "ghcr.io/terpnetwork/terp-core:v5.1.6-oline".into() }
fn d_minio_image() -> String { "minio/minio:latest".into() }

impl Default for ImagesConfig {
    fn default() -> Self {
        Self {
            node: d_node_image(),
            minio: d_minio_image(),
            relayer: String::new(),
            argus: String::new(),
        }
    }
}

// ── Akash ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AkashConfig {
    #[serde(default = "d_akash_rpc")]
    pub rpc: String,
    #[serde(default = "d_akash_grpc")]
    pub grpc: String,
    #[serde(default = "d_akash_rest")]
    pub rest: String,
}

fn d_akash_rpc() -> String { "https://akash-rpc.polkachu.com".into() }
fn d_akash_grpc() -> String { "https://akash.lavenderfive.com:443".into() }
fn d_akash_rest() -> String { "https://api.akashnet.net:443".into() }

impl Default for AkashConfig {
    fn default() -> Self {
        Self { rpc: d_akash_rpc(), grpc: d_akash_grpc(), rest: d_akash_rest() }
    }
}

// ── DNS ───────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DnsConfig {
    #[serde(default)]
    pub cf_token: String,
    #[serde(default)]
    pub cf_zone: String,
}

// ── SSH ───────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SshConfig {
    #[serde(default = "d_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub pubkey: String,
}

fn d_ssh_port() -> u16 { 22 }

impl Default for SshConfig {
    fn default() -> Self { Self { port: d_ssh_port(), pubkey: String::new() } }
}

// ── Snapshot export ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SnapshotExportConfig {
    #[serde(default)]
    pub domain: String,
    #[serde(default = "d_snap_path")]
    pub path: String,
    #[serde(default = "d_snap_schedule")]
    pub schedule: String,
    #[serde(default = "d_snap_format")]
    pub format: String,
    #[serde(default = "d_snap_retain")]
    pub retain: String,
    #[serde(default = "d_snap_keep")]
    pub keep_last: u32,
}

fn d_snap_path() -> String { "snapshots/terpnetwork".into() }
fn d_snap_schedule() -> String { "00:00:00".into() }
fn d_snap_format() -> String { "tar.gz".into() }
fn d_snap_retain() -> String { "2 days".into() }
fn d_snap_keep() -> u32 { 2 }

impl Default for SnapshotExportConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            path: d_snap_path(),
            schedule: d_snap_schedule(),
            format: d_snap_format(),
            retain: d_snap_retain(),
            keep_last: d_snap_keep(),
        }
    }
}

// ── Nodes ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NodeConfig {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub ports: Option<NodePorts>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodePorts {
    #[serde(default = "d_rpc")]
    pub rpc: u16,
    #[serde(default = "d_api")]
    pub api: u16,
    #[serde(default = "d_grpc")]
    pub grpc: u16,
    #[serde(default = "d_p2p")]
    pub p2p: u16,
}

fn d_rpc() -> u16 { 26657 }
fn d_api() -> u16 { 1317 }
fn d_grpc() -> u16 { 9090 }
fn d_p2p() -> u16 { 26656 }

impl Default for NodePorts {
    fn default() -> Self { Self { rpc: d_rpc(), api: d_api(), grpc: d_grpc(), p2p: d_p2p() } }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NodesConfig {
    #[serde(default)]
    pub snapshot: NodeConfig,
    #[serde(default)]
    pub seed: NodeConfig,
    #[serde(default)]
    pub left_tackle: NodeConfig,
    #[serde(default)]
    pub right_tackle: NodeConfig,
    #[serde(default)]
    pub left_forward: NodeConfig,
    #[serde(default)]
    pub right_forward: NodeConfig,
}

// ── Relayer ───────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RelayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub key_name: String,
    #[serde(default)]
    pub remote_chain: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub key_terp: String,
    #[serde(default)]
    pub key_remote: String,
    #[serde(default)]
    pub entrypoint: String,
}

// ── Argus ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArgusConfig {
    #[serde(default)]
    pub node_moniker: String,
    #[serde(default)]
    pub node_seeds: String,
    #[serde(default)]
    pub node_persistent_peers: String,
    #[serde(default = "d_argus_image")]
    pub image: String,
    #[serde(default)]
    pub entrypoint_url: String,
    #[serde(default)]
    pub api_domain: String,
    #[serde(default = "d_bech32")]
    pub bech32_prefix: String,
    #[serde(default = "d_argus_db_user")]
    pub db_user: String,
    #[serde(default)]
    pub db_password: String,
    #[serde(default = "d_argus_db_data")]
    pub db_data_name: String,
    #[serde(default = "d_argus_db_accounts")]
    pub db_accounts_name: String,
}

fn d_argus_image() -> String { "ghcr.io/permissionlessweb/argus:latest".into() }
fn d_bech32() -> String { "terp".into() }
fn d_argus_db_user() -> String { "argus".into() }
fn d_argus_db_data() -> String { "argus_data".into() }
fn d_argus_db_accounts() -> String { "argus_accounts".into() }

impl Default for ArgusConfig {
    fn default() -> Self {
        Self {
            node_moniker: String::new(),
            node_seeds: String::new(),
            node_persistent_peers: String::new(),
            image: d_argus_image(),
            entrypoint_url: String::new(),
            api_domain: String::new(),
            bech32_prefix: d_bech32(),
            db_user: d_argus_db_user(),
            db_password: String::new(),
            db_data_name: d_argus_db_data(),
            db_accounts_name: d_argus_db_accounts(),
        }
    }
}

// ── Registry ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistryConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default = "d_reg_port")]
    pub port: u16,
    #[serde(default = "d_reg_user")]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub storage_dir: String,
}

fn d_reg_port() -> u16 { 5000 }
fn d_reg_user() -> String { "oline".into() }

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            port: d_reg_port(),
            username: d_reg_user(),
            password: String::new(),
            storage_dir: String::new(),
        }
    }
}

// ── Sites ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SitesConfig {
    #[serde(default)]
    pub gateway_domain: String,
    #[serde(default)]
    pub s3_domain: String,
    #[serde(default)]
    pub console_domain: String,
}

// ── MinIO ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinioConfig {
    #[serde(default = "d_autopin")]
    pub autopin_interval: u32,
}

fn d_autopin() -> u32 { 300 }

impl Default for MinioConfig {
    fn default() -> Self { Self { autopin_interval: d_autopin() } }
}

// ── Proxy ─────────────────────────────────────────────────────────────────

fn d_proxy_image() -> String { "ghcr.io/hard-nett/oline-proxy-node:latest".into() }
fn d_proxy_svc() -> String { "proxy-node".into() }
fn d_akash_chain_id() -> String { "akashnet-2".into() }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    /// Whether the proxy is enabled for log streaming and provider communication.
    #[serde(default)]
    pub enabled: bool,
    /// Docker image for the provider-proxy-node container.
    #[serde(default = "d_proxy_image")]
    pub image: String,
    /// Service name in the SDL template.
    #[serde(default = "d_proxy_svc")]
    pub service_name: String,
    /// Proxy deployment URL (auto-populated after `oline proxy deploy`).
    #[serde(default)]
    pub url: String,
    /// DSEQ of the proxy deployment (auto-populated).
    #[serde(default)]
    pub dseq: u64,
    /// Domain for the proxy's Akash ingress.
    #[serde(default)]
    pub domain: String,
    /// Akash chain ID for the co-located node.
    #[serde(default = "d_akash_chain_id")]
    pub akash_chain_id: String,
    /// Seed nodes for the co-located Akash node.
    #[serde(default)]
    pub akash_seeds: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            image: d_proxy_image(),
            service_name: d_proxy_svc(),
            url: String::new(),
            dseq: 0,
            domain: String::new(),
            akash_chain_id: d_akash_chain_id(),
            akash_seeds: String::new(),
        }
    }
}

// ── Logging ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoggingConfig {
    /// Auto-persist logs when entering the TUI.
    #[serde(default = "d_persist")]
    pub persist: bool,
    /// Custom log directory (default: ~/.oline/logs/).
    #[serde(default)]
    pub log_dir: String,
}

fn d_persist() -> bool { true }

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            persist: true,
            log_dir: String::new(),
        }
    }
}

// ─── Core implementation ──────────────────────────────────────────────────

impl TomlConfig {
    /// Load from TOML file, then apply env var overrides.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let content = fs::read_to_string(path.as_ref())?;
        let mut config: Self = toml::from_str(&content)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Load from TOML file with optional profile selection, then apply env var overrides.
    pub fn load_with_profile(path: impl AsRef<Path>, profile: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let content = fs::read_to_string(path.as_ref())?;
        let profiled: ProfiledTomlConfig = toml::from_str(&content)?;
        match profile {
            Some(p) => profiled.resolve(p),
            None => {
                let mut config = profiled.base;
                config.apply_env_overrides();
                Ok(config)
            }
        }
    }

    /// Build from struct defaults + env var overrides (no file needed).
    pub fn from_defaults() -> Self {
        let mut config = Self {
            chain: ChainConfig::default(),
            images: ImagesConfig::default(),
            akash: AkashConfig::default(),
            dns: DnsConfig::default(),
            ssh: SshConfig::default(),
            snapshot: SnapshotExportConfig::default(),
            nodes: NodesConfig::default(),
            relayer: RelayerConfig::default(),
            argus: ArgusConfig::default(),
            registry: RegistryConfig::default(),
            sites: SitesConfig::default(),
            minio: MinioConfig::default(),
            testnet: TestnetConfig::default(),
            proxy: ProxyConfig::default(),
            logging: LoggingConfig::default(),
        };
        config.apply_env_overrides();
        config
    }

    /// Apply env var overrides to every field.
    ///
    /// For each field at TOML path `x.y.z`, checks `OLINE_X_Y_Z`.
    /// Also checks legacy env var names for backward compatibility.
    pub fn apply_env_overrides(&mut self) {
        // ── Chain ────────────────────────────────────────────────────
        self.chain.id = resolve_str("chain.id", &self.chain.id);
        self.chain.binary = resolve_str("chain.binary", &self.chain.binary);
        self.chain.genesis_url = resolve_str("chain.genesis_url", &self.chain.genesis_url);
        self.chain.chain_json = resolve_str("chain.chain_json", &self.chain.chain_json);
        self.chain.addrbook_url = resolve_str("chain.addrbook_url", &self.chain.addrbook_url);
        self.chain.peers = resolve_vec("chain.peers", &self.chain.peers);
        self.chain.private_peers = resolve_vec("chain.private_peers", &self.chain.private_peers);
        self.chain.sync_method = resolve_str("chain.sync_method", &self.chain.sync_method);
        self.chain.snapshot_url = resolve_str("chain.snapshot_url", &self.chain.snapshot_url);
        self.chain.entrypoint_url = resolve_str("chain.entrypoint_url", &self.chain.entrypoint_url);
        self.chain.faucet_domain = resolve_str("chain.faucet_domain", &self.chain.faucet_domain);

        // Legacy env var compat: OLINE_CHAIN_ID already matches, but some old names differ.
        // If the new key was empty but the old key has a value, use the old key.
        legacy_override_str(&mut self.images.node, "OMNIBUS_IMAGE");
        legacy_override_str(&mut self.chain.id, "OLINE_CHAIN_ID");
        legacy_override_str(&mut self.chain.binary, "OLINE_BINARY");
        legacy_override_str(&mut self.chain.chain_json, "OLINE_CHAIN_JSON");
        legacy_override_str(&mut self.chain.genesis_url, "GENESIS_URL");
        legacy_override_str(&mut self.chain.addrbook_url, "OLINE_ADDRBOOK_URL");
        legacy_override_str(&mut self.chain.entrypoint_url, "OLINE_ENTRYPOINT_URL");
        legacy_override_str(&mut self.chain.sync_method, "OLINE_SYNC_METHOD");
        legacy_override_str(&mut self.chain.snapshot_url, "OLINE_SNAPSHOT_URL");
        legacy_override_vec(&mut self.chain.peers, "OLINE_PERSISTENT_PEERS");
        legacy_override_vec(&mut self.chain.private_peers, "OLINE_VALIDATOR_PEER_ID");

        // ── Images ───────────────────────────────────────────────────
        self.images.node = resolve_str("images.node", &self.images.node);
        self.images.minio = resolve_str("images.minio", &self.images.minio);
        self.images.relayer = resolve_str("images.relayer", &self.images.relayer);
        self.images.argus = resolve_str("images.argus", &self.images.argus);
        legacy_override_str(&mut self.images.minio, "MINIO_IPFS_IMAGE");

        // ── Akash ────────────────────────────────────────────────────
        self.akash.rpc = resolve_str("akash.rpc", &self.akash.rpc);
        self.akash.grpc = resolve_str("akash.grpc", &self.akash.grpc);
        self.akash.rest = resolve_str("akash.rest", &self.akash.rest);
        legacy_override_str(&mut self.akash.rpc, "OLINE_RPC_ENDPOINT");
        legacy_override_str(&mut self.akash.grpc, "OLINE_GRPC_ENDPOINT");
        legacy_override_str(&mut self.akash.rest, "OLINE_REST_ENDPOINT");

        // ── DNS ──────────────────────────────────────────────────────
        self.dns.cf_token = resolve_str("dns.cf_token", &self.dns.cf_token);
        self.dns.cf_zone = resolve_str("dns.cf_zone", &self.dns.cf_zone);
        legacy_override_str(&mut self.dns.cf_token, "OLINE_CF_API_TOKEN");
        legacy_override_str(&mut self.dns.cf_zone, "OLINE_CF_ZONE_ID");

        // ── SSH ──────────────────────────────────────────────────────
        self.ssh.port = resolve_u16("ssh.port", self.ssh.port);
        self.ssh.pubkey = resolve_str("ssh.pubkey", &self.ssh.pubkey);
        if let Ok(v) = std::env::var("SSH_P") { if let Ok(p) = v.parse() { self.ssh.port = p; } }
        legacy_override_str(&mut self.ssh.pubkey, "SSH_PUBKEY");

        // ── Snapshot export ──────────────────────────────────────────
        self.snapshot.domain = resolve_str("snapshot.domain", &self.snapshot.domain);
        self.snapshot.path = resolve_str("snapshot.path", &self.snapshot.path);
        self.snapshot.schedule = resolve_str("snapshot.schedule", &self.snapshot.schedule);
        self.snapshot.format = resolve_str("snapshot.format", &self.snapshot.format);
        self.snapshot.retain = resolve_str("snapshot.retain", &self.snapshot.retain);
        self.snapshot.keep_last = resolve_u32("snapshot.keep_last", self.snapshot.keep_last);
        legacy_override_str(&mut self.snapshot.domain, "OLINE_SNAP_DOWNLOAD_DOMAIN");
        legacy_override_str(&mut self.snapshot.path, "OLINE_SNAP_PATH");
        legacy_override_str(&mut self.snapshot.schedule, "OLINE_SNAP_TIME");
        legacy_override_str(&mut self.snapshot.format, "OLINE_SNAP_SAVE_FORMAT");
        legacy_override_str(&mut self.snapshot.retain, "OLINE_SNAP_RETAIN");

        // ── Nodes ────────────────────────────────────────────────────
        self.apply_node_overrides("snapshot", &mut self.nodes.snapshot.clone(), "SNAP");
        self.apply_node_overrides("seed", &mut self.nodes.seed.clone(), "SEED");
        self.apply_node_overrides("left_tackle", &mut self.nodes.left_tackle.clone(), "TL");
        self.apply_node_overrides("right_tackle", &mut self.nodes.right_tackle.clone(), "TR");
        self.apply_node_overrides("left_forward", &mut self.nodes.left_forward.clone(), "FL");
        self.apply_node_overrides("right_forward", &mut self.nodes.right_forward.clone(), "FR");

        // Re-assign after override (clone workaround for borrow checker)
        let nodes = [
            ("snapshot", "SNAP"), ("seed", "SEED"),
            ("left_tackle", "TL"), ("right_tackle", "TR"),
            ("left_forward", "FL"), ("right_forward", "FR"),
        ];
        for (name, suffix) in nodes {
            let node = self.node_mut(name);
            node.domain = resolve_str(&format!("nodes.{}.domain", name), &node.domain);
            // Legacy: check old domain vars like RPC_D_SNAP.
            // If node domain is empty but legacy domain vars exist, try to infer.
            if node.domain.is_empty() {
                if let Ok(d) = std::env::var(&format!("RPC_D_{}", suffix)) {
                    if !d.is_empty() {
                        // Reverse-derive base domain from rpc subdomain
                        if let Some(base) = d.strip_prefix("rpc.") {
                            node.domain = base.to_string();
                        } else if let Some(rest) = d.strip_prefix("rpc-") {
                            node.domain = rest.to_string();
                        }
                    }
                }
            }
        }

        // ── Relayer ──────────────────────────────────────────────────
        self.relayer.enabled = resolve_bool("relayer.enabled", self.relayer.enabled);
        self.relayer.key_name = resolve_str("relayer.key_name", &self.relayer.key_name);
        self.relayer.remote_chain = resolve_str("relayer.remote_chain", &self.relayer.remote_chain);
        self.relayer.domain = resolve_str("relayer.domain", &self.relayer.domain);
        self.relayer.key_terp = resolve_str("relayer.key_terp", &self.relayer.key_terp);
        self.relayer.key_remote = resolve_str("relayer.key_remote", &self.relayer.key_remote);
        self.relayer.entrypoint = resolve_str("relayer.entrypoint", &self.relayer.entrypoint);
        legacy_override_str(&mut self.relayer.key_name, "RLY_KEY_NAME");
        legacy_override_str(&mut self.relayer.remote_chain, "RLY_REMOTE_CHAIN_ID");
        legacy_override_str(&mut self.relayer.domain, "RLY_API_D");
        legacy_override_str(&mut self.relayer.key_terp, "RLY_KEY_TERP");
        legacy_override_str(&mut self.relayer.key_remote, "RLY_KEY_REMOTE");
        legacy_override_str(&mut self.relayer.entrypoint, "RELAYER_ENTRYPOINT");

        // ── Argus ────────────────────────────────────────────────────
        self.argus.node_moniker = resolve_str("argus.node_moniker", &self.argus.node_moniker);
        self.argus.node_seeds = resolve_str("argus.node_seeds", &self.argus.node_seeds);
        self.argus.node_persistent_peers = resolve_str("argus.node_persistent_peers", &self.argus.node_persistent_peers);
        self.argus.image = resolve_str("argus.image", &self.argus.image);
        self.argus.entrypoint_url = resolve_str("argus.entrypoint_url", &self.argus.entrypoint_url);
        self.argus.api_domain = resolve_str("argus.api_domain", &self.argus.api_domain);
        self.argus.bech32_prefix = resolve_str("argus.bech32_prefix", &self.argus.bech32_prefix);
        self.argus.db_user = resolve_str("argus.db_user", &self.argus.db_user);
        self.argus.db_password = resolve_str("argus.db_password", &self.argus.db_password);
        self.argus.db_data_name = resolve_str("argus.db_data_name", &self.argus.db_data_name);
        self.argus.db_accounts_name = resolve_str("argus.db_accounts_name", &self.argus.db_accounts_name);
        legacy_override_str(&mut self.argus.node_moniker, "ARGUS_NODE_MONIKER");
        legacy_override_str(&mut self.argus.node_seeds, "ARGUS_NODE_SEEDS");
        legacy_override_str(&mut self.argus.node_persistent_peers, "ARGUS_NODE_PERSISTENT_PEERS");
        legacy_override_str(&mut self.argus.image, "ARGUS_IMAGE");
        legacy_override_str(&mut self.argus.entrypoint_url, "ARGUS_ENTRYPOINT_URL");
        legacy_override_str(&mut self.argus.api_domain, "ARGUS_API_D");
        legacy_override_str(&mut self.argus.bech32_prefix, "ARGUS_BECH32_PREFIX");
        legacy_override_str(&mut self.argus.db_user, "ARGUS_DB_USER");
        legacy_override_str(&mut self.argus.db_password, "ARGUS_DB_PASSWORD");
        legacy_override_str(&mut self.argus.db_data_name, "ARGUS_DB_DATA_NAME");
        legacy_override_str(&mut self.argus.db_accounts_name, "ARGUS_DB_ACCOUNTS_NAME");

        // ── Registry ─────────────────────────────────────────────────
        self.registry.url = resolve_str("registry.url", &self.registry.url);
        self.registry.port = resolve_u16("registry.port", self.registry.port);
        self.registry.username = resolve_str("registry.username", &self.registry.username);
        self.registry.password = resolve_str("registry.password", &self.registry.password);
        self.registry.storage_dir = resolve_str("registry.storage_dir", &self.registry.storage_dir);
        legacy_override_str(&mut self.registry.url, "OLINE_REGISTRY_URL");
        legacy_override_str(&mut self.registry.username, "OLINE_REGISTRY_USERNAME");
        legacy_override_str(&mut self.registry.password, "OLINE_REGISTRY_PASSWORD");
        legacy_override_str(&mut self.registry.storage_dir, "OLINE_REGISTRY_DIR");

        // ── Sites ────────────────────────────────────────────────────
        self.sites.gateway_domain = resolve_str("sites.gateway_domain", &self.sites.gateway_domain);
        self.sites.s3_domain = resolve_str("sites.s3_domain", &self.sites.s3_domain);
        self.sites.console_domain = resolve_str("sites.console_domain", &self.sites.console_domain);
        legacy_override_str(&mut self.sites.gateway_domain, "SITES_GATEWAY_DOMAIN");
        legacy_override_str(&mut self.sites.s3_domain, "SITES_S3_DOMAIN");
        legacy_override_str(&mut self.sites.console_domain, "SITES_CONSOLE_DOMAIN");

        // ── MinIO ────────────────────────────────────────────────────
        self.minio.autopin_interval = resolve_u32("minio.autopin_interval", self.minio.autopin_interval);

        // ── Proxy ───────────────────────────────────────────────────
        self.proxy.enabled = resolve_bool("proxy.enabled", self.proxy.enabled);
        self.proxy.image = resolve_str("proxy.image", &self.proxy.image);
        self.proxy.service_name = resolve_str("proxy.service_name", &self.proxy.service_name);
        self.proxy.url = resolve_str("proxy.url", &self.proxy.url);
        self.proxy.domain = resolve_str("proxy.domain", &self.proxy.domain);
        self.proxy.akash_chain_id = resolve_str("proxy.akash_chain_id", &self.proxy.akash_chain_id);
        self.proxy.akash_seeds = resolve_str("proxy.akash_seeds", &self.proxy.akash_seeds);

        // ── Logging ─────────────────────────────────────────────────
        self.logging.persist = resolve_bool("logging.persist", self.logging.persist);
        self.logging.log_dir = resolve_str("logging.log_dir", &self.logging.log_dir);
    }

    fn node_mut(&mut self, name: &str) -> &mut NodeConfig {
        match name {
            "snapshot" => &mut self.nodes.snapshot,
            "seed" => &mut self.nodes.seed,
            "left_tackle" => &mut self.nodes.left_tackle,
            "right_tackle" => &mut self.nodes.right_tackle,
            "left_forward" => &mut self.nodes.left_forward,
            "right_forward" => &mut self.nodes.right_forward,
            _ => unreachable!(),
        }
    }

    fn apply_node_overrides(&self, _name: &str, _node: &mut NodeConfig, _suffix: &str) {
        // Port overrides handled in to_sdl_vars via defaults
    }

    /// Get effective ports for a node (custom or defaults).
    fn node_ports(node: &NodeConfig) -> NodePorts {
        node.ports.clone().unwrap_or_default()
    }

    /// Derive subdomain from a base domain.
    ///
    /// Simple domains (e.g. "terp.network") → dot prefix: `rpc.terp.network`
    /// Structured domains (e.g. "mainnet.terp.network") → dash prefix: `rpc-mainnet.terp.network`
    fn derive_subdomain(prefix: &str, domain: &str) -> String {
        if domain.is_empty() { return String::new(); }
        let dot_count = domain.chars().filter(|c| *c == '.').count();
        if dot_count <= 1 {
            format!("{}.{}", prefix, domain)
        } else {
            format!("{}-{}", prefix, domain)
        }
    }

    /// Convert to flat SDL template variable map.
    ///
    /// Emits both legacy keys (for existing SDL templates) and new deterministic
    /// `OLINE_*` keys. SDL templates can migrate incrementally.
    pub fn to_sdl_vars(&self) -> HashMap<String, String> {
        let mut v = HashMap::new();

        // ── Chain ────────────────────────────────────────────────────
        v.insert("OLINE_CHAIN_ID".into(), self.chain.id.clone());
        v.insert("OLINE_BINARY".into(), self.chain.binary.clone());
        v.insert("GENESIS_URL".into(), self.chain.genesis_url.clone());
        v.insert("OLINE_CHAIN_JSON".into(), self.chain.chain_json.clone());
        v.insert("OLINE_ADDRBOOK_URL".into(), self.chain.addrbook_url.clone());
        v.insert("OLINE_PERSISTENT_PEERS".into(), self.chain.peers.join(","));
        v.insert("OLINE_VALIDATOR_PEER_ID".into(), self.chain.private_peers.join(","));
        v.insert("OLINE_SYNC_METHOD".into(), self.chain.sync_method.clone());
        v.insert("OLINE_SNAPSHOT_URL".into(), self.chain.snapshot_url.clone());
        v.insert("OLINE_ENTRYPOINT_URL".into(), self.chain.entrypoint_url.clone());
        v.insert("FAUCET_D".into(), self.chain.faucet_domain.clone());

        // ── Images ───────────────────────────────────────────────────
        v.insert("OMNIBUS_IMAGE".into(), self.images.node.clone());
        v.insert("OLINE_IMAGES_NODE".into(), self.images.node.clone());
        v.insert("MINIO_IPFS_IMAGE".into(), self.images.minio.clone());
        v.insert("RLY_IMAGE".into(), self.images.relayer.clone());
        v.insert("ARGUS_IMAGE".into(), self.images.argus.clone());

        // ── Akash ────────────────────────────────────────────────────
        v.insert("OLINE_RPC_ENDPOINT".into(), self.akash.rpc.clone());
        v.insert("OLINE_AKASH_RPC".into(), self.akash.rpc.clone());
        v.insert("OLINE_GRPC_ENDPOINT".into(), self.akash.grpc.clone());
        v.insert("OLINE_AKASH_GRPC".into(), self.akash.grpc.clone());
        v.insert("OLINE_REST_ENDPOINT".into(), self.akash.rest.clone());
        v.insert("OLINE_AKASH_REST".into(), self.akash.rest.clone());

        // ── DNS ──────────────────────────────────────────────────────
        v.insert("OLINE_CF_API_TOKEN".into(), self.dns.cf_token.clone());
        v.insert("OLINE_CF_ZONE_ID".into(), self.dns.cf_zone.clone());

        // ── SSH ──────────────────────────────────────────────────────
        v.insert("SSH_P".into(), self.ssh.port.to_string());

        // ── Snapshot export ──────────────────────────────────────────
        v.insert("OLINE_SNAP_DOWNLOAD_DOMAIN".into(), self.snapshot.domain.clone());
        v.insert("OLINE_SNAP_PATH".into(), self.snapshot.path.clone());
        v.insert("OLINE_SNAP_TIME".into(), self.snapshot.schedule.clone());
        v.insert("OLINE_SNAP_SAVE_FORMAT".into(), self.snapshot.format.clone());
        v.insert("OLINE_SNAP_RETAIN".into(), self.snapshot.retain.clone());
        v.insert("OLINE_SNAP_KEEP_LAST".into(), self.snapshot.keep_last.to_string());

        // ── Nodes (derived subdomains + ports) ───────────────────────
        self.insert_node_vars(&mut v, &self.nodes.snapshot, "SNAP");
        self.insert_node_vars(&mut v, &self.nodes.seed, "SEED");
        self.insert_node_vars(&mut v, &self.nodes.left_tackle, "TL");
        self.insert_node_vars(&mut v, &self.nodes.right_tackle, "TR");
        self.insert_node_vars(&mut v, &self.nodes.left_forward, "FL");
        self.insert_node_vars(&mut v, &self.nodes.right_forward, "FR");

        // ── Sites ────────────────────────────────────────────────────
        v.insert("SITES_GATEWAY_DOMAIN".into(), self.sites.gateway_domain.clone());
        v.insert("SITES_S3_DOMAIN".into(), self.sites.s3_domain.clone());
        v.insert("SITES_CONSOLE_DOMAIN".into(), self.sites.console_domain.clone());

        // ── MinIO ────────────────────────────────────────────────────
        v.insert("OLINE_AUTOPIN_INTERVAL".into(), self.minio.autopin_interval.to_string());

        // ── Relayer ──────────────────────────────────────────────────
        v.insert("RLY_KEY_NAME".into(), self.relayer.key_name.clone());
        v.insert("RLY_REMOTE_CHAIN_ID".into(), self.relayer.remote_chain.clone());
        v.insert("RLY_API_D".into(), self.relayer.domain.clone());
        v.insert("RLY_KEY_TERP".into(), self.relayer.key_terp.clone());
        v.insert("RLY_KEY_REMOTE".into(), self.relayer.key_remote.clone());
        v.insert("RELAYER_ENTRYPOINT".into(), self.relayer.entrypoint.clone());

        // ── Argus ────────────────────────────────────────────────────
        v.insert("ARGUS_NODE_MONIKER".into(), self.argus.node_moniker.clone());
        v.insert("ARGUS_NODE_SEEDS".into(), self.argus.node_seeds.clone());
        v.insert("ARGUS_NODE_PERSISTENT_PEERS".into(), self.argus.node_persistent_peers.clone());
        v.insert("ARGUS_ENTRYPOINT_URL".into(), self.argus.entrypoint_url.clone());
        v.insert("ARGUS_API_D".into(), self.argus.api_domain.clone());
        v.insert("ARGUS_BECH32_PREFIX".into(), self.argus.bech32_prefix.clone());
        v.insert("ARGUS_DB_USER".into(), self.argus.db_user.clone());
        v.insert("ARGUS_DB_PASSWORD".into(), self.argus.db_password.clone());
        v.insert("ARGUS_DB_DATA_NAME".into(), self.argus.db_data_name.clone());
        v.insert("ARGUS_DB_ACCOUNTS_NAME".into(), self.argus.db_accounts_name.clone());

        // ── Registry ─────────────────────────────────────────────────
        v.insert("OLINE_REGISTRY_URL".into(), self.registry.url.clone());
        v.insert("OLINE_REGISTRY_P".into(), self.registry.port.to_string());
        v.insert("OLINE_REGISTRY_USERNAME".into(), self.registry.username.clone());
        v.insert("OLINE_REGISTRY_PASSWORD".into(), self.registry.password.clone());
        v.insert("OLINE_REGISTRY_DIR".into(), self.registry.storage_dir.clone());

        // ── Proxy ────────────────────────────────────────────────────
        v.insert("PROXY_NODE_IMAGE".into(), self.proxy.image.clone());
        v.insert("PROXY_SVC".into(), self.proxy.service_name.clone());
        v.insert("PROXY_DOMAIN".into(), self.proxy.domain.clone());
        v.insert("AKASH_CHAIN_ID".into(), self.proxy.akash_chain_id.clone());
        v.insert("AKASH_SEEDS".into(), self.proxy.akash_seeds.clone());

        // ── SDL template dir ─────────────────────────────────────────
        // Prefer ~/.oline/templates/ so `oline` works from any directory.
        // Fall back to ./templates/sdls/oline for dev-tree usage.
        let sdl_home = crate::config::oline_config_dir().join("templates");
        let sdl_dir = if sdl_home.exists() {
            sdl_home.to_string_lossy().into_owned()
        } else {
            "templates/sdls/oline".into()
        };
        v.insert("SDL_DIR".into(), sdl_dir);

        // ── Testnet ───────────────────────────────────────────────────
        v.insert("TESTNET_SENTRY_IMAGE".into(),
            resolve_str("testnet.sentry_image", &self.testnet.sentry_image));
        v.insert("TESTNET_SENTRY_A_FAUCET_MNEMONIC".into(),
            resolve_str("testnet.sentry_a_faucet_mnemonic", &self.testnet.sentry_a_faucet_mnemonic));
        v.insert("TESTNET_SENTRY_B_FAUCET_MNEMONIC".into(),
            resolve_str("testnet.sentry_b_faucet_mnemonic", &self.testnet.sentry_b_faucet_mnemonic));

        v
    }

    /// Insert derived domain/port vars for a node position into the SDL var map.
    fn insert_node_vars(&self, v: &mut HashMap<String, String>, node: &NodeConfig, suffix: &str) {
        let ports = Self::node_ports(node);
        let d = &node.domain;

        v.insert(format!("RPC_P_{}", suffix), ports.rpc.to_string());
        v.insert(format!("API_P_{}", suffix), ports.api.to_string());
        v.insert(format!("GRPC_P_{}", suffix), ports.grpc.to_string());
        v.insert(format!("P2P_P_{}", suffix), ports.p2p.to_string());

        if d.is_empty() {
            v.insert(format!("RPC_D_{}", suffix), String::new());
            v.insert(format!("API_D_{}", suffix), String::new());
            v.insert(format!("GRPC_D_{}", suffix), String::new());
            v.insert(format!("P2P_D_{}", suffix), String::new());
        } else {
            v.insert(format!("RPC_D_{}", suffix), Self::derive_subdomain("rpc", d));
            v.insert(format!("API_D_{}", suffix), Self::derive_subdomain("api", d));
            v.insert(format!("GRPC_D_{}", suffix), Self::derive_subdomain("grpc", d));
            v.insert(format!("P2P_D_{}", suffix), Self::derive_subdomain("peer", d));
        }
    }

    /// Fields that are secrets and should not be displayed/exported.
    pub fn secret_paths() -> &'static [&'static str] {
        &[
            "dns.cf_token",
            "relayer.key_terp",
            "relayer.key_remote",
            "argus.db_password",
            "registry.password",
        ]
    }
}

// ─── Legacy env var bridge ────────────────────────────────────────────────

/// If `field` is empty and the legacy env var is set, use the legacy value.
fn legacy_override_str(field: &mut String, legacy_key: &str) {
    if field.is_empty() {
        if let Ok(v) = std::env::var(legacy_key) {
            if !v.is_empty() {
                *field = v;
            }
        }
    }
}

/// Same as `legacy_override_str` but for Vec fields (comma-delimited env var).
fn legacy_override_vec(field: &mut Vec<String>, legacy_key: &str) {
    if field.is_empty() {
        if let Ok(v) = std::env::var(legacy_key) {
            if !v.is_empty() {
                *field = v.split(',').map(|s| s.trim().to_string()).collect();
            }
        }
    }
}

// ─── Field introspection (replaces FIELD_DESCRIPTORS) ─────────────────────

/// A single config field for interactive display / override.
#[derive(Debug, Clone)]
pub struct ConfigField {
    pub path: &'static str,
    pub description: &'static str,
    pub is_secret: bool,
}

/// All config fields in display order.
pub const CONFIG_FIELDS: &[ConfigField] = &[
    // Chain
    ConfigField { path: "chain.id",             description: "Chain ID",                        is_secret: false },
    ConfigField { path: "chain.binary",         description: "Cosmos daemon binary",            is_secret: false },
    ConfigField { path: "chain.genesis_url",    description: "Genesis JSON URL",                is_secret: false },
    ConfigField { path: "chain.chain_json",     description: "Chain JSON URL",                  is_secret: false },
    ConfigField { path: "chain.addrbook_url",   description: "Address book URL",                is_secret: false },
    ConfigField { path: "chain.peers",          description: "Persistent peers",                is_secret: false },
    ConfigField { path: "chain.private_peers",  description: "Private peer IDs",                is_secret: false },
    ConfigField { path: "chain.sync_method",    description: "Sync method (snapshot/statesync)",is_secret: false },
    ConfigField { path: "chain.snapshot_url",   description: "Snapshot download URL",           is_secret: false },
    ConfigField { path: "chain.entrypoint_url", description: "Bootstrap entrypoint script URL", is_secret: false },
    // Images
    ConfigField { path: "images.node",          description: "Node container image",            is_secret: false },
    ConfigField { path: "images.minio",         description: "MinIO container image",           is_secret: false },
    ConfigField { path: "images.relayer",       description: "Relayer container image",         is_secret: false },
    ConfigField { path: "images.argus",         description: "Argus container image",           is_secret: false },
    // Akash
    ConfigField { path: "akash.rpc",            description: "Akash RPC endpoint",              is_secret: false },
    ConfigField { path: "akash.grpc",           description: "Akash gRPC endpoint",             is_secret: false },
    ConfigField { path: "akash.rest",           description: "Akash REST endpoint",             is_secret: false },
    // DNS
    ConfigField { path: "dns.cf_token",         description: "Cloudflare API token",            is_secret: true  },
    ConfigField { path: "dns.cf_zone",          description: "Cloudflare zone ID",              is_secret: false },
    // SSH
    ConfigField { path: "ssh.port",             description: "SSH port",                        is_secret: false },
    ConfigField { path: "ssh.pubkey",           description: "SSH public key",                  is_secret: false },
    // Snapshot export
    ConfigField { path: "snapshot.domain",      description: "Snapshot download domain",        is_secret: false },
    ConfigField { path: "snapshot.path",        description: "S3 snapshot path",                is_secret: false },
    ConfigField { path: "snapshot.schedule",    description: "Snapshot schedule time",          is_secret: false },
    ConfigField { path: "snapshot.format",      description: "Snapshot save format",            is_secret: false },
    ConfigField { path: "snapshot.retain",      description: "Snapshot retention period",       is_secret: false },
    ConfigField { path: "snapshot.keep_last",   description: "Min snapshots to keep",           is_secret: false },
    // Nodes
    ConfigField { path: "nodes.snapshot.domain",     description: "Snapshot node domain",       is_secret: false },
    ConfigField { path: "nodes.seed.domain",         description: "Seed node domain",           is_secret: false },
    ConfigField { path: "nodes.left_tackle.domain",  description: "Left tackle domain",         is_secret: false },
    ConfigField { path: "nodes.right_tackle.domain", description: "Right tackle domain",        is_secret: false },
    ConfigField { path: "nodes.left_forward.domain", description: "Left forward domain",        is_secret: false },
    ConfigField { path: "nodes.right_forward.domain",description: "Right forward domain",       is_secret: false },
    // Relayer
    ConfigField { path: "relayer.key_name",     description: "Relayer key name",                is_secret: false },
    ConfigField { path: "relayer.remote_chain", description: "Remote chain ID",                 is_secret: false },
    ConfigField { path: "relayer.domain",       description: "Relayer API domain",              is_secret: false },
    ConfigField { path: "relayer.key_terp",     description: "Terp relayer key mnemonic",       is_secret: true  },
    ConfigField { path: "relayer.key_remote",   description: "Remote relayer key mnemonic",     is_secret: true  },
    ConfigField { path: "relayer.entrypoint",   description: "Relayer entrypoint URL",          is_secret: false },
    // Argus
    ConfigField { path: "argus.node_moniker",        description: "Argus node moniker",         is_secret: false },
    ConfigField { path: "argus.node_seeds",          description: "Argus node seeds",           is_secret: false },
    ConfigField { path: "argus.node_persistent_peers",description: "Argus persistent peers",    is_secret: false },
    ConfigField { path: "argus.image",               description: "Argus Docker image",         is_secret: false },
    ConfigField { path: "argus.entrypoint_url",      description: "Argus entrypoint URL",       is_secret: false },
    ConfigField { path: "argus.api_domain",          description: "Argus API domain",           is_secret: false },
    ConfigField { path: "argus.bech32_prefix",       description: "Bech32 prefix",              is_secret: false },
    ConfigField { path: "argus.db_user",             description: "PostgreSQL username",         is_secret: false },
    ConfigField { path: "argus.db_password",         description: "PostgreSQL password",         is_secret: true  },
    ConfigField { path: "argus.db_data_name",        description: "PostgreSQL data DB name",     is_secret: false },
    ConfigField { path: "argus.db_accounts_name",    description: "PostgreSQL accounts DB name", is_secret: false },
    // Registry
    ConfigField { path: "registry.url",         description: "Registry URL",                    is_secret: false },
    ConfigField { path: "registry.port",        description: "Registry port",                   is_secret: false },
    ConfigField { path: "registry.username",    description: "Registry username",               is_secret: false },
    ConfigField { path: "registry.password",    description: "Registry password",               is_secret: true  },
    ConfigField { path: "registry.storage_dir", description: "Registry storage dir",            is_secret: false },
    // Sites
    ConfigField { path: "sites.gateway_domain", description: "Sites IPFS gateway domain",       is_secret: false },
    ConfigField { path: "sites.s3_domain",      description: "Sites S3 domain",                 is_secret: false },
    ConfigField { path: "sites.console_domain", description: "Sites console domain",            is_secret: false },
    // MinIO
    ConfigField { path: "minio.autopin_interval", description: "IPFS auto-pin interval (s)",    is_secret: false },
];

// ─── Field-dispatch macros ────────────────────────────────────────────────
//
// `dispatch_get!` and `dispatch_set!` expand a table of `(kind, path, field)`
// entries into the match bodies for `get_value` and `set_value`.  Both macros
// share the same table format so the two methods can never drift apart.
//
// Supported kinds:
//   str  – String field   (get: clone;          set: direct assign)
//   vec  – Vec<String>    (get: join(",");       set: split+collect, empty filtered)
//   u16  – u16 field      (get: to_string();     set: parse, ignore on error)
//   u32  – u32 field      (get: to_string();     set: parse, ignore on error)
//
// Field paths are dot-chained relative to `self`, e.g. `chain.id` expands to
// `self.chain.id` (or `cfg.chain.id` in the get variant).

macro_rules! dispatch_get {
    // Entry point: `$cfg` is an ident so arm rules can chain field access after it.
    ($cfg:ident, $key:expr, {
        $( $kind:ident $path:literal => $( $seg:ident ).+ ),* $(,)?
    }) => {
        match $key {
            $( $path => dispatch_get!(@arm $kind $cfg $( $seg ).+), )*
            _ => String::new(),
        }
    };
    // str arm: clone the String field
    (@arm str $cfg:ident $( $seg:ident ).+) => { $cfg.$( $seg ).+.clone() };
    // vec arm: join with comma
    (@arm vec $cfg:ident $( $seg:ident ).+) => { $cfg.$( $seg ).+.join(",") };
    // u16 / u32 arms: convert to string
    (@arm u16 $cfg:ident $( $seg:ident ).+) => { $cfg.$( $seg ).+.to_string() };
    (@arm u32 $cfg:ident $( $seg:ident ).+) => { $cfg.$( $seg ).+.to_string() };
}

macro_rules! dispatch_set {
    // Entry point: `$cfg` and `$val` are idents so arms can use them freely.
    ($cfg:ident, $key:expr, $val:ident, {
        $( $kind:ident $path:literal => $( $seg:ident ).+ ),* $(,)?
    }) => {
        match $key {
            $( $path => dispatch_set!(@arm $kind $cfg $val $( $seg ).+), )*
            _ => {}
        }
    };
    // str arm: move the value in directly
    (@arm str $cfg:ident $val:ident $( $seg:ident ).+) => { $cfg.$( $seg ).+ = $val };
    // vec arm: split on comma, trim, drop empty
    (@arm vec $cfg:ident $val:ident $( $seg:ident ).+) => {
        $cfg.$( $seg ).+ = $val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    // u16 arm: parse; silently ignore unparseable input
    (@arm u16 $cfg:ident $val:ident $( $seg:ident ).+) => {
        if let Ok(n) = $val.parse() { $cfg.$( $seg ).+ = n }
    };
    // u32 arm: parse; silently ignore unparseable input
    (@arm u32 $cfg:ident $val:ident $( $seg:ident ).+) => {
        if let Ok(n) = $val.parse() { $cfg.$( $seg ).+ = n }
    };
}

impl TomlConfig {
    /// Get the current value of a field by its dotted path.
    pub fn get_value(&self, path: &str) -> String {
        dispatch_get!(self, path, {
            str  "chain.id"                       => chain.id,
            str  "chain.binary"                   => chain.binary,
            str  "chain.genesis_url"               => chain.genesis_url,
            str  "chain.chain_json"                => chain.chain_json,
            str  "chain.addrbook_url"              => chain.addrbook_url,
            vec  "chain.peers"                    => chain.peers,
            vec  "chain.private_peers"             => chain.private_peers,
            str  "chain.sync_method"               => chain.sync_method,
            str  "chain.snapshot_url"              => chain.snapshot_url,
            str  "chain.entrypoint_url"            => chain.entrypoint_url,
            str  "chain.faucet_domain"             => chain.faucet_domain,
            str  "images.node"                    => images.node,
            str  "images.minio"                   => images.minio,
            str  "images.relayer"                 => images.relayer,
            str  "images.argus"                   => images.argus,
            str  "akash.rpc"                      => akash.rpc,
            str  "akash.grpc"                     => akash.grpc,
            str  "akash.rest"                     => akash.rest,
            str  "dns.cf_token"                   => dns.cf_token,
            str  "dns.cf_zone"                    => dns.cf_zone,
            u16  "ssh.port"                       => ssh.port,
            str  "ssh.pubkey"                     => ssh.pubkey,
            str  "snapshot.domain"                => snapshot.domain,
            str  "snapshot.path"                  => snapshot.path,
            str  "snapshot.schedule"              => snapshot.schedule,
            str  "snapshot.format"                => snapshot.format,
            str  "snapshot.retain"                => snapshot.retain,
            u32  "snapshot.keep_last"             => snapshot.keep_last,
            str  "nodes.snapshot.domain"          => nodes.snapshot.domain,
            str  "nodes.seed.domain"              => nodes.seed.domain,
            str  "nodes.left_tackle.domain"       => nodes.left_tackle.domain,
            str  "nodes.right_tackle.domain"      => nodes.right_tackle.domain,
            str  "nodes.left_forward.domain"      => nodes.left_forward.domain,
            str  "nodes.right_forward.domain"     => nodes.right_forward.domain,
            str  "relayer.key_name"               => relayer.key_name,
            str  "relayer.remote_chain"           => relayer.remote_chain,
            str  "relayer.domain"                 => relayer.domain,
            str  "relayer.key_terp"               => relayer.key_terp,
            str  "relayer.key_remote"             => relayer.key_remote,
            str  "relayer.entrypoint"             => relayer.entrypoint,
            str  "argus.node_moniker"             => argus.node_moniker,
            str  "argus.node_seeds"               => argus.node_seeds,
            str  "argus.node_persistent_peers"    => argus.node_persistent_peers,
            str  "argus.image"                    => argus.image,
            str  "argus.entrypoint_url"           => argus.entrypoint_url,
            str  "argus.api_domain"               => argus.api_domain,
            str  "argus.bech32_prefix"            => argus.bech32_prefix,
            str  "argus.db_user"                  => argus.db_user,
            str  "argus.db_password"              => argus.db_password,
            str  "argus.db_data_name"             => argus.db_data_name,
            str  "argus.db_accounts_name"         => argus.db_accounts_name,
            str  "registry.url"                   => registry.url,
            u16  "registry.port"                  => registry.port,
            str  "registry.username"              => registry.username,
            str  "registry.password"              => registry.password,
            str  "registry.storage_dir"           => registry.storage_dir,
            str  "sites.gateway_domain"           => sites.gateway_domain,
            str  "sites.s3_domain"                => sites.s3_domain,
            str  "sites.console_domain"           => sites.console_domain,
            u32  "minio.autopin_interval"         => minio.autopin_interval,
        })
    }

    /// Set a field value by its dotted path.
    pub fn set_value(&mut self, path: &str, value: String) {
        dispatch_set!(self, path, value, {
            str  "chain.id"                       => chain.id,
            str  "chain.binary"                   => chain.binary,
            str  "chain.genesis_url"               => chain.genesis_url,
            str  "chain.chain_json"                => chain.chain_json,
            str  "chain.addrbook_url"              => chain.addrbook_url,
            vec  "chain.peers"                    => chain.peers,
            vec  "chain.private_peers"             => chain.private_peers,
            str  "chain.sync_method"               => chain.sync_method,
            str  "chain.snapshot_url"              => chain.snapshot_url,
            str  "chain.entrypoint_url"            => chain.entrypoint_url,
            str  "chain.faucet_domain"             => chain.faucet_domain,
            str  "images.node"                    => images.node,
            str  "images.minio"                   => images.minio,
            str  "images.relayer"                 => images.relayer,
            str  "images.argus"                   => images.argus,
            str  "akash.rpc"                      => akash.rpc,
            str  "akash.grpc"                     => akash.grpc,
            str  "akash.rest"                     => akash.rest,
            str  "dns.cf_token"                   => dns.cf_token,
            str  "dns.cf_zone"                    => dns.cf_zone,
            u16  "ssh.port"                       => ssh.port,
            str  "ssh.pubkey"                     => ssh.pubkey,
            str  "snapshot.domain"                => snapshot.domain,
            str  "snapshot.path"                  => snapshot.path,
            str  "snapshot.schedule"              => snapshot.schedule,
            str  "snapshot.format"                => snapshot.format,
            str  "snapshot.retain"                => snapshot.retain,
            u32  "snapshot.keep_last"             => snapshot.keep_last,
            str  "nodes.snapshot.domain"          => nodes.snapshot.domain,
            str  "nodes.seed.domain"              => nodes.seed.domain,
            str  "nodes.left_tackle.domain"       => nodes.left_tackle.domain,
            str  "nodes.right_tackle.domain"      => nodes.right_tackle.domain,
            str  "nodes.left_forward.domain"      => nodes.left_forward.domain,
            str  "nodes.right_forward.domain"     => nodes.right_forward.domain,
            str  "relayer.key_name"               => relayer.key_name,
            str  "relayer.remote_chain"           => relayer.remote_chain,
            str  "relayer.domain"                 => relayer.domain,
            str  "relayer.key_terp"               => relayer.key_terp,
            str  "relayer.key_remote"             => relayer.key_remote,
            str  "relayer.entrypoint"             => relayer.entrypoint,
            str  "argus.node_moniker"             => argus.node_moniker,
            str  "argus.node_seeds"               => argus.node_seeds,
            str  "argus.node_persistent_peers"    => argus.node_persistent_peers,
            str  "argus.image"                    => argus.image,
            str  "argus.entrypoint_url"           => argus.entrypoint_url,
            str  "argus.api_domain"               => argus.api_domain,
            str  "argus.bech32_prefix"            => argus.bech32_prefix,
            str  "argus.db_user"                  => argus.db_user,
            str  "argus.db_password"              => argus.db_password,
            str  "argus.db_data_name"             => argus.db_data_name,
            str  "argus.db_accounts_name"         => argus.db_accounts_name,
            str  "registry.url"                   => registry.url,
            u16  "registry.port"                  => registry.port,
            str  "registry.username"              => registry.username,
            str  "registry.password"              => registry.password,
            str  "registry.storage_dir"           => registry.storage_dir,
            str  "sites.gateway_domain"           => sites.gateway_domain,
            str  "sites.s3_domain"                => sites.s3_domain,
            str  "sites.console_domain"           => sites.console_domain,
            u32  "minio.autopin_interval"         => minio.autopin_interval,
        })
    }

    /// Check if a given env var name corresponds to a secret field.
    pub fn is_secret_env(env_var: &str) -> bool {
        for f in CONFIG_FIELDS {
            if env_key(f.path) == env_var && f.is_secret {
                return true;
            }
        }
        // Also check legacy env var names
        matches!(env_var, "OLINE_CF_API_TOKEN" | "RLY_KEY_TERP" | "RLY_KEY_REMOTE"
            | "ARGUS_DB_PASSWORD" | "OLINE_REGISTRY_PASSWORD")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_key_derivation() {
        assert_eq!(env_key("chain.id"), "OLINE_CHAIN_ID");
        assert_eq!(env_key("images.node"), "OLINE_IMAGES_NODE");
        assert_eq!(env_key("nodes.snapshot.domain"), "OLINE_NODES_SNAPSHOT_DOMAIN");
        assert_eq!(env_key("akash.rpc"), "OLINE_AKASH_RPC");
    }

    #[test]
    fn test_subdomain_derivation() {
        // Simple domain → dot prefix
        assert_eq!(TomlConfig::derive_subdomain("rpc", "terp.network"), "rpc.terp.network");
        assert_eq!(TomlConfig::derive_subdomain("api", "terp.network"), "api.terp.network");
        assert_eq!(TomlConfig::derive_subdomain("peer", "terp.network"), "peer.terp.network");

        // Structured domain → dash prefix
        assert_eq!(TomlConfig::derive_subdomain("rpc", "mainnet.terp.network"), "rpc-mainnet.terp.network");
        assert_eq!(TomlConfig::derive_subdomain("api", "mainnet.terp.network"), "api-mainnet.terp.network");

        // Empty → empty
        assert_eq!(TomlConfig::derive_subdomain("rpc", ""), "");
    }

    #[test]
    fn test_defaults_produce_sdl_vars() {
        let cfg = TomlConfig::from_defaults();
        let vars = cfg.to_sdl_vars();
        assert_eq!(vars.get("OLINE_CHAIN_ID").unwrap(), "morocco-1");
        assert_eq!(vars.get("OLINE_BINARY").unwrap(), "terpd");
        assert_eq!(vars.get("OMNIBUS_IMAGE").unwrap(), "ghcr.io/terpnetwork/terp-core:v5.1.6-oline");
        assert_eq!(vars.get("SSH_P").unwrap(), "22");
        assert_eq!(vars.get("RPC_P_SNAP").unwrap(), "26657");
        assert_eq!(vars.get("P2P_P_SEED").unwrap(), "26656");
    }

    #[test]
    fn test_deep_merge_scalars() {
        let mut base = toml::toml! {
            [chain]
            id = "default-chain"
            binary = "terpd"
        };
        let overlay = toml::toml! {
            [chain]
            id = "morocco-1"
        };
        deep_merge(&mut toml::Value::Table(base.clone()), &toml::Value::Table(overlay));
        // Re-test via ProfiledTomlConfig round-trip
        let toml_str = r#"
[chain]
id = "default"
binary = "terpd"

[profiles.mainnet.chain]
id = "morocco-1"
"#;
        let profiled: ProfiledTomlConfig = toml::from_str(toml_str).unwrap();
        let resolved = profiled.resolve("mainnet").unwrap();
        assert_eq!(resolved.chain.id, "morocco-1");
        assert_eq!(resolved.chain.binary, "terpd");
    }

    #[test]
    fn test_profiled_config_resolve() {
        let toml_str = r#"
[chain]
id = "default"
binary = "terpd"

[images]
node = "ghcr.io/terpnetwork/terp-core:5.1.8-oline"

[profiles.mainnet.chain]
id = "morocco-1"

[profiles.testnet.chain]
id = "athena-4"
"#;
        let profiled: ProfiledTomlConfig = toml::from_str(toml_str).unwrap();
        let mainnet = profiled.clone().resolve("mainnet").unwrap();
        assert_eq!(mainnet.chain.id, "morocco-1");
        assert_eq!(mainnet.chain.binary, "terpd");
        assert_eq!(mainnet.images.node, "ghcr.io/terpnetwork/terp-core:5.1.8-oline");

        let testnet = profiled.resolve("testnet").unwrap();
        assert_eq!(testnet.chain.id, "athena-4");
        assert_eq!(testnet.chain.binary, "terpd");
    }

    #[test]
    fn test_profiled_missing_profile_falls_back() {
        let toml_str = r#"
[chain]
id = "default-id"
binary = "terpd"

[profiles.mainnet.chain]
id = "morocco-1"
"#;
        let profiled: ProfiledTomlConfig = toml::from_str(toml_str).unwrap();
        let resolved = profiled.resolve("nonexistent").unwrap();
        assert_eq!(resolved.chain.id, "default-id"); // base value, no crash
    }

}
