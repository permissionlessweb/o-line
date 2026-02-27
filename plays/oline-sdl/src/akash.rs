//! Helpers to inject variables and values into the sdls via use of akash-deploy-rs SDL feature: https://github.com/permissionlessweb/akash-deploy-rs/blob/main/src/sdl/template.rs
use crate::config::OLineConfig;
use crate::crypto::{gen_ssh_key, generate_credential, S3_KEY, S3_SECRET};
use crate::snapshots::fetch_latest_snapshot_url;
use std::{collections::HashMap, env::var};

/// Extract the hostname (without scheme or port) from a ServiceEndpoint URI.
/// e.g. "https://abc.provider.com" → "abc.provider.com"
///      "http://host:8080"         → "host"
///      "host:8080"                → "host"
pub fn endpoint_hostname(uri: &str) -> &str {
    let s = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    // Strip port if present
    s.split(':').next().unwrap_or(s)
}

/// Helper to insert the shared SDL template variables into a HashMap.
/// All values come from the config struct so interactively-entered values
/// are used, not just env vars that happened to be set at launch.
pub fn insert_sdl_defaults(vars: &mut HashMap<String, String>, config: &OLineConfig) {
    vars.insert("OMNIBUS_IMAGE".into(), config.val("default.omnibus_image"));
    vars.insert("CHAIN_JSON".into(),    config.val("chain.chain_json"));
    vars.insert("ADDRBOOK_URL".into(),  config.val("chain.addrbook_url"));
    vars.insert("TLS_CONFIG_URL".into(), config.val("cloudflare.tls_config_url"));
    vars.insert("CHAIN_ID".into(),      config.val("chain.chain_id"));
}

/// reusable helper for defining the domain url & ports for each oline step
pub fn insert_nodes_sdl_variables(
    vars: &mut HashMap<String, String>,
    config: &OLineConfig,
    suffix: &str,
) {
    let suffix_lower = suffix.to_lowercase();
    let (p2p_port, rpc_port, api_port, grpc_port) = (
        format!("P2P_PORT_{}", suffix),
        format!("RPC_PORT_{}", suffix),
        format!("API_PORT_{}", suffix),
        format!("GRPC_PORT_{}", suffix),
    );
    let (p2p_domain, rpc_domain, api_domain, grpc_domain) = (
        format!("P2P_DOMAIN_{}", suffix),
        format!("RPC_DOMAIN_{}", suffix),
        format!("API_DOMAIN_{}", suffix),
        format!("GRPC_DOMAIN_{}", suffix),
    );

    // Env var with fallback to saved config (for fields declared in SPECIAL_TEAMS_FD).
    // Phase B/C suffixes have no matching config keys and will fall back to "" as before.
    let cfg = |env_key: &str, field: &str| {
        var(env_key)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| config.val(&format!("special_teams.{}_{}", suffix_lower, field)))
    };

    vars.insert(p2p_port.clone(),    cfg(&p2p_port,    "p2p_port"));
    vars.insert(p2p_domain.clone(),  cfg(&p2p_domain,  "p2p_domain"));
    vars.insert(rpc_port.clone(),    cfg(&rpc_port,    "rpc_port"));
    vars.insert(rpc_domain.clone(),  cfg(&rpc_domain,  "rpc_domain"));
    vars.insert(api_port.clone(),    cfg(&api_port,    "api_port"));
    vars.insert(api_domain.clone(),  cfg(&api_domain,  "api_domain"));
    vars.insert(grpc_port.clone(),   cfg(&grpc_port,   "grpc_port"));
    vars.insert(grpc_domain.clone(), cfg(&grpc_domain, "grpc_domain"));
    vars.insert("ENTRYPOINT_URL".into(), config.val("cloudflare.entrypoint_url"));
    vars.insert("SSH_PORT".into(), var("SSH_PORT").unwrap_or("22".to_string()));
}

/// Build a refresh vars map for a specific node by adding unsuffixed TLS service vars
/// (`RPC_DOMAIN`, `RPC_PORT`, etc.) derived from the suffixed SDL vars
/// (`RPC_DOMAIN_{SUFFIX}`, `RPC_PORT_{SUFFIX}`, ...).
///
/// `verify_certs_and_signal_start` patches `/tmp/oline-env.sh` using this map.
/// Without this mapping the domain/port vars would never be refreshed — `a_vars` only
/// stores the suffixed form, but `REFRESH_VARS` in crypto.rs looks for unsuffixed keys.
pub fn node_refresh_vars(sdl_vars: &HashMap<String, String>, suffix: &str) -> HashMap<String, String> {
    let mut out = sdl_vars.clone();
    for field in ["RPC", "API", "GRPC", "P2P"] {
        for role in ["DOMAIN", "PORT"] {
            let src = format!("{}_{}_{}", field, role, suffix);
            let dst = format!("{}_{}", field, role);
            if let Some(v) = sdl_vars.get(&src) {
                out.insert(dst, v.clone());
            }
        }
    }
    out
}

/// Helper to insert S3 snapshot export variables.
/// `s3_key`, `s3_secret`, and `s3_host` are generated/derived at deploy time.
pub async fn insert_s3_vars(
    vars: &mut HashMap<String, String>,
    c: &OLineConfig,
    s3_key: &str,
    s3_secret: &str,
    s3_host: &str,
) {
    vars.insert("S3_KEY".into(), s3_key.to_string());
    vars.insert("S3_SECRET".into(), s3_secret.to_string());
    vars.insert("S3_HOST".into(), s3_host.to_string());
    vars.insert("SNAPSHOT_PATH".into(), c.val("snapshot.path"));
    vars.insert("SNAPSHOT_TIME".into(), c.val("snapshot.time"));
    vars.insert("SNAPSHOT_SAVE_FORMAT".into(), c.val("snapshot.save_format"));
    vars.insert("SNAPSHOT_RETAIN".into(), c.val("snapshot.retain"));
    vars.insert("SNAPSHOT_KEEP_LAST".into(), c.val("snapshot.keep_last"));
    // Metadata URL uses the public download domain so URLs in snapshot.json are externally accessible
    let dd = c.val("snapshot.download_domain");
    let meta_url = format!(
        "https://{}/{}/snapshot.json",
        dd,
        c.val("snapshot.path").trim_matches('/')
    );
    vars.insert("SNAPSHOT_METADATA_URL".into(), meta_url);
    vars.insert("SNAPSHOT_DOWNLOAD_DOMAIN".into(), dd);
    vars.insert(
        "OLINE_SNAPSHOT_DOWNLOAD_DOMAIN".into(),
        var("OLINE_SNAPSHOT_DOWNLOAD_DOMAIN").unwrap_or_default(),
    );
    vars.insert(
        "SNAPSHOT_URL".into(),
        fetch_latest_snapshot_url(&c.val("snapshot.state_url"), &c.val("snapshot.base_url"))
            .await
            .unwrap(),
    );
}

/// Helper to insert minio-ipfs variables.
/// `root_user` and `root_password` are the auto-generated credentials
/// shared between the snapshot node (as S3_KEY/S3_SECRET) and MinIO.
pub fn insert_minio_vars(
    vars: &mut HashMap<String, String>,
    c: &OLineConfig,
    root_user: &str,
    root_password: &str,
) {
    vars.insert("MINIO_SVC".into(), "oline-a-minio-ipfs".into());
    vars.insert("MINIO_IPFS_IMAGE".into(), c.val("minio.image"));
    // Derive MINIO_BUCKET from snapshot_path (first path component, e.g. "snapshots" from "snapshots/terpnetwork")
    let minio_bucket = c
        .val("snapshot.path")
        .split('/')
        .next()
        .unwrap_or("snapshots")
        .to_string();
    vars.insert("MINIO_BUCKET".into(), minio_bucket);
    vars.insert(
        "AUTOPIN_INTERVAL".into(),
        c.val("minio.autopin_interval").clone(),
    );
    vars.insert("MINIO_ROOT_USER".into(), root_user.to_string());
    vars.insert("MINIO_ROOT_PASSWORD".into(), root_password.to_string());
}

// ── SDL variable builders ──
pub async fn build_phase_a_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    vars.insert("SNAPSHOT_SVC".into(), "oline-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a-seed".into());
    vars.insert(
        "SNAPSHOT_MONIKER".into(),
        "oline::special::snapshot-node".into(),
    );
    vars.insert("SEED_MONIKER".into(), "oline::special::seed-node".into());
    insert_nodes_sdl_variables(&mut vars, config, "SNAPSHOT");
    insert_nodes_sdl_variables(&mut vars, config, "SEED");
    insert_sdl_defaults(&mut vars, config);
    let s3_key = generate_credential(S3_KEY);
    let s3_secret = generate_credential(S3_SECRET);
    let s3_host = config.val("snapshot.download_domain").clone();
    insert_s3_vars(&mut vars, config, &s3_key, &s3_secret, &s3_host).await;
    insert_minio_vars(&mut vars, config, &s3_key, &s3_secret);
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.val("validator.peer_id").clone(),
    );

    // generate ssh-key
    let ssh_key = gen_ssh_key();
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());
    vars.insert(
        "SSH_PRIVKEY".into(),
        ssh_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string(),
    );
    // save ssh-key to secrets
    vars
}

pub fn build_phase_b_vars(
    config: &OLineConfig,
    snapshot_peer: &str,
    snapshot_url: &str,
    statesync_rpc_servers: &str,
) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, config);
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        snapshot_peer.to_string(),
    );
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.val("validator.peer_id"),
    );
    vars.insert(
        "TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(),
        config.val("validator.peer_id"),
    );
    vars.insert("SNAPSHOT_URL".into(), snapshot_url.to_string());
    vars.insert(
        "SNAPSHOT_SAVE_FORMAT".into(),
        config.val("snapshot.save_format"),
    );
    // Statesync — use both A1 snapshot RPC and A1 seed RPC so tackles can
    // sync to the network quickly without waiting for a full replay.
    if !statesync_rpc_servers.is_empty() {
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
        vars.insert(
            "STATESYNC_RPC_SERVERS".into(),
            statesync_rpc_servers.to_string(),
        );
    }
    vars
}

pub fn build_phase_c_vars(
    config: &OLineConfig,
    seed_peer: &str,
    snapshot_peer: &str,
    left_tackle_peer: &str,
    right_tackle_peer: &str,
) -> HashMap<String, String> {
    let tackles_combined = format!("{},{}", left_tackle_peer, right_tackle_peer);
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, config);
    vars.insert("TERPD_P2P_SEEDS".into(), format!("{} ", seed_peer));
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        tackles_combined.clone(),
    );
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), tackles_combined);
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        format!("{} ", snapshot_peer),
    );
    vars
}
