//! Helpers to inject variables and values into the sdls via use of akash-deploy-rs SDL feature: https://github.com/permissionlessweb/akash-deploy-rs/blob/main/src/sdl/template.rs
use crate::config::OLineConfig;
use crate::crypto::{gen_ssh_key, generate_credential, save_ssh_key, S3_KEY, S3_SECRET};
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
pub fn insert_sdl_defaults(vars: &mut std::collections::HashMap<String, String>) {
    vars.insert(
        "OMNIBUS_IMAGE".into(),
        std::env::var("OMNIBUS_IMAGE").expect("omnibus image"),
    );
    vars.insert(
        "CHAIN_JSON".into(),
        std::env::var("OLINE_CHAIN_JSON").expect("chain json"),
    );
    vars.insert(
        "ADDRBOOK_URL".into(),
        std::env::var("OLINE_ADDRBOOK_URL").expect("addrbook"),
    );
    vars.insert(
        "TLS_CONFIG_URL".into(),
        var("TLS_CONFIG_URL").unwrap_or_default(),
    );
}

/// reusable helper for defining the domain url & ports for each oline step
pub fn insert_nodes_sdl_variables(
    vars: &mut std::collections::HashMap<String, String>,
    suffix: &str,
) {
    let (p2p_port, rpc_port, api_port, grpc_port) = (
        format!("{}_{}", "P2P_PORT", suffix),
        format!("{}_{}", "RPC_PORT", suffix),
        format!("{}_{}", "API_PORT", suffix),
        format!("{}_{}", "GRPC_PORT", suffix),
    );
    let (p2p_domain, rpc_domain, api_domain, grpc_domain) = (
        format!("{}_{}", "P2P_DOMAIN", suffix),
        format!("{}_{}", "RPC_DOMAIN", suffix),
        format!("{}_{}", "API_DOMAIN", suffix),
        format!("{}_{}", "GRPC_DOMAIN", suffix),
    );

    vars.insert(p2p_port.clone(), var(p2p_port).unwrap_or_default());
    vars.insert(p2p_domain.clone(), var(p2p_domain).unwrap_or_default());
    vars.insert(rpc_port.clone(), var(rpc_port).unwrap_or_default());
    vars.insert(rpc_domain.clone(), var(rpc_domain).unwrap_or_default());
    vars.insert(api_port.clone(), var(api_port).unwrap_or_default());
    vars.insert(api_domain.clone(), var(api_domain).unwrap_or_default());
    vars.insert(grpc_port.clone(), var(grpc_port).unwrap_or_default());
    vars.insert(grpc_domain.clone(), var(grpc_domain).unwrap_or_default());
    vars.insert(
        "ENTRYPOINT_URL".into(),
        var("ENTRYPOINT_URL").unwrap_or_default(),
    );
    vars.insert(
        "SSH_PORT".into(),
        var("SSH_PORT").unwrap_or("22".to_string()),
    );
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
    insert_nodes_sdl_variables(&mut vars, "SNAPSHOT");
    insert_nodes_sdl_variables(&mut vars, "SEED");
    insert_sdl_defaults(&mut vars);
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
    insert_sdl_defaults(&mut vars);
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
    seed_peer: &str,
    snapshot_peer: &str,
    left_tackle_peer: &str,
    right_tackle_peer: &str,
) -> HashMap<String, String> {
    let tackles_combined = format!("{},{}", left_tackle_peer, right_tackle_peer);
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars);
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
