//! Helpers to inject variables and values into the sdls via use of akash-deploy-rs SDL feature: https://github.com/permissionlessweb/akash-deploy-rs/blob/main/src/sdl/template.rs
use crate::config::OLineConfig;
use crate::crypto::{generate_credential, S3_KEY, S3_SECRET};
use crate::snapshots::{fetch_latest_snapshot_url, insert_minio_vars, insert_s3_vars};
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

// ── SDL variable builders ──
pub async fn build_phase_a_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let s3_key = generate_credential(S3_KEY);
    let s3_secret = generate_credential(S3_SECRET);
    let s3_host = config.val("snapshot.download_domain").clone();
    insert_sdl_defaults(&mut vars);
    insert_s3_vars(&mut vars, config, &s3_key, &s3_secret, &s3_host);
    insert_minio_vars(&mut vars, config, &s3_key, &s3_secret);
    insert_nodes_sdl_variables(&mut vars, "SNAPSHOT");
    insert_nodes_sdl_variables(&mut vars, "SEED");
    vars.insert(
        "SNAPSHOT_URL".into(),
        fetch_latest_snapshot_url(
            &config.val("snapshot.state_url"),
            &config.val("snapshot.base_url"),
        )
        .await
        .unwrap(),
    );
    vars.insert("SNAPSHOT_SVC".into(), "oline-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a-seed".into());
    vars.insert("MINIO_SVC".into(), "oline-a-minio-ipfs".into());
    vars.insert(
        "TLS_CONFIG_URL".into(),
        var("TLS_CONFIG_URL").unwrap_or_default(),
    );
    vars.insert(
        "SNAPSHOT_MONIKER".into(),
        "oline::special::snapshot-node".into(),
    );
    vars.insert("SEED_MONIKER".into(), "oline::special::seed-node".into());
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.val("validator.peer_id").clone(),
    );
    vars.insert(
        "OLINE_SNAPSHOT_DOWNLOAD_DOMAIN".into(),
        var("OLINE_SNAPSHOT_DOWNLOAD_DOMAIN").unwrap_or_default(),
    );
    vars.insert(
        "MINIO_ROOT_USER".into(),
        var("MINIO_ROOT_USER").unwrap_or_default(),
    );
    vars.insert(
        "MINIO_ROOT_PASSWORD".into(),
        var("MINIO_ROOT_PASSWORD").unwrap_or_default(),
    );
    vars.insert(
        "MINIO_BUCKET".into(),
        var("MINIO_BUCKET").unwrap_or_default(),
    );
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
