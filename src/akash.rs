//! SDL variable injection for Akash deployment phases.
//!
//! Each `build_phase_*_vars()` function:
//!   1. Calls `config.to_sdl_vars()` — auto-injects ALL FIELD_DESCRIPTOR values
//!      keyed by `fd.ev` (the env var name).  SDL templates must use `${fd.ev}`.
//!   2. Inserts **computed / runtime** variables that cannot come from the config:
//!      service names, random monikers, SSH keypairs, S3 credentials, accept lists,
//!      peer IDs collected from earlier phases, statesync servers, etc.
//!
//! To add a new SDL variable backed by a field descriptor:
//!   1. Add an `Fd` entry to the relevant `*_FD` constant in `lib.rs`.
//!   2. Reference `${fd.ev}` in the SDL template.
//!   Done — no code change needed here.
use crate::config::OLineConfig;
use crate::crypto::{ensure_ssh_key, gen_ssh_key, generate_credential, S3_KEY, S3_SECRET};
use std::collections::HashMap;
use std::path::PathBuf;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the hostname (without scheme or port) from a ServiceEndpoint URI.
pub fn endpoint_hostname(uri: &str) -> &str {
    let s = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    s.split(':').next().unwrap_or(s)
}

/// Build the YAML `accept:` list items for a service's port-80 ingress block.
///
/// Only RPC and API domains are included (GRPC uses a dedicated TLS NodePort).
/// Empty/unconfigured domains are filtered out.  Each line is indented with
/// 10 spaces to align under the `accept:` key.
pub fn build_accept_items(vars: &HashMap<String, String>, suffix: &str) -> String {
    ["RPC", "API"]
        .iter()
        .filter_map(|svc| {
            let key = format!("{}_DOMAIN_{}", svc, suffix);
            vars.get(&key)
                .filter(|v| !v.is_empty())
                .map(|v| format!("          - {}", v))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build unsuffixed refresh vars for a node (used by `verify_files_and_signal_start`
/// to patch `/tmp/oline-env.sh`).
pub fn node_refresh_vars(
    sdl_vars: &HashMap<String, String>,
    suffix: &str,
) -> HashMap<String, String> {
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

// ── Phase variable builders ───────────────────────────────────────────────────

/// Phase A: Kickoff Special Teams (snapshot node + seed node + MinIO).
///
/// `config.to_sdl_vars()` injects all FD-backed vars (chain, image, ports,
/// domains, snapshot settings, …).  Only computed/generated vars are explicit.
pub async fn build_phase_a_vars(
    config: &OLineConfig,
    secrets_path: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut vars = config.to_sdl_vars();

    // ── Static service names ──────────────────────────────────────────────────
    vars.insert("SNAPSHOT_SVC".into(), "oline-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a-seed".into());
    vars.insert("MINIO_SVC".into(), "oline-a-minio-ipfs".into());

    // ── Random monikers ───────────────────────────────────────────────────────
    vars.insert("SNAPSHOT_MONIKER".into(), generate_credential(12));
    vars.insert("SEED_MONIKER".into(), generate_credential(12));

    // ── SSH keypair (shared by snapshot + seed + minio for SFTP cert delivery) ─
    // Reuse existing key if present; generate fresh otherwise.
    let key_path: PathBuf = format!("{}/oline-parallel-key", secrets_path).into();
    let ssh_key = ensure_ssh_key(&key_path)?;
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());
    vars.insert(
        "SSH_PRIVKEY".into(),
        ssh_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string(),
    );
    vars.insert("SSH_KEY_PATH".into(), key_path.to_string_lossy().into());

    // ── S3 credentials (generated; shared by snapshot node + MinIO) ───────────
    let s3_key = generate_credential(S3_KEY);
    let s3_secret = generate_credential(S3_SECRET);
    vars.insert("S3_KEY".into(), s3_key.clone());
    vars.insert("S3_SECRET".into(), s3_secret.clone());
    // MinIO is on the Akash internal service network — plain HTTP, no-ssl flag.
    vars.insert("S3_HOST".into(), "oline-a-minio-ipfs:9000 --no-ssl".into());
    vars.insert("MINIO_ROOT_USER".into(), s3_key);
    vars.insert("MINIO_ROOT_PASSWORD".into(), s3_secret);

    // ── Derived vars ─────────────────────────────────────────────────────────
    let snapshot_path = config.val("OLINE_SNAPSHOT_PATH");
    let download_domain = config.val("OLINE_SNAPSHOT_DOWNLOAD_DOMAIN");
    // SNAPSHOT_METADATA_URL: base URL that snapshot.sh appends "/snapshot.json" to.
    vars.insert(
        "SNAPSHOT_METADATA_URL".into(),
        format!(
            "https://{}/{}",
            download_domain,
            snapshot_path.trim_matches('/')
        ),
    );
    // MINIO_BUCKET: first path segment of snapshot.path.
    vars.insert(
        "MINIO_BUCKET".into(),
        snapshot_path
            .split('/')
            .next()
            .unwrap_or("snapshots")
            .to_string(),
    );

    // ── Accept lists (must be after domain vars from to_sdl_vars()) ───────────
    vars.insert(
        "SNAPSHOT_80_ACCEPTS".into(),
        build_accept_items(&vars, "SNAPSHOT"),
    );
    vars.insert("SEED_80_ACCEPTS".into(), build_accept_items(&vars, "SEED"));
    // MinIO download domain accept — filter empty so SDL never gets `- null`.
    let minio_accepts = if download_domain.is_empty() {
        String::new()
    } else {
        format!("          - {}", download_domain)
    };
    vars.insert("MINIO_80_ACCEPTS".into(), minio_accepts);

    Ok(vars)
}

/// Phase B: Left & Right Tackles.
pub fn build_phase_b_vars(
    config: &OLineConfig,
    snapshot_peer: &str,
    statesync_rpc_servers: &str,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    // ── Static service names ──────────────────────────────────────────────────
    vars.insert("LT_SVC".into(), "oline-b-left-tackle".into());
    vars.insert("RT_SVC".into(), "oline-b-right-tackle".into());
    vars.insert("SEED_SVC".into(), "oline-a-seed".into());

    // ── Random monikers ───────────────────────────────────────────────────────
    vars.insert("LEFT_TACKLE_MONIKER".into(), generate_credential(12));
    vars.insert("RIGHT_TACKLE_MONIKER".into(), generate_credential(12));

    // ── SSH key for cert delivery (bootstrap) ─────────────────────────────────
    let ssh_key = gen_ssh_key();
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());

    // ── Runtime peer inputs ───────────────────────────────────────────────────
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        snapshot_peer.to_string(),
    );
    // Validator private peer ID (also from config, but keep for clarity)
    let validator_peer = config.val("OLINE_VALIDATOR_PEER_ID");
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), validator_peer.clone());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), validator_peer);

    // ── Statesync ─────────────────────────────────────────────────────────────
    // Always insert so ${STATESYNC_RPC_SERVERS} never errors; empty = disabled.
    vars.insert(
        "STATESYNC_RPC_SERVERS".into(),
        statesync_rpc_servers.to_string(),
    );
    if !statesync_rpc_servers.is_empty() {
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
    }

    // ── Snapshot JSON URL (resolved from minio metadata) ─────────────────────
    vars.insert(
        "SNAPSHOT_JSON".into(),
        format!(
            "https://{}/{}/snapshot.json",
            config.val("OLINE_SNAPSHOT_DOWNLOAD_DOMAIN"),
            config.val("OLINE_SNAPSHOT_PATH").trim_matches('/')
        ),
    );

    // ── Snapshot mode ──────────────────────────────────────────────────────
    // Parallel deploy: B/C nodes wait for SFTP snapshot delivery.
    vars.entry("SNAPSHOT_MODE".into()).or_insert_with(|| "sftp".into());

    // ── Offline mode ─────────────────────────────────────────────────────
    // Phase B nodes receive ALL data via SFTP — no internet downloads.
    vars.insert("OLINE_OFFLINE".into(), "1".into());

    // ── Accept lists ─────────────────────────────────────────────────────────
    vars.insert("LT_80_ACCEPTS".into(), build_accept_items(&vars, "TACKLE_L"));
    vars.insert("RT_80_ACCEPTS".into(), build_accept_items(&vars, "TACKLE_R"));

    vars
}

/// Phase C: Left & Right Forwards.
pub fn build_phase_c_vars(
    config: &OLineConfig,
    seed_peer: &str,
    snapshot_peer: &str,
    left_tackle_peer: &str,
    right_tackle_peer: &str,
    statesync_rpc: &str,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    // ── Static service names ──────────────────────────────────────────────────
    vars.insert("LF_SVC".into(), "oline-c-left-forward".into());
    vars.insert("RF_SVC".into(), "oline-c-right-forward".into());

    // ── Random monikers ───────────────────────────────────────────────────────
    vars.insert("LEFT_FORWARD_MONIKER".into(), generate_credential(12));
    vars.insert("RIGHT_FORWARD_MONIKER".into(), generate_credential(12));

    // ── SSH key for cert delivery (bootstrap) ─────────────────────────────────
    let ssh_key = gen_ssh_key();
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());

    // ── Runtime peer inputs ───────────────────────────────────────────────────
    let tackles_combined = format!("{},{}", left_tackle_peer, right_tackle_peer);
    vars.insert("TERPD_P2P_SEEDS".into(), format!("{} ", seed_peer));
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), tackles_combined.clone());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), tackles_combined);
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        format!("{} ", snapshot_peer),
    );

    // ── Statesync ─────────────────────────────────────────────────────────────
    vars.insert("STATESYNC_RPC_SERVERS".into(), statesync_rpc.to_string());
    if !statesync_rpc.is_empty() {
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
    }

    // ── Snapshot JSON URL ─────────────────────────────────────────────────────
    vars.insert(
        "SNAPSHOT_JSON".into(),
        format!(
            "https://{}/{}/snapshot.json",
            config.val("OLINE_SNAPSHOT_DOWNLOAD_DOMAIN"),
            config.val("OLINE_SNAPSHOT_PATH").trim_matches('/')
        ),
    );

    // ── Snapshot mode ──────────────────────────────────────────────────────
    vars.entry("SNAPSHOT_MODE".into()).or_insert_with(|| "sftp".into());

    // ── Offline mode ─────────────────────────────────────────────────────
    // Phase C nodes receive ALL data via SFTP — no internet downloads.
    vars.insert("OLINE_OFFLINE".into(), "1".into());

    // ── Accept lists ─────────────────────────────────────────────────────────
    vars.insert(
        "LF_80_ACCEPTS".into(),
        build_accept_items(&vars, "FORWARD_L"),
    );
    vars.insert(
        "RF_80_ACCEPTS".into(),
        build_accept_items(&vars, "FORWARD_R"),
    );

    vars
}

/// Phase E: IBC Relayer.
pub fn build_phase_rly_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    // ── SSH key for cert delivery (bootstrap) ─────────────────────────────────
    let ssh_key = gen_ssh_key();
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());
    vars.insert(
        "SSH_PRIVKEY".into(),
        ssh_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string(),
    );

    // ── Accept list for the relayer REST API ─────────────────────────────────
    let api_domain = config.val("RLY_API_DOMAIN");
    let rly_accepts = if api_domain.is_empty() {
        String::new()
    } else {
        format!("          - {}", api_domain)
    };
    vars.insert("RLY_80_ACCEPTS".into(), rly_accepts);

    vars
}

/// Phase G: Standalone MinIO-IPFS Gateway for static website hosting.
pub fn build_ipfs_site_vars(
    config: &OLineConfig,
    gateway_domain: &str,
    bucket: &str,
) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    // ── Static service name ───────────────────────────────────────────────────
    vars.insert("IPFS_SVC".into(), "oline-g-ipfs-gateway".into());

    // ── S3 credentials (generated fresh per deployment) ───────────────────────
    let s3_key = generate_credential(S3_KEY);
    let s3_secret = generate_credential(S3_SECRET);
    vars.insert("MINIO_ROOT_USER".into(), s3_key.clone());
    vars.insert("MINIO_ROOT_PASSWORD".into(), s3_secret.clone());
    vars.insert("S3_KEY".into(), s3_key);
    vars.insert("S3_SECRET".into(), s3_secret);

    // ── SSH keypair for pre-start file delivery ───────────────────────────────
    let ssh_key = gen_ssh_key();
    vars.insert("SSH_PUBKEY".into(), ssh_key.public_key().to_string());
    vars.insert(
        "SSH_PRIVKEY".into(),
        ssh_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string(),
    );

    // ── Bucket ────────────────────────────────────────────────────────────
    vars.insert("IPFS_BUCKET".into(), bucket.to_string());

    // ── Three Sites domains ───────────────────────────────────────────────
    let gw_domain = if gateway_domain.is_empty() {
        config.val("SITES_GATEWAY_DOMAIN")
    } else {
        gateway_domain.to_string()
    };
    let s3_domain = {
        let v = config.val("SITES_S3_DOMAIN");
        if v.is_empty() && !gw_domain.is_empty() {
            format!("s3-{}", gw_domain)
        } else {
            v
        }
    };
    let console_domain = {
        let v = config.val("SITES_CONSOLE_DOMAIN");
        if v.is_empty() && !gw_domain.is_empty() {
            format!("console-{}", gw_domain)
        } else {
            v
        }
    };

    vars.insert("SITES_GATEWAY_DOMAIN".into(), gw_domain.clone());
    vars.insert("SITES_S3_DOMAIN".into(), s3_domain.clone());
    vars.insert("SITES_CONSOLE_DOMAIN".into(), console_domain.clone());

    // ── Accept list for port 80 (all non-empty domains) ───────────────────
    let accepts: String = [&gw_domain, &s3_domain, &console_domain]
        .iter()
        .filter(|d| !d.is_empty())
        .map(|d| format!("          - {}", d))
        .collect::<Vec<_>>()
        .join("\n");
    vars.insert("SITES_80_ACCEPTS".into(), accepts);

    vars
}

/// Phase F: Argus Indexer.
pub fn build_phase_f_vars(config: &OLineConfig, statesync_rpc: &str) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();

    // ── Random moniker ────────────────────────────────────────────────────────
    vars.insert("ARGUS_NODE_MONIKER".into(), generate_credential(12));

    // ── Statesync ─────────────────────────────────────────────────────────────
    vars.insert("STATESYNC_RPC_SERVERS".into(), statesync_rpc.to_string());

    // ── Snapshot JSON URL ─────────────────────────────────────────────────────
    vars.insert(
        "SNAPSHOT_JSON".into(),
        format!(
            "https://{}/{}/snapshot.json",
            config.val("OLINE_SNAPSHOT_DOWNLOAD_DOMAIN"),
            config.val("OLINE_SNAPSHOT_PATH").trim_matches('/')
        ),
    );

    // ── Accept list for Argus REST API ────────────────────────────────────────
    let api_domain = config.val("ARGUS_API_DOMAIN");
    let argus_accepts = if api_domain.is_empty() {
        String::new()
    } else {
        format!("          - {}", api_domain)
    };
    vars.insert("ARGUS_80_ACCEPTS".into(), argus_accepts);

    vars
}
