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
use crate::crypto::{ensure_ssh_key_encrypted, gen_ssh_key, generate_credential, S3_KEY, S3_SECRET};
use std::collections::HashMap;
use std::path::PathBuf;

// ── Statesync trust param auto-fetch ─────────────────────────────────────────

/// Fetch statesync trust height and hash from a CometBFT RPC endpoint.
///
/// Takes a statesync RPC string (format: `"host:port,host:port"`), queries
/// the first server's `/block` for latest height, subtracts 1000, then
/// fetches the block hash at that height via `/block?height=N`.
pub async fn fetch_statesync_trust_params(rpc: &str) -> Result<(String, String), String> {
    let server = rpc.split(',').next().unwrap_or(rpc).trim();
    if server.is_empty() {
        return Err("empty RPC address".into());
    }
    let base = if server.starts_with("http") {
        server.to_string()
    } else {
        format!("http://{}", server)
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    // Latest block height
    let body: serde_json::Value = client
        .get(format!("{}/block", base))
        .send()
        .await
        .map_err(|e| format!("block request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("parse block: {e}"))?;

    let latest_height: u64 = body["result"]["block"]["header"]["height"]
        .as_str()
        .ok_or("missing latest_block_height")?
        .parse()
        .map_err(|e| format!("parse height: {e}"))?;

    let trust_height = latest_height.saturating_sub(1000);
    if trust_height == 0 {
        return Err(format!("chain too young: latest_height={latest_height}"));
    }

    // Block hash at trust height
    let body: serde_json::Value = client
        .get(format!("{}/block?height={}", base, trust_height))
        .send()
        .await
        .map_err(|e| format!("block?height request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("parse block hash: {e}"))?;

    let hash = body["result"]["block_id"]["hash"]
        .as_str()
        .ok_or("missing block hash")?
        .to_string();

    Ok((trust_height.to_string(), hash))
}

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
            let key = format!("{}_D_{}", svc, suffix);
            vars.get(&key)
                .filter(|v| !v.is_empty())
                .map(|v| format!("          - {}", v))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build unsuffixed refresh vars for a node (used by `verify_files_and_signal_start`
/// to patch `/tmp/oline-env.sh`).
///
/// Maps suffixed FD vars (e.g. `RPC_D_SNAP`) to the unsuffixed names that
/// `REFRESH_VARS` in crypto.rs expects (e.g. `RPC_DOMAIN`, `API_D`, `P2P_P`).
///
/// Note: RPC uses `RPC_DOMAIN` (not `RPC_D`) because `config-node-endpoints.sh`
/// and `oline-entrypoint.sh` read `$RPC_DOMAIN` inside the container.
pub fn node_refresh_vars(
    sdl_vars: &HashMap<String, String>,
    suffix: &str,
) -> HashMap<String, String> {
    let mut out = sdl_vars.clone();
    for field in ["RPC", "API", "GRPC", "P2P"] {
        for role in ["D", "P"] {
            let src = format!("{}_{}_{}", field, role, suffix);
            // RPC domain is RPC_DOMAIN in containers (not RPC_D)
            let dst = if field == "RPC" && role == "D" {
                "RPC_DOMAIN".to_string()
            } else {
                format!("{}_{}", field, role)
            };
            if let Some(v) = sdl_vars.get(&src) {
                out.insert(dst, v.clone());
            }
        }
    }
    out
}

/// Inject the Akash-assigned external NodePort for P2P into refresh vars.
///
/// Akash maps SDL ports to random NodePorts (e.g. internal 26656 → external 32202).
/// `config-node-endpoints.sh` uses `P2P_EXT_PORT` for `external_address` so remote
/// peers connect on the correct port. Without this, the node would advertise the
/// internal port (26656) which may not be reachable from outside.
pub fn inject_p2p_nodeport(
    vars: &mut HashMap<String, String>,
    endpoints: &[akash_deploy_rs::ServiceEndpoint],
    service: &str,
) {
    let p2p_port: u16 = vars
        .get("P2P_P")
        .and_then(|s| s.parse().ok())
        .unwrap_or(26656);
    if let Some(ep) = endpoints
        .iter()
        .find(|e| e.service == service && e.internal_port == p2p_port)
    {
        vars.insert("P2P_EXT_PORT".to_string(), ep.port.to_string());
        tracing::debug!(
            "  [p2p] {} NodePort: internal {} → external {}",
            service, p2p_port, ep.port,
        );
    }
}

// ── Phase variable builders ───────────────────────────────────────────────────

/// Phase A: Kickoff Special Teams (snapshot node + seed node + MinIO).
///
/// `config.to_sdl_vars()` injects all FD-backed vars (chain, image, ports,
/// domains, snapshot settings, …).  Only computed/generated vars are explicit.
pub async fn build_phase_a_vars(
    config: &OLineConfig,
    secrets_path: &str,
    password: &str,
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
    // Reuse existing key if present; generate fresh otherwise. Stored encrypted.
    let key_path: PathBuf = format!("{}/oline-parallel-key", secrets_path).into();
    let ssh_key = ensure_ssh_key_encrypted(&key_path, password)?;
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
    let snapshot_path = config.val("OLINE_SNAP_PATH");
    let download_domain = config.val("OLINE_SNAP_DOWNLOAD_DOMAIN");
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

    // ── Sync method (unified) ─────────────────────────────────────────────────
    // OLINE_SYNC_METHOD controls everything. Default: "snapshot".
    //   snapshot   → SNAPSHOT_URL set, STATESYNC_* cleared
    //   statesync  → STATESYNC_* set, SNAPSHOT_URL cleared
    let sync_method = config.val("OLINE_SYNC_METHOD");
    if sync_method == "statesync" {
        // Statesync mode — clear all snapshot vars, set statesync vars
        vars.insert("OLINE_SNAPSHOT_URL".into(), String::new());
        vars.insert("OLINE_SNAP_STATE_URL".into(), String::new());
        vars.insert("OLINE_SNAP_BASE_URL".into(), String::new());
        vars.insert("SNAPSHOT_JSON".into(), String::new());
        vars.insert("SNAPSHOT_URL".into(), String::new());
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
        vars.insert("STATESYNC_RPC_SERVERS".into(), config.val("STATESYNC_RPC_SERVERS"));
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), config.val("STATESYNC_TRUST_HEIGHT"));
        vars.insert("STATESYNC_TRUST_HASH".into(), config.val("STATESYNC_TRUST_HASH"));
        vars.insert("STATESYNC_TRUST_PERIOD".into(), config.val("STATESYNC_TRUST_PERIOD"));
    } else {
        // Snapshot mode (default) — clear all statesync vars, ensure SNAPSHOT_URL is set
        vars.insert("STATESYNC_RPC_SERVERS".into(), String::new());
        vars.insert("STATESYNC_ENABLE".into(), "false".into());
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), String::new());
        vars.insert("STATESYNC_TRUST_HASH".into(), String::new());
        vars.insert("STATESYNC_TRUST_PERIOD".into(), String::new());
        // Ensure SNAPSHOT_URL is populated (from OLINE_SNAPSHOT_URL or SNAPSHOT_URL env)
        let snap_url = config.val("OLINE_SNAPSHOT_URL");
        if !snap_url.is_empty() {
            vars.insert("SNAPSHOT_URL".into(), snap_url);
        }
    }

    // ── Accept lists (must be after domain vars from to_sdl_vars()) ───────────
    vars.insert(
        "SNAPSHOT_80_ACCEPTS".into(),
        build_accept_items(&vars, "SNAP"),
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

    // ── Sync method (snapshot vs statesync) ─────────────────────────────────
    let sync_method = config.val("OLINE_SYNC_METHOD");
    if sync_method == "statesync" {
        // Statesync: node fetches state from RPC servers
        let rpc = if statesync_rpc_servers.is_empty() {
            config.val("STATESYNC_RPC_SERVERS")
        } else {
            statesync_rpc_servers.to_string()
        };
        vars.insert("STATESYNC_RPC_SERVERS".into(), rpc);
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), config.val("STATESYNC_TRUST_HEIGHT"));
        vars.insert("STATESYNC_TRUST_HASH".into(), config.val("STATESYNC_TRUST_HASH"));
        vars.insert("STATESYNC_TRUST_PERIOD".into(), config.val("STATESYNC_TRUST_PERIOD"));
        vars.insert("OLINE_OFFLINE".into(), "0".into());
        vars.insert("SNAPSHOT_MODE".into(), "".into());
        // Clear snapshot download vars — statesync nodes don't need them.
        vars.insert("OLINE_SNAPSHOT_URL".into(), String::new());
        vars.insert("SNAPSHOT_URL".into(), String::new());
    } else {
        // Snapshot (default): SFTP delivery, no internet
        vars.insert("STATESYNC_RPC_SERVERS".into(), String::new());
        vars.insert("STATESYNC_ENABLE".into(), "false".into());
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), String::new());
        vars.insert("STATESYNC_TRUST_HASH".into(), String::new());
        vars.insert("STATESYNC_TRUST_PERIOD".into(), String::new());
        vars.entry("SNAPSHOT_MODE".into()).or_insert_with(|| "sftp".into());
        vars.insert("OLINE_OFFLINE".into(), "1".into());
    }

    // ── Snapshot JSON URL (only needed in snapshot mode) ─────────────────────
    if sync_method != "statesync" {
        vars.insert(
            "SNAPSHOT_JSON".into(),
            format!(
                "https://{}/{}/snapshot.json",
                config.val("OLINE_SNAP_DOWNLOAD_DOMAIN"),
                config.val("OLINE_SNAP_PATH").trim_matches('/')
            ),
        );
    } else {
        vars.insert("SNAPSHOT_JSON".into(), String::new());
    }

    // ── Accept lists ─────────────────────────────────────────────────────────
    vars.insert("LT_80_ACCEPTS".into(), build_accept_items(&vars, "TL"));
    vars.insert("RT_80_ACCEPTS".into(), build_accept_items(&vars, "TR"));

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
    vars.insert("LEFT_FMONIKER".into(), generate_credential(12));
    vars.insert("RIGHT_FMONIKER".into(), generate_credential(12));

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

    // ── Sync method (snapshot vs statesync) ─────────────────────────────────
    let sync_method = config.val("OLINE_SYNC_METHOD");
    if sync_method == "statesync" {
        // Statesync: node fetches state from RPC servers
        let rpc = if statesync_rpc.is_empty() {
            config.val("STATESYNC_RPC_SERVERS")
        } else {
            statesync_rpc.to_string()
        };
        vars.insert("STATESYNC_RPC_SERVERS".into(), rpc);
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), config.val("STATESYNC_TRUST_HEIGHT"));
        vars.insert("STATESYNC_TRUST_HASH".into(), config.val("STATESYNC_TRUST_HASH"));
        vars.insert("STATESYNC_TRUST_PERIOD".into(), config.val("STATESYNC_TRUST_PERIOD"));
        vars.insert("OLINE_OFFLINE".into(), "0".into());
        vars.insert("SNAPSHOT_MODE".into(), "".into());
        // Clear snapshot download vars — statesync nodes don't need them.
        vars.insert("OLINE_SNAPSHOT_URL".into(), String::new());
        vars.insert("SNAPSHOT_URL".into(), String::new());
    } else {
        // Snapshot (default): SFTP delivery, no internet
        vars.insert("STATESYNC_RPC_SERVERS".into(), String::new());
        vars.insert("STATESYNC_ENABLE".into(), "false".into());
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), String::new());
        vars.insert("STATESYNC_TRUST_HASH".into(), String::new());
        vars.insert("STATESYNC_TRUST_PERIOD".into(), String::new());
        vars.entry("SNAPSHOT_MODE".into()).or_insert_with(|| "sftp".into());
        vars.insert("OLINE_OFFLINE".into(), "1".into());
    }

    // ── Snapshot JSON URL (only needed in snapshot mode) ─────────────────────
    if sync_method != "statesync" {
        vars.insert(
            "SNAPSHOT_JSON".into(),
            format!(
                "https://{}/{}/snapshot.json",
                config.val("OLINE_SNAP_DOWNLOAD_DOMAIN"),
                config.val("OLINE_SNAP_PATH").trim_matches('/')
            ),
        );
    } else {
        vars.insert("SNAPSHOT_JSON".into(), String::new());
    }

    // ── Accept lists ─────────────────────────────────────────────────────────
    vars.insert(
        "LF_80_ACCEPTS".into(),
        build_accept_items(&vars, "FL"),
    );
    vars.insert(
        "RF_80_ACCEPTS".into(),
        build_accept_items(&vars, "FR"),
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
    let api_domain = config.val("RLY_API_D");
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
    let rpc = if statesync_rpc.is_empty() {
        config.val("STATESYNC_RPC_SERVERS")
    } else {
        statesync_rpc.to_string()
    };
    let use_statesync = !rpc.is_empty();
    if use_statesync {
        vars.insert("STATESYNC_RPC_SERVERS".into(), rpc);
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), config.val("STATESYNC_TRUST_HEIGHT"));
        vars.insert("STATESYNC_TRUST_HASH".into(), config.val("STATESYNC_TRUST_HASH"));
        vars.insert("STATESYNC_TRUST_PERIOD".into(), config.val("STATESYNC_TRUST_PERIOD"));
        // Clear snapshot download vars — statesync nodes don't need them.
        vars.insert("OLINE_SNAPSHOT_URL".into(), String::new());
        vars.insert("SNAPSHOT_URL".into(), String::new());
        vars.insert("SNAPSHOT_JSON".into(), String::new());
    } else {
        vars.insert("STATESYNC_RPC_SERVERS".into(), String::new());
        vars.insert("STATESYNC_ENABLE".into(), "false".into());
        vars.insert("STATESYNC_TRUST_HEIGHT".into(), String::new());
        vars.insert("STATESYNC_TRUST_HASH".into(), String::new());
        vars.insert("STATESYNC_TRUST_PERIOD".into(), String::new());

        // ── Snapshot JSON URL (only in snapshot mode) ────────────────────────
        vars.insert(
            "SNAPSHOT_JSON".into(),
            format!(
                "https://{}/{}/snapshot.json",
                config.val("OLINE_SNAP_DOWNLOAD_DOMAIN"),
                config.val("OLINE_SNAP_PATH").trim_matches('/')
            ),
        );
    }

    // ── Accept list for Argus REST API ────────────────────────────────────────
    let api_domain = config.val("ARGUS_API_D");
    let argus_accepts = if api_domain.is_empty() {
        String::new()
    } else {
        format!("          - {}", api_domain)
    };
    vars.insert("ARGUS_80_ACCEPTS".into(), argus_accepts);

    vars
}
