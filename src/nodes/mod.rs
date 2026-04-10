//! Encrypted store of deployed node SSH credentials for post-deploy management.
//!
//! `NodeStore` holds a JSON array of `NodeRecord`s that capture the SSH connectivity
//! info and RPC endpoint for each Akash-hosted node.  The store is written after
//! each phase deploy and read by `oline refresh` / `oline manage` for SSH refresh
//! and health-check operations.
//!
//! Encryption uses the same AES-256-GCM + Argon2id scheme as `SiteStore` and
//! `encrypt_mnemonic`.  Store file: `$SECRETS_PATH/nodes.enc`.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    path::{Path, PathBuf},
};

use crate::crypto::{NONCE_LEN, SALT_LEN};

// ── Record ─────────────────────────────────────────────────────────────────────

/// SSH + RPC credentials for a single Akash-hosted node.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeRecord {
    /// Human-readable label (e.g. "Phase A - Snapshot").
    pub label: String,
    /// Akash deployment sequence number.
    pub dseq: u64,
    /// Service name in the SDL (e.g. "oline-a-snapshot").
    pub service: String,
    /// Provider-assigned SSH hostname (no scheme, no port).
    pub host: String,
    /// Provider-assigned external SSH port.
    pub ssh_port: u16,
    /// Internal SSH port used in the SDL (default 22 — used to find the endpoint).
    pub ssh_internal_port: u16,
    /// Cosmos RPC URL for health checks (e.g. "http://provider.host:26XXX").
    pub rpc_url: String,
    /// SSH private key filename inside `$SECRETS_PATH` (e.g. "oline-ssh-key").
    pub key_name: String,
    /// Phase identifier (A / B / C / E / G / …).
    pub phase: String,
    /// Unix timestamp when the record was saved.
    pub added_at: u64,
}

impl NodeRecord {
    pub fn new(
        label: impl Into<String>,
        dseq: u64,
        service: impl Into<String>,
        host: impl Into<String>,
        ssh_port: u16,
        rpc_url: impl Into<String>,
        key_name: impl Into<String>,
        phase: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            dseq,
            service: service.into(),
            host: host.into(),
            ssh_port,
            ssh_internal_port: 22,
            rpc_url: rpc_url.into(),
            key_name: key_name.into(),
            phase: phase.into(),
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Absolute path to the SSH private key on disk.
    pub fn key_path(&self) -> PathBuf {
        let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        PathBuf::from(dir).join(&self.key_name)
    }
}

// ── Store ──────────────────────────────────────────────────────────────────────

/// Encrypted collection of `NodeRecord`s.
pub struct NodeStore {
    path: PathBuf,
    password: String,
}

impl NodeStore {
    /// Open (or create) a node store at the given path, encrypted with `password`.
    pub fn open(path: impl AsRef<Path>, password: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: password.into(),
        }
    }

    /// Default path: `$SECRETS_PATH/nodes.enc` (falls back to `./nodes.enc`).
    pub fn default_path() -> PathBuf {
        let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        PathBuf::from(dir).join("nodes.enc")
    }

    /// Load and decrypt all records. Returns an empty vec if the file doesn't exist.
    pub fn load(&self) -> Result<Vec<NodeRecord>, Box<dyn Error>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let blob = std::fs::read_to_string(&self.path)?;
        let json = decrypt_nodes(&blob, &self.password)?;
        let records: Vec<NodeRecord> = serde_json::from_str(&json)?;
        Ok(records)
    }

    /// Encrypt and persist `records`.
    pub fn save(&self, records: &[NodeRecord]) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string(records)?;
        let blob = encrypt_nodes(&json, &self.password)?;
        std::fs::write(&self.path, blob)?;
        Ok(())
    }

    /// Append a new record and persist.
    pub fn add(&self, record: NodeRecord) -> Result<(), Box<dyn Error>> {
        let mut records = self.load()?;
        records.push(record);
        self.save(&records)
    }

    /// Find a node by composite ID (`DSEQ.N`) or fall back to label match.
    ///
    /// `DSEQ.N` — selects the Nth node (0-indexed) within the given DSEQ.
    /// Otherwise, matches by label (case-sensitive).
    pub fn find(&self, query: &str) -> Result<NodeRecord, Box<dyn Error>> {
        let records = self.load()?;
        // Try DSEQ.N format first
        if let Some((dseq_part, idx_part)) = query.split_once('.') {
            if let (Ok(dseq), Ok(idx)) = (dseq_part.parse::<u64>(), idx_part.parse::<usize>()) {
                let matches: Vec<_> = records.iter().filter(|r| r.dseq == dseq).collect();
                return matches.get(idx).cloned().cloned().ok_or_else(|| {
                    format!(
                        "Node {}.{} not found ({} nodes for DSEQ {}). Run `oline refresh list`.",
                        dseq, idx, matches.len(), dseq
                    ).into()
                });
            }
        }
        // Try bare DSEQ (single node only)
        if let Ok(dseq) = query.parse::<u64>() {
            let matches: Vec<_> = records.iter().filter(|r| r.dseq == dseq).collect();
            if matches.len() == 1 {
                return Ok(matches[0].clone());
            }
            if matches.len() > 1 {
                return Err(format!(
                    "DSEQ {} has {} nodes — use DSEQ.N to specify (e.g. {}.0, {}.1). Run `oline refresh list`.",
                    dseq, matches.len(), dseq, dseq
                ).into());
            }
        }
        // Fall back to label match
        records.iter().find(|r| r.label == query).cloned().ok_or_else(|| {
            format!(
                "Node '{}' not found. Run `oline refresh list` to see saved nodes.",
                query
            ).into()
        })
    }

    /// Remove all records for a given `dseq`.
    pub fn remove_by_dseq(&self, dseq: u64) -> Result<usize, Box<dyn Error>> {
        let mut records = self.load()?;
        let before = records.len();
        records.retain(|r| r.dseq != dseq);
        let removed = before - records.len();
        if removed > 0 {
            self.save(&records)?;
        }
        Ok(removed)
    }
}

// ── Auto-registration helper ──────────────────────────────────────────────────

/// Register all nodes from a deployed phase into the encrypted node store.
///
/// Called after each phase deployment completes (both parallel and sequential paths).
/// Idempotent: removes any existing records for the same `dseq` before adding new ones.
///
/// `services` maps `(service_name, human_label)` — e.g. `("oline-a-snapshot", "Phase A - Snapshot")`.
pub fn register_phase_nodes(
    endpoints: &[akash_deploy_rs::ServiceEndpoint],
    dseq: u64,
    services: &[(&str, &str)],
    key_name: &str,
    phase: &str,
    password: &str,
    ssh_port_internal: u16,
) {
    let store = NodeStore::open(NodeStore::default_path(), password);
    // Idempotent: clear any stale records for this dseq before re-adding.
    let _ = store.remove_by_dseq(dseq);

    for &(service, label) in services {
        let ssh_ep = crate::deployer::OLineDeployer::find_endpoint_by_internal_port(
            endpoints,
            service,
            ssh_port_internal,
        );
        let rpc_ep = crate::deployer::OLineDeployer::find_endpoint_by_internal_port(
            endpoints, service, 26657,
        );
        let ssh_host = ssh_ep
            .map(|ep| crate::akash::endpoint_hostname(&ep.uri).to_string())
            .unwrap_or_default();
        let ssh_port_ext = ssh_ep.map(|ep| ep.port).unwrap_or(22);
        let rpc_url = rpc_ep
            .map(|ep| {
                format!(
                    "http://{}:{}",
                    crate::akash::endpoint_hostname(&ep.uri),
                    ep.port
                )
            })
            .unwrap_or_default();

        if ssh_host.is_empty() {
            tracing::debug!(
                "  [node-register] No SSH endpoint for {} — skipping.",
                service
            );
            continue;
        }

        let record = NodeRecord::new(label, dseq, service, &ssh_host, ssh_port_ext, &rpc_url, key_name, phase);
        match store.add(record) {
            Ok(_) => tracing::info!("  [node-register] {} → {}:{}", label, ssh_host, ssh_port_ext),
            Err(e) => tracing::warn!("  [node-register] Failed to save {}: {}", label, e),
        }
    }
}

// ── Encryption helpers ─────────────────────────────────────────────────────────

fn encrypt_nodes(plaintext: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {:?}", e))?;

    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("AES-GCM encrypt failed: {:?}", e))?;

    let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(&combined))
}

fn decrypt_nodes(blob: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let data = BASE64.decode(blob.trim())?;
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("Node store blob too short".into());
    }
    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {:?}", e))?;

    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Node store decryption failed — wrong password?")?;
    String::from_utf8(plaintext).map_err(Into::into)
}
