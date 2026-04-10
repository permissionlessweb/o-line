//! Encrypted store for WireGuard VPN state: server config + per-device peer records.
//!
//! `VpnStore` holds a JSON array of `WgServer` records, each containing the server
//! config and all peer records.  The store is written after `oline vpn bootstrap` and
//! updated by `add-peer` / `revoke-peer`.
//!
//! Encryption uses the same AES-256-GCM + Argon2id scheme as `FirewallStore`.
//! Store file: `$SECRETS_PATH/vpn.enc`.

pub mod keygen;
pub mod pfsense;

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

// ── WgPeer ─────────────────────────────────────────────────────────────────────

/// A single WireGuard peer (client device).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WgPeer {
    /// Human-readable name (e.g. "alice", "laptop-1").
    pub name: String,
    /// Private key (base64) — kept for generating client .conf.
    pub private_key: String,
    /// Public key (base64) — installed on pfSense.
    pub public_key: String,
    /// Peer VPN address (e.g. "10.0.0.2/32").
    pub peer_address: String,
    /// Allowed IPs for this peer's traffic (e.g. "0.0.0.0/0" or "192.168.1.0/24").
    pub allowed_ips: String,
    /// SSH target where the .conf was pushed, if any (format: "user@host:port").
    pub pushed_to: Option<String>,
    /// Unix timestamp when peer was added.
    pub added_at: u64,
}

// ── WgServer ───────────────────────────────────────────────────────────────────

/// WireGuard server configuration on a pfSense firewall.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WgServer {
    /// Label of the `FirewallRecord` this server is linked to.
    pub firewall_label: String,
    /// WireGuard interface name (e.g. "wg0").
    pub interface: String,
    /// UDP listen port (e.g. 51820).
    pub listen_port: u16,
    /// VPN subnet address for the server (e.g. "10.0.0.1/24").
    pub server_address: String,
    /// Server private key (base64) — stored encrypted.
    pub private_key: String,
    /// Server public key (base64).
    pub public_key: String,
    /// WAN endpoint advertised to clients (e.g. "1.2.3.4:51820" or "vpn.example.com:51820").
    pub wan_endpoint: Option<String>,
    /// All registered peer devices.
    pub peers: Vec<WgPeer>,
    /// Unix timestamp when the server was bootstrapped.
    pub created_at: u64,
}

impl WgServer {
    /// Auto-assign the next available /32 peer address within the server subnet.
    ///
    /// Parses `server_address` (e.g. "10.0.0.1/24") and all existing peer addresses
    /// to find the next free last-octet.
    pub fn next_peer_address(&self) -> Result<String, Box<dyn Error>> {
        // Parse server IP (e.g. "10.0.0.1" from "10.0.0.1/24")
        let server_ip = self.server_address.split('/').next().unwrap_or("");
        let parts: Vec<&str> = server_ip.split('.').collect();
        if parts.len() != 4 {
            return Err(format!("Cannot parse server address: {}", self.server_address).into());
        }
        let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

        // Collect all used last-octets (server + peers)
        let mut used: std::collections::HashSet<u8> = std::collections::HashSet::new();
        if let Ok(last) = parts[3].parse::<u8>() {
            used.insert(last);
        }
        for peer in &self.peers {
            let peer_ip = peer.peer_address.split('/').next().unwrap_or("");
            let peer_parts: Vec<&str> = peer_ip.split('.').collect();
            if peer_parts.len() == 4 {
                if let Ok(last) = peer_parts[3].parse::<u8>() {
                    used.insert(last);
                }
            }
        }

        // Find next available octet (2..=254)
        for octet in 2u8..=254 {
            if !used.contains(&octet) {
                return Ok(format!("{}.{}/32", prefix, octet));
            }
        }
        Err("VPN subnet exhausted (all /32 addresses used)".into())
    }
}

// ── VpnStore ───────────────────────────────────────────────────────────────────

/// Encrypted collection of `WgServer` records.
pub struct VpnStore {
    path: PathBuf,
    password: String,
}

impl VpnStore {
    /// Open (or create) a VPN store at the given path, encrypted with `password`.
    pub fn open(path: impl AsRef<Path>, password: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: password.into(),
        }
    }

    /// Default path: `$SECRETS_PATH/vpn.enc` (falls back to `./vpn.enc`).
    pub fn default_path() -> PathBuf {
        let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        PathBuf::from(dir).join("vpn.enc")
    }

    /// Load and decrypt all records. Returns an empty vec if the file doesn't exist.
    pub fn load(&self) -> Result<Vec<WgServer>, Box<dyn Error>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let blob = std::fs::read_to_string(&self.path)?;
        let json = decrypt_store(&blob, &self.password)?;
        let records: Vec<WgServer> = serde_json::from_str(&json)?;
        Ok(records)
    }

    /// Encrypt and persist `records`.
    pub fn save(&self, records: &[WgServer]) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string(records)?;
        let blob = encrypt_store(&json, &self.password)?;
        std::fs::write(&self.path, blob)?;
        Ok(())
    }

    /// Append a new server record and persist.
    pub fn add(&self, record: WgServer) -> Result<(), Box<dyn Error>> {
        let mut records = self.load()?;
        records.push(record);
        self.save(&records)
    }

    /// Find a server by firewall label.
    pub fn find_by_label(&self, label: &str) -> Result<Option<WgServer>, Box<dyn Error>> {
        let records = self.load()?;
        Ok(records.into_iter().find(|r| r.firewall_label == label))
    }

    /// Update a server record (replace by firewall_label).
    pub fn update(&self, server: WgServer) -> Result<(), Box<dyn Error>> {
        let mut records = self.load()?;
        let label = server.firewall_label.clone();
        if let Some(pos) = records.iter().position(|r| r.firewall_label == label) {
            records[pos] = server;
        } else {
            records.push(server);
        }
        self.save(&records)
    }

    /// Remove a server record by firewall label. Returns count removed.
    pub fn remove_by_label(&self, label: &str) -> Result<usize, Box<dyn Error>> {
        let mut records = self.load()?;
        let before = records.len();
        records.retain(|r| r.firewall_label != label);
        let removed = before - records.len();
        if removed > 0 {
            self.save(&records)?;
        }
        Ok(removed)
    }
}

// ── Encryption helpers (same as FirewallStore) ─────────────────────────────────

fn encrypt_store(plaintext: &str, password: &str) -> Result<String, Box<dyn Error>> {
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

fn decrypt_store(blob: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let data = BASE64.decode(blob.trim())?;
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("VPN store blob too short".into());
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
        .map_err(|_| "VPN store decryption failed — wrong password?")?;
    String::from_utf8(plaintext).map_err(Into::into)
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server() -> WgServer {
        let (priv_key, pub_key) = crate::vpn::keygen::generate_wg_keypair();
        WgServer {
            firewall_label: "pfSense".to_string(),
            interface: "wg0".to_string(),
            listen_port: 51820,
            server_address: "10.99.0.1/24".to_string(),
            private_key: priv_key,
            public_key: pub_key,
            wan_endpoint: Some("192.168.1.168:51820".to_string()),
            peers: vec![],
            created_at: 1700000000,
        }
    }

    fn tmp_store(password: &str) -> (VpnStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vpn.enc");
        let store = VpnStore::open(&path, password);
        (store, dir)
    }

    #[test]
    fn test_store_round_trip() {
        let (store, _dir) = tmp_store("pw");
        store.add(sample_server()).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].firewall_label, "pfSense");
        assert_eq!(loaded[0].interface, "wg0");
        assert_eq!(loaded[0].listen_port, 51820);
    }

    #[test]
    fn test_store_empty_file() {
        let (store, _dir) = tmp_store("pw");
        let loaded = store.load().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_store_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vpn.enc");

        let store1 = VpnStore::open(&path, "correct");
        store1.add(sample_server()).unwrap();

        let store2 = VpnStore::open(&path, "wrong");
        assert!(store2.load().is_err());
    }

    #[test]
    fn test_update_server() {
        let (store, _dir) = tmp_store("pw");
        let mut server = sample_server();
        store.add(server.clone()).unwrap();

        server.listen_port = 51821;
        store.update(server).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].listen_port, 51821);
    }

    #[test]
    fn test_next_peer_address() {
        let mut server = sample_server();
        assert_eq!(server.next_peer_address().unwrap(), "10.99.0.2/32");

        let (peer_priv, peer_pub) = crate::vpn::keygen::generate_wg_keypair();
        server.peers.push(WgPeer {
            name: "alice".to_string(),
            private_key: peer_priv,
            public_key: peer_pub,
            peer_address: "10.99.0.2/32".to_string(),
            allowed_ips: "0.0.0.0/0".to_string(),
            pushed_to: None,
            added_at: 0,
        });
        assert_eq!(server.next_peer_address().unwrap(), "10.99.0.3/32");
    }
}
