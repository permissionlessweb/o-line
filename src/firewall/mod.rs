//! Encrypted store of firewall SSH credentials for pfSense management.
//!
//! `FirewallStore` holds a JSON array of `FirewallRecord`s that capture SSH
//! connectivity info for each managed pfSense firewall.  The store is written
//! after `oline firewall bootstrap` installs a key and read by `list`/`status`.
//!
//! Encryption uses the same AES-256-GCM + Argon2id scheme as `NodeStore`.
//! Store file: `$SECRETS_PATH/firewalls.enc`.

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

// ── ForwardTarget ─────────────────────────────────────────────────────────────

/// An internal server reachable through a pfSense jump host.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ForwardTarget {
    /// Target IP or hostname (as seen from pfSense).
    pub host: String,
    /// SSH port on the target (default 22).
    pub port: u16,
    /// SSH username on the target.
    pub user: String,
}

impl ForwardTarget {
    /// Parse from `[user@]host[:port]` format.
    ///
    /// Examples: `root@10.0.0.50`, `10.0.0.50`, `admin@10.0.0.50:2222`
    pub fn parse(s: &str) -> Result<Self, String> {
        let (user, host_port) = if let Some(at) = s.find('@') {
            (s[..at].to_string(), &s[at + 1..])
        } else {
            ("root".to_string(), s)
        };

        if user.is_empty() {
            return Err(format!("Empty user in '{}'", s));
        }

        let (host, port) = if let Some(colon) = host_port.rfind(':') {
            let port_str = &host_port[colon + 1..];
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid port '{}' in '{}'", port_str, s))?;
            (host_port[..colon].to_string(), port)
        } else {
            (host_port.to_string(), 22)
        };

        if host.is_empty() {
            return Err(format!("Empty host in '{}'", s));
        }

        Ok(Self { host, port, user })
    }
}

impl std::fmt::Display for ForwardTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.port == 22 {
            write!(f, "{}@{}", self.user, self.host)
        } else {
            write!(f, "{}@{}:{}", self.user, self.host, self.port)
        }
    }
}

// ── Record ─────────────────────────────────────────────────────────────────────

/// SSH credentials for a single managed pfSense firewall.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallRecord {
    /// Human-readable label (e.g. "Office pfSense").
    pub label: String,
    /// Firewall IP or hostname (e.g. "192.168.1.1").
    pub host: String,
    /// SSH port (default 22).
    pub ssh_port: u16,
    /// SSH username (default "admin").
    pub user: String,
    /// SSH private key filename inside `$SECRETS_PATH` (e.g. "pfsense-ssh-key").
    pub key_name: String,
    /// Whether password auth has been disabled on the firewall (future use).
    pub password_auth_disabled: bool,
    /// Internal servers whose keys were installed via this firewall as jump host.
    #[serde(default)]
    pub forward_targets: Vec<ForwardTarget>,
    /// Unix timestamp when the record was saved.
    pub added_at: u64,
}

impl FirewallRecord {
    pub fn new(
        label: impl Into<String>,
        host: impl Into<String>,
        ssh_port: u16,
        user: impl Into<String>,
        key_name: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            host: host.into(),
            ssh_port,
            user: user.into(),
            key_name: key_name.into(),
            password_auth_disabled: false,
            forward_targets: vec![],
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Absolute path to the SSH private key on disk.
    /// If `key_name` is already an absolute path, returns it directly.
    /// Otherwise, joins with `$SECRETS_PATH`.
    pub fn key_path(&self) -> PathBuf {
        let p = PathBuf::from(&self.key_name);
        if p.is_absolute() {
            p
        } else {
            let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
            PathBuf::from(dir).join(&self.key_name)
        }
    }
}

// ── Store ──────────────────────────────────────────────────────────────────────

/// Encrypted collection of `FirewallRecord`s.
pub struct FirewallStore {
    path: PathBuf,
    password: String,
}

impl FirewallStore {
    /// Open (or create) a firewall store at the given path, encrypted with `password`.
    pub fn open(path: impl AsRef<Path>, password: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: password.into(),
        }
    }

    /// Default path: `$SECRETS_PATH/firewalls.enc` (falls back to `./firewalls.enc`).
    pub fn default_path() -> PathBuf {
        let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        PathBuf::from(dir).join("firewalls.enc")
    }

    /// Load and decrypt all records. Returns an empty vec if the file doesn't exist.
    pub fn load(&self) -> Result<Vec<FirewallRecord>, Box<dyn Error>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let blob = std::fs::read_to_string(&self.path)?;
        let json = decrypt_store(&blob, &self.password)?;
        let records: Vec<FirewallRecord> = serde_json::from_str(&json)?;
        Ok(records)
    }

    /// Encrypt and persist `records`.
    pub fn save(&self, records: &[FirewallRecord]) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string(records)?;
        let blob = encrypt_store(&json, &self.password)?;
        std::fs::write(&self.path, blob)?;
        Ok(())
    }

    /// Append a new record and persist.
    pub fn add(&self, record: FirewallRecord) -> Result<(), Box<dyn Error>> {
        let mut records = self.load()?;
        records.push(record);
        self.save(&records)
    }

    /// Remove all records matching `label`. Returns count removed.
    pub fn remove_by_label(&self, label: &str) -> Result<usize, Box<dyn Error>> {
        let mut records = self.load()?;
        let before = records.len();
        records.retain(|r| r.label != label);
        let removed = before - records.len();
        if removed > 0 {
            self.save(&records)?;
        }
        Ok(removed)
    }
}

// ── ClientAccess ─────────────────────────────────────────────────────────────

/// Tracks one client's SSH key access grant.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientAccess {
    /// Human-readable client identifier (e.g. "alice", "ci-bot").
    pub name: String,
    /// Full SSH public key line (e.g. "ssh-ed25519 AAAA... user@host").
    pub pubkey: String,
    /// Label of the `FirewallRecord` used as jump host.
    pub firewall_label: String,
    /// Servers where this client's key was installed.
    pub targets: Vec<ForwardTarget>,
    /// Unix timestamp when access was granted.
    pub granted_at: u64,
}

impl ClientAccess {
    /// Extract the base64 key data blob (2nd field) for grep-based removal.
    pub fn key_data(&self) -> Option<&str> {
        self.pubkey.split_whitespace().nth(1)
    }
}

// ── ClientStore ──────────────────────────────────────────────────────────────

/// Encrypted collection of `ClientAccess` records.
/// Stored at `$SECRETS_PATH/clients.enc`, encrypted with the same password as `FirewallStore`.
pub struct ClientStore {
    path: PathBuf,
    password: String,
}

impl ClientStore {
    /// Open (or create) a client store at the given path, encrypted with `password`.
    pub fn open(path: impl AsRef<Path>, password: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: password.into(),
        }
    }

    /// Default path: `$SECRETS_PATH/clients.enc` (falls back to `./clients.enc`).
    pub fn default_path() -> PathBuf {
        let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        PathBuf::from(dir).join("clients.enc")
    }

    /// Load and decrypt all records. Returns an empty vec if the file doesn't exist.
    pub fn load(&self) -> Result<Vec<ClientAccess>, Box<dyn Error>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let blob = std::fs::read_to_string(&self.path)?;
        let json = decrypt_store(&blob, &self.password)?;
        let records: Vec<ClientAccess> = serde_json::from_str(&json)?;
        Ok(records)
    }

    /// Encrypt and persist `records`.
    pub fn save(&self, records: &[ClientAccess]) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string(records)?;
        let blob = encrypt_store(&json, &self.password)?;
        std::fs::write(&self.path, blob)?;
        Ok(())
    }

    /// Append a new record and persist.
    pub fn add(&self, record: ClientAccess) -> Result<(), Box<dyn Error>> {
        let mut records = self.load()?;
        records.push(record);
        self.save(&records)
    }

    /// Find a client by name.
    pub fn find_by_name(&self, name: &str) -> Result<Option<ClientAccess>, Box<dyn Error>> {
        let records = self.load()?;
        Ok(records.into_iter().find(|r| r.name == name))
    }

    /// Remove all records matching `name`. Returns count removed.
    pub fn remove_by_name(&self, name: &str) -> Result<usize, Box<dyn Error>> {
        let mut records = self.load()?;
        let before = records.len();
        records.retain(|r| r.name != name);
        let removed = before - records.len();
        if removed > 0 {
            self.save(&records)?;
        }
        Ok(removed)
    }
}

// ── Encryption helpers ─────────────────────────────────────────────────────────

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
        return Err("Firewall store blob too short".into());
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
        .map_err(|_| "Firewall store decryption failed — wrong password?")?;
    String::from_utf8(plaintext).map_err(Into::into)
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(password: &str) -> (FirewallStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firewalls.enc");
        let store = FirewallStore::open(&path, password);
        (store, dir)
    }

    #[test]
    fn test_store_round_trip() {
        let (store, _dir) = tmp_store("test-password");

        let rec = FirewallRecord::new("Office pfSense", "192.168.1.1", 22, "admin", "pfsense-key");
        store.add(rec.clone()).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].label, "Office pfSense");
        assert_eq!(loaded[0].host, "192.168.1.1");
        assert_eq!(loaded[0].ssh_port, 22);
        assert_eq!(loaded[0].user, "admin");
        assert_eq!(loaded[0].key_name, "pfsense-key");
        assert!(!loaded[0].password_auth_disabled);
    }

    #[test]
    fn test_store_empty_file() {
        let (store, _dir) = tmp_store("pw");
        let loaded = store.load().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_store_add_multiple() {
        let (store, _dir) = tmp_store("pw");

        store
            .add(FirewallRecord::new("FW1", "10.0.0.1", 22, "admin", "k1"))
            .unwrap();
        store
            .add(FirewallRecord::new("FW2", "10.0.0.2", 2222, "root", "k2"))
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].label, "FW1");
        assert_eq!(loaded[1].label, "FW2");
    }

    #[test]
    fn test_store_remove_by_label() {
        let (store, _dir) = tmp_store("pw");

        store
            .add(FirewallRecord::new("FW1", "10.0.0.1", 22, "admin", "k1"))
            .unwrap();
        store
            .add(FirewallRecord::new("FW2", "10.0.0.2", 22, "admin", "k2"))
            .unwrap();

        let removed = store.remove_by_label("FW1").unwrap();
        assert_eq!(removed, 1);

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].label, "FW2");
    }

    #[test]
    fn test_store_remove_nonexistent() {
        let (store, _dir) = tmp_store("pw");
        store
            .add(FirewallRecord::new("FW1", "10.0.0.1", 22, "admin", "k1"))
            .unwrap();

        let removed = store.remove_by_label("NOPE").unwrap();
        assert_eq!(removed, 0);

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn test_store_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firewalls.enc");

        let store1 = FirewallStore::open(&path, "correct");
        store1
            .add(FirewallRecord::new("FW", "1.2.3.4", 22, "admin", "k"))
            .unwrap();

        let store2 = FirewallStore::open(&path, "wrong");
        assert!(store2.load().is_err());
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let plaintext = r#"[{"label":"test","host":"1.2.3.4"}]"#;
        let password = "secret123";
        let encrypted = encrypt_store(plaintext, password).unwrap();
        let decrypted = decrypt_store(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_forward_target_parse_full() {
        let t = ForwardTarget::parse("root@10.0.0.50:2222").unwrap();
        assert_eq!(t.user, "root");
        assert_eq!(t.host, "10.0.0.50");
        assert_eq!(t.port, 2222);
    }

    #[test]
    fn test_forward_target_parse_user_host() {
        let t = ForwardTarget::parse("admin@10.0.0.50").unwrap();
        assert_eq!(t.user, "admin");
        assert_eq!(t.host, "10.0.0.50");
        assert_eq!(t.port, 22);
    }

    #[test]
    fn test_forward_target_parse_host_only() {
        let t = ForwardTarget::parse("10.0.0.50").unwrap();
        assert_eq!(t.user, "root");
        assert_eq!(t.host, "10.0.0.50");
        assert_eq!(t.port, 22);
    }

    #[test]
    fn test_forward_target_parse_empty_host() {
        assert!(ForwardTarget::parse("root@").is_err());
    }

    #[test]
    fn test_forward_target_parse_bad_port() {
        assert!(ForwardTarget::parse("root@host:abc").is_err());
    }

    #[test]
    fn test_forward_target_display() {
        let t = ForwardTarget { host: "10.0.0.50".into(), port: 22, user: "root".into() };
        assert_eq!(t.to_string(), "root@10.0.0.50");

        let t2 = ForwardTarget { host: "10.0.0.50".into(), port: 2222, user: "admin".into() };
        assert_eq!(t2.to_string(), "admin@10.0.0.50:2222");
    }

    // ── ClientStore tests ──────────────────────────────────────────────────

    fn tmp_client_store(password: &str) -> (ClientStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.enc");
        let store = ClientStore::open(&path, password);
        (store, dir)
    }

    fn sample_client(name: &str) -> ClientAccess {
        ClientAccess {
            name: name.to_string(),
            pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@host".to_string(),
            firewall_label: "pfSense".to_string(),
            targets: vec![ForwardTarget {
                host: "10.0.0.50".into(),
                port: 22,
                user: "root".into(),
            }],
            granted_at: 1700000000,
        }
    }

    #[test]
    fn test_client_store_round_trip() {
        let (store, _dir) = tmp_client_store("pw");
        store.add(sample_client("alice")).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "alice");
        assert_eq!(loaded[0].firewall_label, "pfSense");
        assert_eq!(loaded[0].targets.len(), 1);
        assert_eq!(loaded[0].targets[0].host, "10.0.0.50");
    }

    #[test]
    fn test_client_store_remove_by_name() {
        let (store, _dir) = tmp_client_store("pw");
        store.add(sample_client("alice")).unwrap();
        store.add(sample_client("bob")).unwrap();

        let removed = store.remove_by_name("alice").unwrap();
        assert_eq!(removed, 1);

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "bob");
    }

    #[test]
    fn test_client_store_remove_nonexistent() {
        let (store, _dir) = tmp_client_store("pw");
        store.add(sample_client("alice")).unwrap();
        let removed = store.remove_by_name("nope").unwrap();
        assert_eq!(removed, 0);
        assert_eq!(store.load().unwrap().len(), 1);
    }

    #[test]
    fn test_client_store_find_by_name() {
        let (store, _dir) = tmp_client_store("pw");
        store.add(sample_client("alice")).unwrap();
        store.add(sample_client("bob")).unwrap();

        assert!(store.find_by_name("alice").unwrap().is_some());
        assert!(store.find_by_name("bob").unwrap().is_some());
        assert!(store.find_by_name("charlie").unwrap().is_none());
    }

    #[test]
    fn test_client_key_data_extraction() {
        let client = sample_client("alice");
        assert_eq!(client.key_data(), Some("AAAAC3NzaC1lZDI1NTE5AAAAITestKey"));

        let no_data = ClientAccess {
            name: "bad".into(),
            pubkey: "ssh-ed25519".into(), // missing key data
            firewall_label: "fw".into(),
            targets: vec![],
            granted_at: 0,
        };
        assert_eq!(no_data.key_data(), None);
    }

    #[test]
    fn test_store_round_trip_with_forward_targets() {
        let (store, _dir) = tmp_store("pw");

        let mut rec = FirewallRecord::new("FW", "10.0.0.1", 22, "admin", "k1");
        rec.forward_targets = vec![
            ForwardTarget { host: "10.0.0.50".into(), port: 22, user: "root".into() },
            ForwardTarget { host: "10.0.0.51".into(), port: 2222, user: "deploy".into() },
        ];
        store.add(rec).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded[0].forward_targets.len(), 2);
        assert_eq!(loaded[0].forward_targets[0].host, "10.0.0.50");
        assert_eq!(loaded[0].forward_targets[1].port, 2222);
    }
}
