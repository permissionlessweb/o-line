//! Encrypted credential store for domain-keyed API tokens.
//!
//! `KeyStore` maintains a JSON array of `KeyEntry`s encrypted with AES-256-GCM
//! using the same Argon2id + random salt/nonce scheme as `SiteStore`.
//! The store file lives at `~/.oline/keys.enc`.
//!
//! Each entry maps one or more domain patterns to a set of credentials
//! (Cloudflare API token + zone ID, and optionally an Akash mnemonic).
//! DNS commands resolve credentials by matching the target domain against
//! stored patterns — longest suffix match wins.

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

// ── Entry ──────────────────────────────────────────────────────────────────────

/// A credential set associated with one or more domains.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyEntry {
    /// Human label (e.g. "permissionless.money", "terp.network").
    pub label: String,
    /// Domain patterns this entry covers. Lookup matches longest suffix.
    /// Examples: "permissionless.money", "*.terp.network", "terp.network".
    pub domains: Vec<String>,
    /// Cloudflare API token.
    pub cf_api_token: String,
    /// Cloudflare zone ID.
    pub cf_zone_id: String,
    /// Optional encrypted Akash mnemonic (base64 blob, same format as .env).
    /// When present, deploy commands can auto-select the right signer per domain.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mnemonic: String,
    /// Unix timestamp (seconds) when entry was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) of last update.
    pub updated_at: u64,
}

impl KeyEntry {
    pub fn new(
        label: String,
        domains: Vec<String>,
        cf_api_token: String,
        cf_zone_id: String,
    ) -> Self {
        let now = now_secs();
        Self {
            label,
            domains,
            cf_api_token,
            cf_zone_id,
            mnemonic: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this entry matches a given domain (longest-suffix match).
    pub fn matches(&self, domain: &str) -> Option<usize> {
        self.domains
            .iter()
            .filter_map(|pattern| {
                let p = pattern.trim().to_lowercase();
                let d = domain.trim().to_lowercase();
                if p.starts_with("*.") {
                    // Wildcard: *.example.com matches sub.example.com and example.com
                    let suffix = &p[2..];
                    if d == suffix || d.ends_with(&format!(".{}", suffix)) {
                        Some(suffix.len())
                    } else {
                        None
                    }
                } else if d == p || d.ends_with(&format!(".{}", p)) {
                    Some(p.len())
                } else {
                    None
                }
            })
            .max()
    }
}

// ── Store ──────────────────────────────────────────────────────────────────────

/// Encrypted collection of `KeyEntry`s.
pub struct KeyStore {
    path: PathBuf,
    password: String,
}

impl KeyStore {
    /// Open (or create) a key store at the given path, encrypted with `password`.
    pub fn open(path: impl AsRef<Path>, password: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: password.into(),
        }
    }

    /// Default path: `~/.oline/keys.enc`.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".oline")
            .join("keys.enc")
    }

    /// Load and decrypt all entries. Returns empty vec if file doesn't exist.
    pub fn load(&self) -> Result<Vec<KeyEntry>, Box<dyn Error>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let blob = std::fs::read_to_string(&self.path)?;
        let json = decrypt_store(&blob, &self.password)?;
        let entries: Vec<KeyEntry> = serde_json::from_str(&json)?;
        Ok(entries)
    }

    /// Encrypt and persist entries.
    pub fn save(&self, entries: &[KeyEntry]) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(entries)?;
        let blob = encrypt_store(&json, &self.password)?;
        std::fs::write(&self.path, blob)?;
        Ok(())
    }

    /// Add a new entry and persist.
    pub fn add(&self, entry: KeyEntry) -> Result<(), Box<dyn Error>> {
        let mut entries = self.load()?;
        entries.push(entry);
        self.save(&entries)
    }

    /// Remove entries matching a label and persist. Returns count removed.
    pub fn remove(&self, label: &str) -> Result<usize, Box<dyn Error>> {
        let mut entries = self.load()?;
        let before = entries.len();
        entries.retain(|e| e.label != label);
        let removed = before - entries.len();
        if removed > 0 {
            self.save(&entries)?;
        }
        Ok(removed)
    }

    /// Find the best-matching entry for a domain (longest suffix match).
    pub fn resolve(&self, domain: &str) -> Result<Option<KeyEntry>, Box<dyn Error>> {
        let entries = self.load()?;
        let mut best: Option<(usize, &KeyEntry)> = None;
        for entry in &entries {
            if let Some(score) = entry.matches(domain) {
                if best.is_none() || score > best.unwrap().0 {
                    best = Some((score, entry));
                }
            }
        }
        Ok(best.map(|(_, e)| e.clone()))
    }

    /// List all entries (labels + domains, no secrets).
    pub fn list_labels(&self) -> Result<Vec<(String, Vec<String>)>, Box<dyn Error>> {
        let entries = self.load()?;
        Ok(entries
            .iter()
            .map(|e| (e.label.clone(), e.domains.clone()))
            .collect())
    }
}

// ── Encryption (same scheme as SiteStore) ──────────────────────────────────────

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
        return Err("Key store blob too short".into());
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
        .map_err(|_| "Key store decryption failed — wrong password?")?;
    String::from_utf8(plaintext).map_err(Into::into)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_entry_matches() {
        let entry = KeyEntry::new(
            "terp".into(),
            vec!["terp.network".into(), "*.terp.network".into()],
            "tok".into(),
            "zone".into(),
        );
        assert!(entry.matches("terp.network").is_some());
        assert!(entry.matches("www.terp.network").is_some());
        assert!(entry.matches("sub.terp.network").is_some());
        assert!(entry.matches("other.com").is_none());
    }

    #[test]
    fn test_key_entry_longest_match() {
        let broad = KeyEntry::new("broad".into(), vec!["network".into()], "t1".into(), "z1".into());
        let specific = KeyEntry::new("specific".into(), vec!["terp.network".into()], "t2".into(), "z2".into());

        // "terp.network" matches both, but specific has longer match
        let broad_score = broad.matches("terp.network").unwrap_or(0);
        let specific_score = specific.matches("terp.network").unwrap_or(0);
        assert!(specific_score > broad_score);
    }

    #[test]
    fn test_store_roundtrip() {
        let tmp = std::env::temp_dir().join("oline-test-keys.enc");
        let _ = std::fs::remove_file(&tmp);

        let store = KeyStore::open(&tmp, "testpass");
        assert!(store.load().unwrap().is_empty());

        store.add(KeyEntry::new(
            "test".into(),
            vec!["example.com".into()],
            "tok123".into(),
            "zone456".into(),
        )).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cf_api_token, "tok123");

        let resolved = store.resolve("example.com").unwrap().unwrap();
        assert_eq!(resolved.label, "test");

        assert!(store.resolve("other.com").unwrap().is_none());

        assert_eq!(store.remove("test").unwrap(), 1);
        assert!(store.load().unwrap().is_empty());

        let _ = std::fs::remove_file(&tmp);
    }
}
