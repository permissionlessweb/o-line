//! Encrypted persistent store for IPFS-hosted static websites.
//!
//! `SiteStore` maintains a JSON array of `SiteRecord`s encrypted with AES-256-GCM
//! using the same Argon2id + random salt/nonce scheme as `encrypt_mnemonic`.
//! The store file is kept at `$SECRETS_PATH/sites.enc` (default: `./sites.enc`).

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

/// A single IPFS-hosted static site managed by o-line.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SiteRecord {
    /// Public domain for the site (e.g. `mysite.example.com`).
    pub domain: String,
    /// Current IPFS CID pinned at this domain (empty until first publish).
    pub cid: String,
    /// Akash deployment sequence number for the minio-ipfs container.
    pub dseq: u64,
    /// S3 bucket name inside the minio instance.
    pub bucket: String,
    /// MinIO S3 access key.
    pub s3_key: String,
    /// MinIO S3 secret key.
    pub s3_secret: String,
    /// MinIO S3 endpoint (e.g. `http://provider.akash.host:32000`).
    pub s3_host: String,
    /// Cloudflare zone ID used for DNS updates.
    pub cf_zone_id: String,
    /// Unix timestamp (seconds) when first deployed.
    pub created_at: u64,
    /// Unix timestamp (seconds) of last CID update.
    pub updated_at: u64,
}

impl SiteRecord {
    pub fn new(
        domain: String,
        dseq: u64,
        bucket: String,
        s3_key: String,
        s3_secret: String,
        s3_host: String,
        cf_zone_id: String,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            domain,
            cid: String::new(),
            dseq,
            bucket,
            s3_key,
            s3_secret,
            s3_host,
            cf_zone_id,
            created_at: now,
            updated_at: now,
        }
    }
}

// ── Store ──────────────────────────────────────────────────────────────────────

/// Encrypted collection of `SiteRecord`s.
pub struct SiteStore {
    path: PathBuf,
    password: String,
}

impl SiteStore {
    /// Open (or create) a site store at the given path, encrypted with `password`.
    pub fn open(path: impl AsRef<Path>, password: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password: password.into(),
        }
    }

    /// Default path: `$SECRETS_PATH/sites.enc` (falls back to `./sites.enc`).
    pub fn default_path() -> PathBuf {
        let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        PathBuf::from(dir).join("sites.enc")
    }

    /// Load and decrypt all records. Returns an empty vec if the file doesn't exist.
    pub fn load(&self) -> Result<Vec<SiteRecord>, Box<dyn Error>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let blob = std::fs::read_to_string(&self.path)?;
        let json = decrypt_sites(&blob, &self.password)?;
        let records: Vec<SiteRecord> = serde_json::from_str(&json)?;
        Ok(records)
    }

    /// Encrypt and persist `records`.
    pub fn save(&self, records: &[SiteRecord]) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string(records)?;
        let blob = encrypt_sites(&json, &self.password)?;
        std::fs::write(&self.path, blob)?;
        Ok(())
    }

    /// Append a new record and persist.
    pub fn add(&self, record: SiteRecord) -> Result<(), Box<dyn Error>> {
        let mut records = self.load()?;
        records.push(record);
        self.save(&records)
    }

    /// Replace the record matching `domain` and persist.  Returns `false` if not found.
    pub fn update(&self, domain: &str, f: impl FnOnce(&mut SiteRecord)) -> Result<bool, Box<dyn Error>> {
        let mut records = self.load()?;
        if let Some(rec) = records.iter_mut().find(|r| r.domain == domain) {
            f(rec);
            rec.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.save(&records)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Find a record by domain.
    pub fn get(&self, domain: &str) -> Result<Option<SiteRecord>, Box<dyn Error>> {
        Ok(self.load()?.into_iter().find(|r| r.domain == domain))
    }
}

// ── Encryption helpers ─────────────────────────────────────────────────────────

fn encrypt_sites(plaintext: &str, password: &str) -> Result<String, Box<dyn Error>> {
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

fn decrypt_sites(blob: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let data = BASE64.decode(blob.trim())?;
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("Sites store blob too short".into());
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
        .map_err(|_| "Sites store decryption failed — wrong password?")?;
    String::from_utf8(plaintext).map_err(Into::into)
}
