//! AuthZ delegation state management for o-line.
//!
//! Handles the local deployer key and grant metadata that enables
//! passwordless deployment via Cosmos SDK AuthZ + FeeGrant.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use akash_deploy_rs::AuthzConfig;

use crate::config::{oline_authz_config_path, oline_deployer_key_path};

/// Check if AuthZ delegation is configured (both deployer.key and authz.json exist).
pub fn has_authz_setup() -> bool {
    oline_deployer_key_path().exists() && oline_authz_config_path().exists()
}

/// Load the deployer mnemonic from the unencrypted key file.
pub fn load_deployer_mnemonic() -> Result<String, String> {
    let path = oline_deployer_key_path();
    fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("failed to read deployer key at {}: {}", path.display(), e))
}

/// Load the persisted AuthZ config metadata.
pub fn load_authz_state() -> Option<AuthzConfig> {
    let path = oline_authz_config_path();
    let data = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Save AuthZ config metadata to disk.
pub fn save_authz_state(state: &AuthzConfig) -> Result<(), String> {
    let path = oline_authz_config_path();
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("failed to serialize authz config: {}", e))?;
    fs::write(&path, json)
        .map_err(|e| format!("failed to write authz config to {}: {}", path.display(), e))
}

/// Generate a new 24-word BIP39 mnemonic.
pub fn generate_deployer_mnemonic() -> String {
    use coins_bip39::{English, Mnemonic};
    let mnemonic = Mnemonic::<English>::new(&mut rand::thread_rng());
    mnemonic.to_phrase()
}

/// Write the deployer mnemonic to disk with restrictive permissions (0600).
pub fn write_deployer_key(mnemonic: &str) -> Result<PathBuf, String> {
    let path = oline_deployer_key_path();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("failed to create deployer key at {}: {}", path.display(), e))?;
    file.write_all(mnemonic.as_bytes())
        .map_err(|e| format!("failed to write deployer key: {}", e))?;
    Ok(path)
}

/// Remove the deployer key and authz config files.
pub fn remove_authz_files() -> Result<(), String> {
    let key_path = oline_deployer_key_path();
    let config_path = oline_authz_config_path();

    if key_path.exists() {
        fs::remove_file(&key_path)
            .map_err(|e| format!("failed to remove {}: {}", key_path.display(), e))?;
    }
    if config_path.exists() {
        fs::remove_file(&config_path)
            .map_err(|e| format!("failed to remove {}: {}", config_path.display(), e))?;
    }
    Ok(())
}
