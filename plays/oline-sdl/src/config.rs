//! core config structures
//!
use serde::{Deserialize, Serialize};

use std::{
    collections::HashMap,
    error::Error,
    fs,
    io::{self},
    path::{Path, PathBuf},
};

use crate::{
    cli::{prompt_continue, read_input, read_secret_input, redact_if_secret},
    crypto::{decrypt_mnemonic, encrypt_mnemonic},
    snapshots::fetch_latest_snapshot_url,
};
// ── OLineConfig & OLineDeployer ──

#[derive(Serialize, Deserialize, Clone)]
pub struct OLineConfig {
    pub mnemonic: String,
    pub rpc_endpoint: String,
    pub grpc_endpoint: String,
    pub snapshot_url: String,
    pub validator_peer_id: String,
    pub trusted_providers: Vec<String>,
    pub auto_select_provider: bool,
    // S3 snapshot export (credentials auto-generated per deployment)
    pub snapshot_path: String,
    pub snapshot_time: String,
    pub snapshot_save_format: String,
    pub snapshot_retain: String,
    pub snapshot_keep_last: String,
    // MinIO-IPFS
    pub minio_ipfs_image: String,
    pub s3_bucket: String,
    pub autopin_interval: String,
    pub snapshot_download_domain: String,
    pub certbot_email: String,
    // Cloudflare DNS (optional — auto-update CNAME after Phase A deploy)
    pub cloudflare_api_token: String,
    pub cloudflare_zone_id: String,
    pub tls_config_url: String,
    pub entrypoint_url: String,
}

// ── Runtime defaults (loaded from env vars / .env, with hardcoded fallbacks) ──

#[derive(Clone)]
pub struct RuntimeDefaults {
    pub secret_keys: Vec<String>,
    pub env_key: String,
    pub sdl_dir: PathBuf,
    pub snapshot_state_url: String,
    pub snapshot_base_url: String,
    pub chain_json: String,
    pub addrbook_url: String,
    pub omnibus_image: String,
    pub minio_ipfs_image: String,
}

impl RuntimeDefaults {
    pub fn load() -> Self {
        Self {
            secret_keys: std::env::var("OLINE_SECRET_KEYS")
                .unwrap_or_else(|_| "S3_KEY,S3_SECRET,MINIO_ROOT_USER,MINIO_ROOT_PASSWORD,TERPD_P2P_PRIVATE_PEER_IDS,CF_API_TOKEN".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            env_key: std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into()),
            sdl_dir: PathBuf::from(std::env::var("OLINE_SDL_DIR").unwrap_or_else(|_| "sdls".into())),
            snapshot_state_url: std::env::var("OLINE_SNAPSHOT_STATE_URL").expect("latest snapshot json"),
            snapshot_base_url: std::env::var("OLINE_SNAPSHOT_BASE_URL").expect("snapshot server"),
            chain_json: std::env::var("OLINE_CHAIN_JSON").expect("chain json"),
            addrbook_url: std::env::var("OLINE_ADDRBOOK_URL").expect("addrbook"),
            omnibus_image: std::env::var("OLINE_OMNIBUS_IMAGE").expect("omnibus image"),
            minio_ipfs_image: std::env::var("OLINE_MINIO_IPFS_IMAGE").expect("minio-ipfs version")
        }
    }

    pub fn load_sdl(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        let path = self.sdl_dir.join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read SDL '{}': {}", path.display(), e).into())
    }

    pub fn is_secret(&self, key: &str) -> bool {
        self.secret_keys.iter().any(|s| s == key)
    }
}

// ── Config collection ──

// ── .env file helpers ──

/// Load KEY=VALUE pairs from .env file into process environment.
/// Skips comments (#), empty lines, and the encrypted mnemonic key.
/// Does not override env vars that are already set.
pub fn load_dotenv(env_key: &str) {
    let env_path = Path::new(".env");
    if let Ok(contents) = fs::read_to_string(env_path) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                // Don't load the encrypted mnemonic as a regular env var
                if key == env_key {
                    continue;
                }
                // Don't override existing env vars
                if std::env::var(key).is_err() {
                    std::env::set_var(key, value);
                }
            }
        }
    }
}

/// Resolve a default value with priority: env var > saved config > hardcoded default.
pub fn default_val(env_key: &str, saved: Option<&str>, hardcoded: &str) -> String {
    std::env::var(env_key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| saved.unwrap_or(hardcoded).to_string())
}

/// Like `default_val` but for optional values (no hardcoded fallback).
pub fn default_val_opt(env_key: &str, saved: Option<&str>) -> Option<String> {
    std::env::var(env_key)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| saved.map(String::from))
}

pub fn read_encrypted_mnemonic_from_env(env_key: &str) -> Result<String, Box<dyn Error>> {
    let env_path = Path::new(".env");
    if !env_path.exists() {
        return Err("No .env file found. Run `oline encrypt` first to store your mnemonic.".into());
    }

    let contents = fs::read_to_string(env_path)?;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix(&format!("{}=", env_key)) {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }

    Err(format!(
        "No {} found in .env file. Run `oline encrypt` first.",
        env_key
    )
    .into())
}

pub fn write_encrypted_mnemonic_to_env(env_key: &str, blob: &str) -> Result<(), Box<dyn Error>> {
    let env_path = Path::new(".env");
    let entry = format!("{}={}", env_key, blob);

    if env_path.exists() {
        let contents = fs::read_to_string(env_path)?;
        let mut found = false;
        let mut new_lines: Vec<String> = Vec::new();
        for line in contents.lines() {
            if line.trim().starts_with(&format!("{}=", env_key)) {
                new_lines.push(entry.clone());
                found = true;
            } else {
                new_lines.push(line.to_string());
            }
        }
        if !found {
            new_lines.push(entry);
        }
        fs::write(env_path, new_lines.join("\n") + "\n")?;
    } else {
        fs::write(env_path, format!("{}\n", entry))?;
    }

    Ok(())
}

// ── Config persistence ──
pub fn config_path() -> PathBuf {
    dirs::home_dir()
        .expect("Cannot determine home directory")
        .join(".oline")
        .join("config.enc")
}

pub fn save_config(c: &OLineConfig, pw: &str) -> Result<(), Box<dyn Error>> {
    let p = config_path();
    if let Some(p) = p.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(&p, encrypt_mnemonic(&serde_json::to_string(c)?, pw)?)?;
    Ok(())
}

pub fn load_config(password: &str) -> Option<OLineConfig> {
    let encrypted = fs::read_to_string(&config_path()).ok()?;
    serde_json::from_str(&decrypt_mnemonic(encrypted.trim(), password).ok()?).ok()
}

pub fn has_saved_config() -> bool {
    config_path().exists()
}

pub async fn collect_config(
    password: &str,
    mnemonic: String,
    lines: &mut io::Lines<io::StdinLock<'_>>,
    defaults: &RuntimeDefaults,
) -> Result<OLineConfig, Box<dyn Error>> {
    // Try to load saved config
    let saved = if has_saved_config() {
        if let Some(cfg) = load_config(password) {
            tracing::info!("  Found saved config:");
            tracing::info!("    RPC endpoint:     {}", cfg.rpc_endpoint);
            tracing::info!("    gRPC endpoint:    {}", cfg.grpc_endpoint);
            tracing::info!("    Snapshot URL:     {}", cfg.snapshot_url);
            tracing::info!(
                "    Validator peer:   {}",
                redact_if_secret(
                    "TERPD_P2P_PRIVATE_PEER_IDS",
                    &cfg.validator_peer_id,
                    defaults
                )
            );
            tracing::info!("    Trusted providers: {:?}", cfg.trusted_providers);
            tracing::info!("    Snapshot path:    {}", cfg.snapshot_path);
            tracing::info!("    MinIO-IPFS image: {}", cfg.minio_ipfs_image);
            tracing::info!("    S3 bucket:        {}", cfg.s3_bucket);
            tracing::info!(
                "    Cloudflare DNS:   {}",
                if cfg.cloudflare_api_token.is_empty() {
                    "not configured"
                } else {
                    "configured"
                }
            );

            if prompt_continue(lines, "Use saved config?")? {
                Some(cfg)
            } else {
                None
            }
        } else {
            tracing::info!("  Saved config found but could not decrypt (wrong password?). Continuing with fresh config.\n");
            None
        }
    } else {
        None
    };
    let d = default_val(
        "OLINE_RPC_ENDPOINT",
        saved.as_ref().map(|s| s.rpc_endpoint.as_str()),
        "https://rpc.akashnet.net:443",
    );
    let rpc_endpoint = read_input(lines, "RPC endpoint", Some(&d))?;

    let d = default_val(
        "OLINE_GRPC_ENDPOINT",
        saved.as_ref().map(|s| s.grpc_endpoint.as_str()),
        "https://grpc.akashnet.net:443",
    );
    let grpc_endpoint = read_input(lines, "gRPC endpoint", Some(&d))?;

    let snapshot_url = {
        let env_url = default_val_opt(
            "OLINE_SNAPSHOT_URL",
            saved.as_ref().map(|s| s.snapshot_url.as_str()),
        );
        if let Some(url) = env_url {
            read_input(lines, "Snapshot URL", Some(&url))?
        } else {
            match fetch_latest_snapshot_url(defaults).await {
                Ok(url) => read_input(lines, "Snapshot URL (fetched from itrocket)", Some(&url))?,
                Err(e) => {
                    tracing::info!("  Warning: failed to fetch snapshot: {}", e);
                    let url = read_input(lines, "Enter snapshot URL manually", None)?;
                    if url.is_empty() {
                        return Err("Snapshot URL is required.".into());
                    }
                    url
                }
            }
        }
    };

    let d = default_val_opt(
        "OLINE_VALIDATOR_PEER_ID",
        saved.as_ref().map(|s| s.validator_peer_id.as_str()),
    );
    let validator_peer_id = read_secret_input("Validator peer ID (id@host:port)", d.as_deref())?;
    if validator_peer_id.is_empty() {
        return Err("Validator peer ID is required.".into());
    }

    let d = default_val(
        "OLINE_TRUSTED_PROVIDERS",
        saved
            .as_ref()
            .map(|s| s.trusted_providers.join(","))
            .as_deref(),
        "",
    );
    let providers_input = read_input(
        lines,
        "Trusted provider addresses (comma-separated, or empty)",
        Some(&d),
    )?;
    let trusted_providers: Vec<String> = if providers_input.is_empty() {
        vec![]
    } else {
        providers_input
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    };

    let auto_default = if saved
        .as_ref()
        .map(|s| s.auto_select_provider)
        .unwrap_or(false)
    {
        "n"
    } else {
        "n"
    };
    let d = default_val("OLINE_AUTO_SELECT_PROVIDER", None, auto_default);
    let auto_select = read_input(lines, "Auto-select cheapest provider? (y/n)", Some(&d))?;
    let auto_select_provider = auto_select.is_empty() || auto_select == "y" || auto_select == "yes";

    // Snapshot export config (credentials auto-generated per deployment)
    tracing::info!("\n── Snapshot Export ──");
    tracing::info!("  Note: S3/MinIO credentials are auto-generated per deployment.");

    let d = default_val(
        "OLINE_SNAPSHOT_PATH",
        saved.as_ref().map(|s| s.snapshot_path.as_str()),
        "snapshots/terpnetwork",
    );
    let snapshot_path = read_input(lines, "S3 snapshot path (bucket/path)", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_TIME",
        saved.as_ref().map(|s| s.snapshot_time.as_str()),
        "00:00:00",
    );
    let snapshot_time = read_input(lines, "Snapshot schedule time (HH:MM:SS)", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_SAVE_FORMAT",
        saved.as_ref().map(|s| s.snapshot_save_format.as_str()),
        "tar.gz",
    );
    let snapshot_save_format = read_input(lines, "Snapshot save format", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_RETAIN",
        saved.as_ref().map(|s| s.snapshot_retain.as_str()),
        "2 days",
    );
    let snapshot_retain = read_input(lines, "Snapshot retention period", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_KEEP_LAST",
        saved.as_ref().map(|s| s.snapshot_keep_last.as_str()),
        "2",
    );
    let snapshot_keep_last = read_input(lines, "Minimum snapshots to keep", Some(&d))?;

    let d = default_val("TLS_CONFIG_URL", None, "");
    let tls_config_url = read_input(lines, "TLS setup command", Some(&d))?;

    let d = default_val("ENTRYPOINT_URL", None, "");
    let entrypoint_url = read_input(lines, "entrypoint url", Some(&d))?;

    // MinIO-IPFS config
    tracing::info!("\n── MinIO-IPFS ──");

    let d = default_val(
        "OLINE_MINIO_IPFS_IMAGE",
        saved.as_ref().map(|s| s.minio_ipfs_image.as_str()),
        &defaults.minio_ipfs_image,
    );
    let minio_ipfs_image = read_input(lines, "MinIO-IPFS image", Some(&d))?;

    let d = default_val(
        "OLINE_S3_BUCKET",
        saved.as_ref().map(|s| s.s3_bucket.as_str()),
        "terp-snapshots",
    );
    let s3_bucket = read_input(lines, "S3 bucket name", Some(&d))?;

    let d = default_val(
        "OLINE_AUTOPIN_INTERVAL",
        saved.as_ref().map(|s| s.autopin_interval.as_str()),
        "300",
    );
    let autopin_interval = read_input(lines, "IPFS auto-pin interval (seconds)", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_DOWNLOAD_DOMAIN",
        saved.as_ref().map(|s| s.snapshot_download_domain.as_str()),
        "snapshots.terp.network",
    );
    let snapshot_download_domain =
        read_input(lines, "Snapshot download domain (public S3 API)", Some(&d))?;

    let d = default_val(
        "OLINE_CERTBOT_EMAIL",
        saved.as_ref().map(|s| s.certbot_email.as_str()),
        "admin@terp.network",
    );
    let certbot_email = read_input(
        lines,
        "Certbot email (Let's Encrypt registration for nginx-snapshot)",
        Some(&d),
    )?;

    // Cloudflare DNS (optional — auto-update CNAME after deploy)
    tracing::info!("\n── Cloudflare DNS (optional) ──");
    tracing::info!("  Set these to auto-update CNAME records after deployment.");
    tracing::info!("  Leave empty to skip automatic DNS updates.\n");

    let d = default_val_opt(
        "OLINE_CF_API_TOKEN",
        saved
            .as_ref()
            .map(|s| s.cloudflare_api_token.as_str())
            .filter(|s| !s.is_empty()),
    );
    let cloudflare_api_token =
        read_secret_input("Cloudflare API token (DNS:Edit permission)", d.as_deref())?;

    let d = default_val_opt(
        "OLINE_CF_ZONE_ID",
        saved
            .as_ref()
            .map(|s| s.cloudflare_zone_id.as_str())
            .filter(|s| !s.is_empty()),
    );
    let cloudflare_zone_id = read_input(lines, "Cloudflare zone ID", d.as_deref())?;

    let config = OLineConfig {
        mnemonic,
        rpc_endpoint,
        grpc_endpoint,
        snapshot_url,
        validator_peer_id,
        trusted_providers,
        auto_select_provider,
        snapshot_path,
        snapshot_time,
        snapshot_save_format,
        snapshot_retain,
        snapshot_keep_last,
        minio_ipfs_image,
        s3_bucket,
        autopin_interval,
        snapshot_download_domain,
        certbot_email,
        cloudflare_api_token,
        cloudflare_zone_id,
        tls_config_url,
        entrypoint_url,
    };

    // Offer to save
    if prompt_continue(lines, "Save config for next time?")? {
        if let Err(e) = save_config(&config, password) {
            tracing::info!("  Warning: failed to save config: {}", e);
        } else {
            tracing::info!("  Config saved to {}", config_path().display());
        }
    }

    Ok(config)
}

/// Helper to insert the shared SDL template variables into a HashMap.
pub fn insert_sdl_defaults(vars: &mut HashMap<String, String>, defaults: &RuntimeDefaults) {
    vars.insert("OMNIBUS_IMAGE".into(), defaults.omnibus_image.clone());
    vars.insert("CHAIN_JSON".into(), defaults.chain_json.clone());
    vars.insert("ADDRBOOK_URL".into(), defaults.addrbook_url.clone());
    vars.insert("ADDRBOOK_URL".into(), defaults.addrbook_url.clone());
}

// ── Raw template substitution ──

/// Raw text-based `${VAR}` substitution. Unlike `apply_template` (which is
/// YAML-aware and only substitutes values), this replaces placeholders
/// everywhere — including YAML mapping keys like `${SNAPSHOT_SVC}:`.
pub fn substitute_template_raw(
    template: &str,
    variables: &HashMap<String, String>,
    defaults: &HashMap<String, String>,
) -> Result<String, Box<dyn Error>> {
    let mut values = defaults.clone();
    values.extend(variables.clone());

    let mut result = String::new();
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
            i += 2; // skip ${
            let start = i;
            while i < chars.len() && chars[i] != '}' {
                i += 1;
            }
            if i >= chars.len() {
                return Err("Unclosed ${...} placeholder in template".into());
            }
            let var_name: String = chars[start..i].iter().collect();
            match values.get(&var_name) {
                Some(val) => result.push_str(val),
                None => return Err(format!("Variable '{}' has no value", var_name).into()),
            }
            i += 1; // skip }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    Ok(result)
}

pub fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Simple Gregorian calendar conversion from days since epoch
    let mut y = 1970;
    let mut remaining = days;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let month_days: [u64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }

    (y, (m + 1) as u64, remaining + 1)
}

pub fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}
