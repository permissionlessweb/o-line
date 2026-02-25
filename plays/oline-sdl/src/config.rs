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
    cli::{prompt_continue, read_input},
    crypto::{decrypt_mnemonic, encrypt_mnemonic},
    FIELD_DESCRIPTORS,
};

// ── Field descriptors — the single source of truth for collection logic ───────
/// c = category\
/// k = key\
/// ev = env_var\
/// p = prompt\
/// d = default; empty string "" for optional fields\
/// s = secret
// ── OLineConfig & OLineDeployer ──
#[derive(Clone, Debug)]
pub struct Fd {
    /// c = category\
    pub c: &'static str,
    /// k = key\
    pub k: &'static str,
    /// ev = env_var\
    pub ev: &'static str,
    /// p = prompt\
    pub p: &'static str,
    /// d = default; empty string "" for optional fields\
    pub d: &'static str,
    /// s = secret
    pub s: bool,
}

// ── OLineConfig & OLineDeployer ──
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OLineConfig {
    pub mnemonic: String, // kept typed — always required
    #[serde(flatten)]
    pub categories: HashMap<String, ConfigCategory>,
}

impl OLineConfig {
    pub fn sdl_dir(&self) -> PathBuf {
        PathBuf::from(self.val("default.sdl_dir"))
    }
    pub fn load_sdl(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        let path = self.sdl_dir().join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read SDL '{}': {}", path.display(), e).into())
    }
    pub fn category(&self, name: &str) -> Option<&ConfigCategory> {
        self.categories.get(name)
    }

    pub fn category_mut(&mut self, name: &str) -> &mut ConfigCategory {
        self.categories.entry(name.to_string()).or_default()
    }

    /// Convenience: read a value from any category with "category.key" dot syntax.
    pub fn get(&self, path: &str) -> Option<&ConfigValue> {
        let (cat, key) = path.split_once('.')?;
        self.category(cat)?.get(key)
    }

    pub fn get_str(&self, path: &str) -> Option<&str> {
        self.get(path)?.as_str()
    }
    pub fn val(&self, path: &str) -> String {
        self.get_str(path).unwrap_or("").to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConfigCategory {
    #[serde(flatten)]
    fields: HashMap<String, ConfigValue>,
}

impl ConfigCategory {
    pub fn get(&self, k: &str) -> Option<&ConfigValue> {
        self.fields.get(k)
    }

    pub fn set(&mut self, k: impl Into<String>, value: impl Into<ConfigValue>) {
        self.fields.insert(k.into(), value.into());
    }

    pub fn get_str(&self, k: &str) -> Option<&str> {
        self.get(k)?.as_str()
    }

    pub fn get_str_or<'a>(&'a self, k: &str, d: &'a str) -> &'a str {
        self.get_str(k).unwrap_or(d)
    }

    pub fn get_bool(&self, k: &str) -> Option<bool> {
        self.get(k)?.as_bool()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &ConfigValue)> {
        self.fields.iter()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ConfigValue {
    Text(String),
    Bool(bool),
    List(Vec<String>),
}
impl ConfigValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&Vec<String>> {
        match self {
            Self::List(v) => Some(v),
            _ => None,
        }
    }
}
impl From<String> for ConfigValue {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}
impl From<&str> for ConfigValue {
    fn from(s: &str) -> Self {
        Self::Text(s.to_string())
    }
}
impl From<bool> for ConfigValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}
impl From<Vec<String>> for ConfigValue {
    fn from(v: Vec<String>) -> Self {
        Self::List(v)
    }
}

#[macro_export]
macro_rules! define_fields {
    (
        $(
            $c:literal / $k:literal =>
                $ev:literal, $p:literal, $d:literal, $s:literal
        ),*
        $(,)?
    ) => {
        &[
            $(
                crate::config::Fd {
                    c:  $c,
                    k:  $k,
                    ev: $ev,
                    p:  $p,
                    d:  $d,
                    s:  $s,
                }
            ),*
        ]
    };
}
// impl RuntimeDefaults {
//     pub fn load() -> Self {
//         Self {
//             secret_keys: std::env::var("OLINE_SECRET_KEYS")
//                 .unwrap_or_else(|_| "S3_KEY,S3_SECRET,MINIO_ROOT_USER,MINIO_ROOT_PASSWORD,TERPD_P2P_PRIVATE_PEER_IDS,CF_API_TOKEN".into())
//                 .split(',')
//                 .map(|s| s.trim().to_string())
//                 .collect(),
//             env_key: std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into()),
//             sdl_dir: PathBuf::from(std::env::var("SDL_DIR").unwrap_or_else(|_| "sdls".into())),
//             snapshot_state_url: std::env::var("OLINE_SNAPSHOT_STATE_URL").expect("latest snapshot json"),
//             snapshot_base_url: std::env::var("OLINE_SNAPSHOT_BASE_URL").expect("snapshot server"),
//             chain_json: ,
//             addrbook_url: ,
//             omnibus_image:
//             minio_ipfs_image: std::env::var("MINIO_IPFS_IMAGE").expect("minio-ipfs version")
//         }
//     }
// }
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

pub fn read_encrypted_mnemonic_from_env() -> Result<String, Box<dyn Error>> {
    let env_path = Path::new(".env");
    if !env_path.exists() {
        return Err("No .env file found. Run `oline encrypt` first to store your mnemonic.".into());
    }
    let env_key =
        std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into());
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

pub fn write_encrypted_mnemonic_to_env(blob: &str) -> Result<(), Box<dyn Error>> {
    let env_path = Path::new(".env");
    let env_key =
        std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into());
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
) -> Result<OLineConfig, Box<dyn Error>> {
    // Try to load saved config
    let saved = if has_saved_config() {
        if let Some(cfg) = load_config(password) {
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

    let mut cfg = OLineConfig {
        mnemonic,
        ..Default::default()
    };

    for fd in FIELD_DESCRIPTORS.iter() {
        let saved_val = saved
            .as_ref()
            .and_then(|s| s.get_str(&format!("{}.{}", fd.c, fd.k)));

        let d = default_val(fd.ev, saved_val, fd.d);

        let value = if fd.s && !d.is_empty() {
            d // don't re-prompt secrets that are already set
        } else {
            read_input(lines, fd.p, Some(&d))?
        };

        cfg.category_mut(fd.c).set(fd.k, value);
    }

    // Offer to save
    if prompt_continue(lines, "Save config for next time?")? {
        if let Err(e) = save_config(&cfg, password) {
            tracing::info!("  Warning: failed to save config: {}", e);
        } else {
            tracing::info!("  Config saved to {}", config_path().display());
        }
    }

    Ok(cfg)
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
