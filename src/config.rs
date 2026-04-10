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
    cli::{print_config_table, prompt_continue, read_input, read_override_selection, read_secret_input},
    crypto::{decrypt_mnemonic, encrypt_mnemonic},
    FIELD_DESCRIPTORS,
};

// ── Field descriptors — the single source of truth for collection logic ───────
/// ev = env_var (also used as the config storage key)\
/// p = prompt\
/// d = default; empty string "" for optional fields\
/// s = secret
// ── OLineConfig & OLineDeployer ──
#[derive(Clone, Debug)]
pub struct Fd {
    /// ev = env_var (also the config key)
    pub ev: &'static str,
    /// p = prompt
    pub p: &'static str,
    /// d = default; empty string "" for optional fields
    pub d: &'static str,
    /// s = secret
    pub s: bool,
}

// ── OLineConfig & OLineDeployer ──
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OLineConfig {
    pub mnemonic: String, // kept typed — always required
    #[serde(flatten)]
    pub fields: HashMap<String, ConfigValue>,
}

impl OLineConfig {
    pub fn sdl_dir(&self) -> PathBuf {
        PathBuf::from(self.val("SDL_DIR"))
    }
    pub fn load_sdl(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        let path = self.sdl_dir().join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read SDL '{}': {}", path.display(), e).into())
    }

    pub fn get(&self, key: &str) -> Option<&ConfigValue> {
        self.fields.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key)?.as_str()
    }

    pub fn val(&self, key: &str) -> String {
        self.get_str(key).unwrap_or("").to_string()
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<ConfigValue>) {
        self.fields.insert(key.into(), value.into());
    }

    /// Return a `HashMap<fd.ev, resolved_value>` for every field descriptor.
    ///
    /// This is the base variable map for SDL template substitution.
    /// SDL templates should use `${fd.ev}` as placeholder names.
    /// Computed/runtime variables (SSH keypairs, S3 creds, peer IDs, accept
    /// lists, etc.) must be inserted by the caller after this call.
    pub fn to_sdl_vars(&self) -> std::collections::HashMap<String, String> {
        let mut vars = std::collections::HashMap::new();
        for fd in crate::FIELD_DESCRIPTORS.iter() {
            vars.insert(fd.ev.to_string(), self.val(fd.ev));
        }
        vars
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
            $ev:literal, $p:literal, $d:literal, $s:literal
        ),*
        $(,)?
    ) => {
        &[
            $(
                crate::config::Fd {
                    ev: $ev,
                    p:  $p,
                    d:  $d,
                    s:  $s,
                }
            ),*
        ]
    };
}
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

/// Resolve a field value with priority: **env var > override > FD default**.
///
/// This is the canonical resolution function used everywhere a field is loaded
/// from descriptors — templates, `--load-config`, interactive prompts, and
/// `collect_config`. Env vars always win.
pub fn resolve_fd_value(fd: &Fd, override_val: Option<&str>) -> String {
    std::env::var(fd.ev)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            override_val
                .filter(|v| !v.is_empty())
                .unwrap_or(fd.d)
                .to_string()
        })
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

/// Update or append `KEY=VALUE` in `.env`, preserving all other lines.
pub fn upsert_env_key(key: &str, value: &str) -> Result<(), Box<dyn Error>> {
    let env_path = Path::new(".env");
    let new_entry = format!("{}={}", key, value);
    let prefix = format!("{}=", key);

    if env_path.exists() {
        let contents = fs::read_to_string(env_path)?;
        let mut new_lines: Vec<String> = Vec::new();
        let mut found = false;
        for line in contents.lines() {
            if line.trim_start().starts_with(&prefix) {
                new_lines.push(new_entry.clone());
                found = true;
            } else {
                new_lines.push(line.to_string());
            }
        }
        if !found {
            new_lines.push(new_entry);
        }
        fs::write(env_path, new_lines.join("\n") + "\n")?;
    } else {
        fs::write(env_path, format!("{}\n", new_entry))?;
    }

    Ok(())
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

/// Build an `OLineConfig` entirely from environment variables and FD defaults.
///
/// Used for non-interactive / CI invocations (`OLINE_NON_INTERACTIVE=1`) where
/// no human is present to answer config prompts.  Every field is resolved via
/// `resolve_fd_value`, so setting the corresponding env var (e.g. `OMNIBUS_IMAGE`,
/// `OLINE_RPC_ENDPOINT`, …) controls the value; unset fields fall back to their
/// hardcoded FD defaults.
pub fn build_config_from_env(mnemonic: String) -> OLineConfig {
    let mut cfg = OLineConfig {
        mnemonic,
        ..Default::default()
    };
    for fd in FIELD_DESCRIPTORS.iter() {
        let value = resolve_fd_value(fd, None);
        cfg.set(fd.ev, value);
    }
    cfg
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
    // Load saved config silently — use it as baseline if available.
    let saved = if has_saved_config() {
        match load_config(password) {
            Some(cfg) => {
                tracing::info!("  Loaded saved config.\n");
                Some(cfg)
            }
            None => {
                tracing::info!("  Saved config found but could not decrypt (wrong password?). Using defaults.\n");
                None
            }
        }
    } else {
        None
    };

    // Resolve all values: env var > saved config > FD default.
    let resolved_values: Vec<String> = FIELD_DESCRIPTORS
        .iter()
        .map(|fd| {
            let saved_val = saved
                .as_ref()
                .and_then(|s| s.get_str(fd.ev));
            resolve_fd_value(fd, saved_val)
        })
        .collect();

    // Show numbered overview; let user pick which fields to override.
    print_config_table(&resolved_values);
    let overrides = read_override_selection(lines)?;

    let mut cfg = OLineConfig {
        mnemonic,
        ..Default::default()
    };

    for (i, fd) in FIELD_DESCRIPTORS.iter().enumerate() {
        let value = if overrides.contains(&i) {
            if fd.s {
                read_secret_input(fd.p, Some(&resolved_values[i]))?
            } else {
                read_input(lines, fd.p, Some(&resolved_values[i]))?
            }
        } else {
            resolved_values[i].clone()
        };
        cfg.set(fd.ev, value);
    }

    // Offer to save updated config.
    if prompt_continue(lines, "Save config for next time?")? {
        if let Err(e) = save_config(&cfg, password) {
            tracing::info!("  Warning: failed to save config: {}", e);
        } else {
            tracing::info!("  Config saved to {}", config_path().display());
        }
    }

    Ok(cfg)
}

// ── Portable deployment config ──

/// Peer ID strings used as SDL rendering inputs.
/// Empty strings mean "not yet deployed / not yet known".
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PeerInputs {
    pub snapshot: String,
    pub seed: String,
    pub statesync_rpc: String,
    pub left_tackle: String,
    pub right_tackle: String,
}

/// A portable, non-secret snapshot of the deployment configuration.
///
/// Omits the mnemonic and all fields marked secret (`Fd.s = true`).
/// Safe to commit alongside SDL files or share with teammates.
/// Load it with `oline sdl --load-config` to skip interactive prompts.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DeployConfig {
    /// Non-secret config values keyed by env var name.
    pub config: HashMap<String, String>,
    /// Peer IDs and statesync RPC inputs for SDL rendering.
    pub peers: PeerInputs,
}

impl DeployConfig {
    /// Build from an `OLineConfig`, stripping the mnemonic and all secret fields.
    pub fn from_config(c: &OLineConfig, descriptors: &[Fd], peers: PeerInputs) -> Self {
        let mut config: HashMap<String, String> = HashMap::new();
        for fd in descriptors {
            if fd.s {
                continue;
            }
            config.insert(fd.ev.to_string(), c.val(fd.ev));
        }
        Self { config, peers }
    }

    /// Serialize to pretty-printed JSON and write to a file, creating parent dirs as needed.
    pub fn write_to_file(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

// ── Raw template substitution ──

/// Raw text-based `${VAR}` substitution. Unlike `apply_template` (which is
/// YAML-aware and only substitutes values), this replaces placeholders
/// everywhere — including YAML mapping keys like `${SNAPSHOT_SVC}:`.
pub fn substitute_template_raw(
    template: &str,
    variables: &HashMap<String, String>,
) -> Result<String, Box<dyn Error>> {
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
            match variables.get(&var_name) {
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

/// Inject `credentials:` blocks into rendered SDL for services whose `image:` matches the
/// registry URL.
///
/// Parses the SDL as YAML, walks each service profile, and if its `image` starts with
/// `registry_host`, inserts a `credentials` mapping with `host`, `username`, `password`.
/// Re-serializes to YAML.
///
/// Called after `substitute_template_raw()` when `OLINE_REGISTRY_URL` is non-empty.
pub fn inject_registry_credentials(
    rendered_sdl: &str,
    registry_url: &str,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn Error>> {
    let mut doc: serde_yaml::Value = serde_yaml::from_str(rendered_sdl)?;

    // Strip scheme for host matching
    let registry_host = registry_url
        .trim_end_matches('/')
        .strip_prefix("https://")
        .or_else(|| registry_url.strip_prefix("http://"))
        .unwrap_or(registry_url);

    // Walk services → each service → image field
    if let Some(services) = doc.get_mut("services") {
        if let Some(services_map) = services.as_mapping_mut() {
            for (_svc_name, svc_val) in services_map.iter_mut() {
                if let Some(svc_map) = svc_val.as_mapping_mut() {
                    let matches = svc_map
                        .get(&serde_yaml::Value::String("image".to_string()))
                        .and_then(|v| v.as_str())
                        .map(|img| img.starts_with(registry_host))
                        .unwrap_or(false);

                    if matches {
                        let mut creds = serde_yaml::Mapping::new();
                        creds.insert(
                            serde_yaml::Value::String("host".to_string()),
                            serde_yaml::Value::String(registry_host.to_string()),
                        );
                        creds.insert(
                            serde_yaml::Value::String("username".to_string()),
                            serde_yaml::Value::String(username.to_string()),
                        );
                        creds.insert(
                            serde_yaml::Value::String("password".to_string()),
                            serde_yaml::Value::String(password.to_string()),
                        );
                        svc_map.insert(
                            serde_yaml::Value::String("credentials".to_string()),
                            serde_yaml::Value::Mapping(creds),
                        );
                    }
                }
            }
        }
    }

    Ok(serde_yaml::to_string(&doc)?)
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
