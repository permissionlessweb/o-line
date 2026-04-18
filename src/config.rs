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
    toml_config::{TomlConfig, CONFIG_FIELDS},
};

// ── OLineConfig ──
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OLineConfig {
    pub mnemonic: String, // kept typed — always required
    #[serde(flatten)]
    pub fields: HashMap<String, ConfigValue>,
    /// When loaded from TOML, holds the parsed config for subdomain derivation etc.
    #[serde(skip)]
    pub toml_source: Option<TomlConfig>,
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

    /// Return a `HashMap<key, value>` for SDL template substitution.
    pub fn to_sdl_vars(&self) -> HashMap<String, String> {
        if let Some(ref toml) = self.toml_source {
            return toml.to_sdl_vars();
        }
        // Fallback: dump all text fields
        self.fields
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()
    }

    /// Build from a TomlConfig, populating the fields HashMap from SDL vars.
    pub fn from_toml(toml: &TomlConfig, mnemonic: String) -> Self {
        let sdl_vars = toml.to_sdl_vars();
        let mut cfg = OLineConfig {
            mnemonic,
            toml_source: Some(toml.clone()),
            ..Default::default()
        };
        for (k, v) in &sdl_vars {
            cfg.set(k.clone(), v.clone());
        }
        cfg
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

pub fn load_dotenv(env_key: &str) {
    let env_file = std::env::var("OLINE_ENV_FILE").unwrap_or_else(|_| ".env".into());
    let env_path = Path::new(&env_file);
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

pub fn read_encrypted_mnemonic_from_env() -> Result<String, Box<dyn Error>> {
    let env_file = std::env::var("OLINE_ENV_FILE").unwrap_or_else(|_| ".env".into());
    let env_path = Path::new(&env_file);
    if !env_path.exists() {
        return Err(format!("No {} file found. Run `oline encrypt` first to store your mnemonic.", env_file).into());
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

/// Build an `OLineConfig` from TOML config file + env var overrides.
///
/// Loads `config.toml` if present, otherwise uses struct defaults.
/// All fields are overridable via deterministic env vars: `OLINE_<PATH>`.
pub fn build_config_from_env(mnemonic: String) -> OLineConfig {
    let toml_cfg = if Path::new("config.toml").exists() {
        match TomlConfig::load("config.toml") {
            Ok(t) => {
                tracing::info!("  Loaded config.toml");
                t
            }
            Err(e) => {
                tracing::warn!("  Failed to parse config.toml: {} — using defaults + env", e);
                TomlConfig::from_defaults()
            }
        }
    } else {
        TomlConfig::from_defaults()
    };

    OLineConfig::from_toml(&toml_cfg, mnemonic)
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

/// Collect deployment config interactively using TOML config fields.
pub async fn collect_config(
    password: &str,
    mnemonic: String,
    lines: &mut io::Lines<impl io::BufRead>,
) -> Result<OLineConfig, Box<dyn Error>> {
    // Load TOML config as baseline
    let mut toml_cfg = if Path::new("config.toml").exists() {
        match TomlConfig::load("config.toml") {
            Ok(t) => {
                tracing::info!("  Loaded config.toml");
                t
            }
            Err(e) => {
                tracing::warn!("  Failed to parse config.toml: {}", e);
                TomlConfig::from_defaults()
            }
        }
    } else {
        TomlConfig::from_defaults()
    };

    // Merge saved config values if available
    if has_saved_config() {
        tracing::info!("  Found saved config.");
        if let Some(saved) = load_config(password) {
            // Apply saved values as fallbacks for empty TOML fields
            for field in CONFIG_FIELDS {
                let env_var = crate::toml_config::env_key(field.path);
                if toml_cfg.get_value(field.path).is_empty() {
                    if let Some(saved_val) = saved.get_str(&env_var) {
                        if !saved_val.is_empty() {
                            toml_cfg.set_value(field.path, saved_val.to_string());
                        }
                    }
                }
            }
        }
    }

    // Resolve current values for display
    let resolved: Vec<String> = CONFIG_FIELDS
        .iter()
        .map(|f| toml_cfg.get_value(f.path))
        .collect();

    // Show table and let user pick overrides
    print_config_table(&resolved);
    let overrides = read_override_selection(lines)?;

    for (i, field) in CONFIG_FIELDS.iter().enumerate() {
        if overrides.contains(&i) {
            let value = if field.is_secret {
                read_secret_input(field.description, Some(&resolved[i]))?
            } else {
                read_input(lines, field.description, Some(&resolved[i]))?
            };
            toml_cfg.set_value(field.path, value);
        }
    }

    let cfg = OLineConfig::from_toml(&toml_cfg, mnemonic);

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

// ── Portable deployment config ──

/// Peer ID strings used as SDL rendering inputs.
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
/// Omits the mnemonic and all fields marked secret.
/// Safe to commit alongside SDL files or share with teammates.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DeployConfig {
    pub config: HashMap<String, String>,
    pub peers: PeerInputs,
}

impl DeployConfig {
    /// Build from an `OLineConfig`, stripping secrets.
    pub fn from_oline_config(c: &OLineConfig, peers: PeerInputs) -> Self {
        let mut config: HashMap<String, String> = HashMap::new();
        for field in CONFIG_FIELDS {
            if field.is_secret {
                continue;
            }
            let env_var = crate::toml_config::env_key(field.path);
            config.insert(env_var, c.val(&crate::toml_config::env_key(field.path)));
        }
        // Also include SDL var keys from the TOML source for full compat
        if let Some(ref toml) = c.toml_source {
            for (k, v) in toml.to_sdl_vars() {
                if !TomlConfig::is_secret_env(&k) {
                    config.entry(k).or_insert(v);
                }
            }
        }
        Self { config, peers }
    }

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

/// Raw text-based `${VAR}` substitution.
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

/// Inject `credentials:` blocks into rendered SDL for services whose `image:` matches
/// the registry URL.
pub fn inject_registry_credentials(
    rendered_sdl: &str,
    registry_url: &str,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn Error>> {
    let mut doc: serde_yaml::Value = serde_yaml::from_str(rendered_sdl)?;

    let registry_host = registry_url
        .trim_end_matches('/')
        .strip_prefix("https://")
        .or_else(|| registry_url.strip_prefix("http://"))
        .unwrap_or(registry_url);

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
