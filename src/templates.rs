//! Named deployment templates.
//!
//! A template provides a named, curated set of config overrides applied on top of
//! the TOML config defaults.

use crate::{
    config::OLineConfig,
    toml_config::TomlConfig,
};

// ── Template definition ───────────────────────────────────────────────────────

pub struct DeployTemplate {
    pub name: &'static str,
    pub description: &'static str,
    /// Per-field overrides: `(config_path, value)`.
    /// Applied on top of TOML config defaults.
    pub overrides: &'static [(&'static str, &'static str)],
}

impl DeployTemplate {
    /// Build a fully-populated `OLineConfig` from TOML defaults + template overrides.
    /// Env vars still take highest priority.
    pub fn build_config(&self) -> OLineConfig {
        let mut toml_cfg = TomlConfig::from_defaults();
        // Apply template overrides before env resolution
        for (path, value) in self.overrides {
            toml_cfg.set_value(path, value.to_string());
        }
        // Re-apply env overrides (they take priority)
        toml_cfg.apply_env_overrides();
        OLineConfig::from_toml(&toml_cfg, String::new())
    }
}

// ── Built-in templates ────────────────────────────────────────────────────────

/// Terp Network mainnet — all values match the config defaults.
const TERP_MAINNET: DeployTemplate = DeployTemplate {
    name: "terp-mainnet",
    description: "Terp Network mainnet (morocco-1) — default config",
    overrides: &[],
};

pub const TEMPLATES: &[&DeployTemplate] = &[&TERP_MAINNET];

// ── Lookup helpers ────────────────────────────────────────────────────────────

pub fn find(name: &str) -> Option<&'static DeployTemplate> {
    TEMPLATES.iter().copied().find(|t| t.name == name)
}

pub fn list_all() -> impl Iterator<Item = &'static DeployTemplate> {
    TEMPLATES.iter().copied()
}
