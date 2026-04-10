//! Named deployment templates.
//!
//! A template provides a named, curated set of field overrides applied on top of
//! the baseline `FIELD_DESCRIPTORS` defaults.  Running `oline init --template <name>`
//! is non-interactive: it builds an `OLineConfig` directly from FD defaults + template
//! overrides and writes `deploy-config.json` without any prompts.

use crate::{
    config::{resolve_fd_value, OLineConfig},
    FIELD_DESCRIPTORS,
};

// ── Template definition ───────────────────────────────────────────────────────

pub struct DeployTemplate {
    pub name: &'static str,
    pub description: &'static str,
    /// Per-field overrides: `(env_var, value)`.
    /// Applied on top of `FIELD_DESCRIPTORS` defaults.
    pub overrides: &'static [(&'static str, &'static str)],
}

impl DeployTemplate {
    /// Build a fully-populated `OLineConfig` from FIELD_DESCRIPTOR defaults
    /// plus this template's overrides — no user input required.
    /// Build a fully-populated `OLineConfig`.
    ///
    /// Resolution order (highest → lowest):
    /// 1. Environment variable (`fd.ev`)
    /// 2. Template override for this `(category, key)`
    /// 3. `FIELD_DESCRIPTOR` default (`fd.d`)
    pub fn build_config(&self) -> OLineConfig {
        let mut cfg = OLineConfig::default();
        for fd in FIELD_DESCRIPTORS.iter() {
            let template_override = self
                .overrides
                .iter()
                .find(|(ev, _)| *ev == fd.ev)
                .map(|(_, v)| *v);
            cfg.set(fd.ev, resolve_fd_value(fd, template_override));
        }
        cfg
    }
}

// ── Built-in templates ────────────────────────────────────────────────────────

/// Terp Network mainnet — all values match the `FIELD_DESCRIPTORS` defaults.
/// Used as the canonical stable baseline for `oline init --template terp-mainnet`.
const TERP_MAINNET: DeployTemplate = DeployTemplate {
    name: "terp-mainnet",
    description: "Terp Network mainnet (morocco-1) — all FIELD_DESCRIPTOR defaults",
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
