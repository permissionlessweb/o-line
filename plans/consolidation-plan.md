# Configuration Consolidation — Implementation Plan

## STATUS: COMPLETE, UARCHIVED
## Goal
Merge `TomlConfig` (from `config.rs`) and `DeployTemplate` (from `templates.rs`) into a single `TomlConfig` source of truth in `toml_config.rs`. Deep cleanup, minimal API surface.

## Architecture Changes

### Before
```
toml_config.rs  → TomlConfig struct, CONFIG_FIELDS, profiles, SDL vars
config.rs       → TomlConfig (wrapper), path helpers, .env loading, crypto, template subs, PeerInputs, DeployConfig
templates.rs    → DeployTemplate, TEMPLATES array, find/list helpers
```

### After
```
toml_config.rs  → TomlConfig + ConfigValue + DeployTemplate + PeerInputs + DeployConfig + TomlConfig alias
config.rs       → path helpers + .env loading + encrypted mnemonic I/O (small, focused)
templates.rs    → DELETED (or kept as dead re-export stub)
```

## What Each Module Keeps

### `toml_config.rs` (KEEP + expand)
All of the following — currently present or deferred to this phase:
- `TomlConfig` struct with `HashMap<String, DatabaseValue>`
- `CONFIG_FIELDS` constant array
- `DatabaseValue` enum + `get_value()` / `set_value()`
- Profile support (`load_with_profile()`)
- `apply_env_overrides()`
- `to_sdl_vars()`
- `secret_paths()`
- `env_key()` + `is_secret_env()`
- `TomlConfig` struct + `ConfigValue` enum (moved from config.rs)
- `TomlConfig::val()`, `TomlConfig::get()`, `TomlConfig::get_str()`
- `TomlConfig::from_toml()`, `TomlConfig::to_sdl_vars()`
- `DeployTemplate` + `TEMPLATES` + `find()` + `list_all()` + `template_for_chain()` + `template_by_name()`
- `PeerInputs` struct (moved from config.rs)
- `DeployConfig` struct + `from_oline_config()` + `write_to_file()`
- `cfg.val("OLINE_XYZ")` method for `TomlConfig` direct access
- Template loading: `sdl_dir()`, `load_sdl()`

### `config.rs` (SIMPLIFY — keep only these)
**Keep:**
- `oline_config_dir()` — home config directory path
- `oline_config_toml_path()` — config.toml path
- `oline_env_path()` — .env file path
- `oline_mnemonic_path()` — mnemonic.enc path
- `oline_deploy_config_path()` — deploy-config.json path
- `oline_deployer_key_path()` — deployer.key path
- `oline_authz_config_path()` — authz.json path
- `load_dotenv()` — .env loading
- `upsert_env_key()` — .env key management
- `read_encrypted_mnemonic()` / `write_encrypted_mnemonic()` — mnemonic I/O
- `days_to_date()` / `is_leap_year()` — date utilities
- `inject_registry_credentials()` — SDL YAML manipulation
- `substitute_template_raw()` — template substitution
- `config_path()` / `save_config()` / `load_config()` / `has_saved_config()` — legacy config persistence
- `build_config_from_env()` — rebuild using TomlConfig → return `TomlConfig`
- `collect_config()` — interactive config

**Remove:**
- `TomlConfig` struct + impl (move to toml_config.rs)
- `ConfigValue` enum (move to toml_config.rs)
- `DeployTemplate`, `TEMPLATES`, `find`, `list_all`, `template_for_chain` (move to toml_config.rs)
- `PeerInputs` struct (move to toml_config.rs)
- `DeployConfig` struct + impl (move to toml_config.rs)

### `templates.rs` (DELETE)
After verifying no callers depend on it:
- Delete `src/templates.rs`
- Export from `lib.rs` pointing to `toml_config` instead

---

## Implementation Steps

### Step 1: Add DeployTemplate + PeerInputs + DeployConfig to toml_config.rs

Append to `toml_config.rs` (near line 1800+, after the existing TOML parse/update sections):

```rust
use std::collections::HashMap;

// ── PeerID stubs ──────────────────────────────────────────────────────────────

/// Peer ID strings used as SDL rendering inputs.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PeerInputs {
    pub snapshot: String,
    pub seed: String,
    pub statesync_rpc: String,
    pub left_tackle: String,
    pub right_tackle: String,
}

// ── Config template presets ───────────────────────────────────────────────────

/// Named deployment template: a set of field overrides applied on top of defaults.
pub struct DeployTemplate {
    pub name: &'static str,
    pub description: &'static str,
    /// Per-field overrides: `(config_path, value)`.
    pub overrides: &'static [(&'static str, &'static str)],
}

impl DeployTemplate {
    /// Build a fully-populated `TomlConfig` from defaults + template overrides.
    /// Env vars still take highest priority.
    pub fn build_config(&self) -> TomlConfig {
        let mut cfg = TomlConfig::from_defaults();
        for (path, value) in self.overrides {
            cfg.set_value(path, value.to_string());
        }
        cfg.apply_env_overrides();
        cfg
    }
}

/// Terp Network mainnet — all values match config defaults.
const TERP_MAINNET: DeployTemplate = DeployTemplate {
    name: "terp-mainnet",
    description: "Terp Network mainnet (morocco-1) — default config",
    overrides: &[],
};

pub const TEMPLATES: &[&DeployTemplate] = &[&TERP_MAINNET];

pub fn find_template(name: &str) -> Option<&'static DeployTemplate> {
    TEMPLATES.iter().copied().find(|t| t.name == name)
}

pub fn list_all_templates() -> impl Iterator<Item = &'static DeployTemplate> {
    TEMPLATES.iter().copied()
}

pub fn template_for_chain() -> &'static DeployTemplate {
    &TERP_MAINNET  // Updatable if multi-chain templates added
}

pub fn template_by_name(name: &str) -> Option<&'static DeployTemplate> {
    find_template(name)
}

/// Non-secret deployment config for SDL rendering.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DeployConfig {
    pub config: HashMap<String, String>,
}

impl DeployConfig {
    /// Build from a TomlConfig, stripping secrets.
    pub fn from_toml(cfg: &TomlConfig) -> Self {
        let mut config = HashMap::new();
        for field in CONFIG_FIELDS {
            if field.is_secret { continue; }
            let env_var = env_key(field.path);
            config.insert(env_var, cfg.get_value(field.path));
        }
        Self { config }
    }

    pub fn write_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}
```

### Step 2: Collapse `secret_paths()` into `CONFIG_FIELDS`

Replace the current `secret_paths()` in `toml_config.rs` with:

```rust
/// Return paths of secret fields.
/// Derived from CONFIG_FIELDS — single source of truth is CONFIG_FIELDS.is_secret.
pub fn secret_paths() -> &'static [&'static str] {
    &CONFIG_FIELDS.iter()
        .filter(|f| f.is_secret)
        .map(|f| f.path)
        .collect::<Vec<_>>()
}
```

### Step 3: Add `cfg.val(key)` method on `TomlConfig`

This is critical — callers use `TomlConfig.val("KEY")` but we want them to use `TomlConfig.val("KEY")`. Add this impl block to `toml_config.rs`:

```rust
impl TomlConfig {
    /// Convenience: get a string value by env key (e.g. "OLINE_CHAIN_ID").
    pub fn val(&self, key: &str) -> String {
        self.get_value(key)
    }
    
    /// Load SDL template from configured SDL directory.
    pub fn load_sdl(&self, filename: &str) -> Result<String, Box<dyn std::error::Error>> {
        let path = self.sdl_dir().join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read SDL '{}': {}", path.display(), e).into())
    }
    
    /// Return SDL templates directory path.
    pub fn sdl_dir(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(self.val("SDL_DIR"))
    }
}
```

### Step 4: Migrate callers from TomlConfig to TomlConfig

**Files to update:**

#### `src/akash.rs` (line 14, 73 calls)
```rust
// Change: use crate::config::TomlConfig;
//         → use crate::toml_config::{TomlConfig, DeployConfig, PeerInputs, CONFIG_FIELDS};
```

Update all function signatures:
- `build_phase_a_vars(config: &TomlConfig)` → `build_phase_a_vars(config: &TomlConfig)`
- `build_phase_b_vars(config: &TomlConfig)` → `build_phase_b_vars(config: &TomlConfig)`
- `build_phase_c_vars(config: &TomlConfig)` → `build_phase_c_vars(config: &TomlConfig)`
- `build_phase_rly_vars(config: &TomlConfig)` → `build_phase_rly_vars(config: &TomlConfig)`
- `render_sdl(config: &TomlConfig)` → `render_sdl(config: &TomlConfig)`

#### `src/config.rs`
```rust
// Update build_config_from_env() return type:
pub fn build_config_from_env(_mnemonic: String, profile: Option<&str>) -> TomlConfig {
    // ... existing logic ...
    toml_cfg  // Return TomlConfig directly instead of wrapping in TomlConfig
}

// Remove/deprecate: save_config(), load_config(), has_saved_config(), collect_config()
// These are legacy. Future work removes them.
```

#### `src/cmd/authz.rs` (line 19)
```rust
// Change: use crate::config::build_config_from_env;
//         → after build_config_from_env returns TomlConfig, update callers
```

#### `src/cmd/deploy.rs` (line 725 — in tests)
```rust
// Update test assertions if any depend on TomlConfig specifically
```

#### `src/lib.rs`
```rust
// Change: pub mod templates;
//         → pub mod templates; // Keep as dead re-export for backwards compat
// OR:     Remove templates module entirely
```

#### `src/templates.rs` → DEPRECATED → Create minimal re-export:
```rust
// DEPRECATED - use crate::toml_config::TEMPLATES, find_template(), etc.
#[deprecated(since = "1.0.0", note = "Use crate::toml_config instead")]
pub use crate::toml_config::{TEMPLATES, DeployTemplate};
#[deprecated(since = "1.0.0", note = "Use crate::toml_config::find_template")]
pub fn find(name: &str) -> Option<&'static DeployTemplate> {
    crate::toml_config::find_template(name)
}
#[deprecated(since = "1.0.0", note = "Use crate::toml_config::list_all_templates")]
pub fn list_all() -> impl Iterator<Item = &'static DeployTemplate> {
    crate::toml_config::list_all_templates()
}
```

Then remove `pub mod templates;` from `lib.rs` entirely (or keep the deprecated re-export if external callers exist).

### Step 5: Run cargo build and fix errors

After making all changes:
```bash
cargo check 2>&1 | head -100
```

Common issues to expect:
1. Missing imports in akash.rs (will need CONFIG_FIELDS, TomlConfig, DeployConfig)
2. Return type mismatches in config.rs functions
3. TomlConfig references in tests

---

## Output Verification Checklist

After implementation, verify:

1. ✅ `cargo check` passes with 0 errors
2. ✅ `cargo build --release` produces working binary
3. ✅ All `Val::val()` calls in akash.rs compile
4. ✅ `build_config_from_env()` returns `TomlConfig` (not `TomlConfig`)
5. ✅ `templates.rs` has deprecation warnings but still compiles
6. ✅ `TomlConfig` struct removed from `config.rs`
