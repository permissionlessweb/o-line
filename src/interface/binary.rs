//! CLI binary wrapper for invoking oline from test code.

use std::collections::HashMap;
use std::error::Error;
use std::process::Command;

/// Wrapper around the compiled `oline` binary for integration testing.
///
/// Allows external test suites (e.g., terp.network) to invoke o-line
/// deployment and management commands programmatically.
pub struct OLineBinary {
    path: std::path::PathBuf,
}

impl OLineBinary {
    /// Build the oline binary and return a handle to it.
    pub fn build() -> Result<Self, Box<dyn Error>> {
        let status = Command::new("cargo")
            .args(["build", "--bin", "oline"])
            .status()?;
        if !status.success() {
            return Err("cargo build --bin oline failed".into());
        }
        let output = Command::new("cargo")
            .args(["metadata", "--format-version=1", "--no-deps"])
            .output()?;
        let meta: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let target_dir = meta["target_directory"]
            .as_str()
            .unwrap_or("target");
        let path = std::path::PathBuf::from(target_dir).join("debug/oline");
        Ok(Self { path })
    }

    /// Create a handle from an already-built binary path.
    pub fn from_path(path: std::path::PathBuf) -> Self {
        Self { path }
    }

    /// Invoke `oline deploy` with the given environment variables.
    ///
    /// Sets `OLINE_NON_INTERACTIVE=1` automatically so the binary
    /// runs without prompts.
    pub fn deploy(&self, env_vars: HashMap<String, String>) -> Result<String, Box<dyn Error>> {
        let output = Command::new(&self.path)
            .arg("deploy")
            .env("OLINE_NON_INTERACTIVE", "1")
            .envs(&env_vars)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "oline deploy failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into())
    }

    /// Invoke `oline manage <subcmd>` with optional arguments.
    pub fn manage(&self, subcmd: &str, args: &[&str]) -> Result<String, Box<dyn Error>> {
        let output = Command::new(&self.path)
            .arg("manage")
            .arg(subcmd)
            .args(args)
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into())
    }
}
