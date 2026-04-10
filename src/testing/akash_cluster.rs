/// Thin Rust wrapper around `tests/akash-devnet.sh`.
///
/// All cluster lifecycle logic lives in the shell script — easy to tune without
/// recompiling.  This module only:
///
///   1. Invokes `akash-devnet.sh wait` and parses its JSON output
///   2. Exposes typed accessors for RPC/gRPC/REST/provider endpoints + mnemonics
///   3. Calls `akash-devnet.sh stop` on [`Drop`]
///
/// # Usage in tests
///
/// ```rust,ignore
/// #[test]
/// #[ignore] // requires: kind, kubectl, docker, Akash provider repo built
/// fn test_akash_deployment() {
///     let cluster = AkashDevCluster::start().expect("cluster start");
///     // cluster.rpc(), cluster.grpc(), cluster.rest(), cluster.provider()
///     // cluster.faucet_mnemonic(), cluster.deployer_mnemonic(), cluster.chain_id()
/// } // Drop → akash-devnet.sh stop
/// ```
///
/// # One-time setup
///
/// ```bash
/// just akash-setup           # clone provider repo + build bins + Kind cluster
/// ```
///
/// Or run setup from Rust:
///
/// ```rust,ignore
/// AkashDevCluster::setup().expect("setup");
/// ```
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

/// A running local Akash dev cluster (Kind + node + provider-services).
///
/// Calls `tests/akash-devnet.sh stop` automatically on drop.
pub struct AkashDevCluster {
    /// Resolved path to `tests/akash-devnet.sh`.
    script: PathBuf,
    /// `http://127.0.0.1:26657`
    pub rpc: String,
    /// `http://127.0.0.1:9090`
    pub grpc: String,
    /// `http://127.0.0.1:1317`
    pub rest: String,
    /// `https://127.0.0.1:8443`
    pub provider: String,
    /// Chain-id read from the running node (e.g. `"local"` or `"akashnet-2"`).
    pub chain_id: String,
    /// Faucet account mnemonic (pre-funded in genesis with 10B uakt).
    pub faucet_mnemonic: String,
    /// Deployer/test account mnemonic (falls back to faucet if no separate key).
    pub deployer_mnemonic: String,
    /// Mnemonic used by the devnet-managed test-provider binary.
    /// Uses the `provider` key-secret if present, otherwise falls back to `faucet_mnemonic`.
    pub provider_mnemonic: String,
}

impl AkashDevCluster {
    /// Run one-time setup: clone provider repo if absent, build Akash binaries,
    /// create Kind cluster.  Idempotent — safe to call repeatedly.
    ///
    /// Equivalent to `just akash-setup`.
    pub fn setup() -> Result<(), String> {
        let script = Self::find_script()?;
        let status = Command::new(&script)
            .arg("setup")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("failed to spawn akash-devnet.sh setup: {}", e))?;

        if !status.success() {
            return Err(format!(
                "akash-devnet.sh setup failed (exit {:?})",
                status.code()
            ));
        }
        Ok(())
    }

    /// Start the cluster and block until node + provider are ready.
    ///
    /// Invokes `tests/akash-devnet.sh wait`, which:
    ///   - runs setup if binaries / Kind cluster are missing
    ///   - starts the node + provider in the background
    ///   - waits for RPC and provider HTTPS ports
    ///   - prints a JSON object to stdout with endpoints + mnemonics
    ///
    /// Progress output (from the shell script) streams to the test's stderr.
    /// Only the final JSON line is captured from stdout.
    ///
    /// Returns an error if setup fails, ports don't come up, or JSON is invalid.
    ///
    /// **Reuses** any already-running cluster.  For a clean ledger (sequence=0,
    /// no stale orders) use [`Self::start_fresh`] instead.
    pub fn start() -> Result<Self, String> {
        Self::run_script_subcommand("wait")
    }

    /// Reset chain state to genesis and start the cluster.
    ///
    /// Equivalent to `tests/akash-devnet.sh reset`, which:
    ///   1. Stops any running node and provider.
    ///   2. Runs `akash unsafe-reset-all` — wipes block data, preserves keys and genesis.
    ///   3. Starts fresh via `akash-devnet.sh wait`.
    ///
    /// Use this in integration tests to guarantee a clean ledger (all account
    /// sequences start at 0, no stale deployments or orders).
    pub fn start_fresh() -> Result<Self, String> {
        Self::run_script_subcommand("reset")
    }

    /// Internal: run `akash-devnet.sh <subcommand>` and parse the JSON output.
    fn run_script_subcommand(subcommand: &str) -> Result<Self, String> {
        let script = Self::find_script()?;

        // Spawn: both stdout and stderr piped so we can include diagnostic
        // context in error messages.  On success, stderr is forwarded to our
        // own stderr so progress output still appears in test logs.
        let child = Command::new(&script)
            .arg(subcommand)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn akash-devnet.sh {}: {}", subcommand, e))?;

        let output = child
            .wait_with_output()
            .map_err(|e| format!("akash-devnet.sh {}: {}", subcommand, e))?;

        // Always forward stderr so progress output is visible in test logs.
        let stderr_str = String::from_utf8_lossy(&output.stderr);
        if !stderr_str.is_empty() {
            eprint!("{}", stderr_str);
        }

        if !output.status.success() {
            // Include the last 40 lines of stderr in the error so CI failures
            // are debuggable without needing to re-run locally.
            let tail: String = stderr_str
                .lines()
                .rev()
                .take(40)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            return Err(format!(
                "akash-devnet.sh {} failed (exit {:?}):\n{}",
                subcommand,
                output.status.code(),
                tail
            ));
        }

        let json: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| {
            format!(
                "akash-devnet.sh {}: invalid JSON output: {}\nraw stdout: {}",
                subcommand,
                e,
                String::from_utf8_lossy(&output.stdout)
            )
        })?;

        let field = |key: &str| -> Result<String, String> {
            json[key]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("akash-devnet.sh {}: missing '{}' in JSON output", subcommand, key))
        };

        let faucet_mnemonic = field("faucet_mnemonic").unwrap_or_default();
        let provider_mnemonic = field("provider_mnemonic")
            .unwrap_or_else(|_| faucet_mnemonic.clone());

        Ok(Self {
            script,
            rpc: field("rpc")?,
            grpc: field("grpc")?,
            rest: field("rest")?,
            provider: field("provider")?,
            chain_id: field("chain_id").unwrap_or_else(|_| "local".into()),
            deployer_mnemonic: field("deployer_mnemonic")
                .unwrap_or_else(|_| faucet_mnemonic.clone()),
            faucet_mnemonic,
            provider_mnemonic,
        })
    }

    /// Print cluster status to stderr (delegates to `akash-devnet.sh status`).
    pub fn status(&self) {
        let _ = Command::new(&self.script)
            .arg("status")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
    }

    /// Path to the `akash-devnet.sh` script.
    ///
    /// Search order:
    ///   1. `$CARGO_MANIFEST_DIR/tests/akash-devnet.sh`  (used during `cargo test`)
    ///   2. `./tests/akash-devnet.sh`                     (cwd fallback)
    ///   3. `$AKASH_DEVNET_SCRIPT`                       (explicit override)
    fn find_script() -> Result<PathBuf, String> {
        // CARGO_MANIFEST_DIR is set by cargo when running tests.
        if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let p = PathBuf::from(&dir).join("tests/akash-devnet.sh");
            if p.exists() {
                return Ok(p);
            }
        }

        let p = PathBuf::from("tests/akash-devnet.sh");
        if p.exists() {
            return Ok(p);
        }

        if let Ok(s) = std::env::var("AKASH_DEVNET_SCRIPT") {
            let p = PathBuf::from(s);
            if p.exists() {
                return Ok(p);
            }
        }

        Err(
            "tests/akash-devnet.sh not found.\n\
             Expected at <crate-root>/tests/akash-devnet.sh, or set AKASH_DEVNET_SCRIPT."
                .to_string(),
        )
    }
}

impl Drop for AkashDevCluster {
    fn drop(&mut self) {
        let _ = Command::new(&self.script)
            .arg("stop")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status();
    }
}
