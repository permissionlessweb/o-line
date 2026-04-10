/// Thin Rust wrapper around the `test-provider` binary.
///
/// Launches the binary as a subprocess, waits for its HTTPS port to be
/// reachable, and kills it automatically on [`Drop`].
///
/// # Usage in tests
///
/// ```rust,ignore
/// #[tokio::test]
/// #[ignore] // requires: cargo build --bin test-provider + running Akash node
/// async fn test_provider_bids() {
///     let cluster = AkashDevCluster::start().expect("cluster");
///
///     // Provider launches and self-registers on the node.
///     let provider = TestProviderHandle::start(
///         &cluster.faucet_mnemonic,
///         &cluster.rpc,
///         &cluster.grpc,
///         &cluster.rest,
///         8443,
///     )
///     .await
///     .expect("test-provider start");
///
///     println!("provider address: {}", provider.address);
///     // ...
/// } // Drop → process killed
/// ```
///
/// # Finding the binary
///
/// Search order:
///   1. `$CARGO_MANIFEST_DIR/target/debug/test-provider`  (during `cargo test`)
///   2. `./target/debug/test-provider`                     (cwd fallback)
///   3. `$TEST_PROVIDER_BIN`                               (explicit override)
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
};
use reqwest;

/// A running `test-provider` subprocess.
pub struct TestProviderHandle {
    process: Child,
    /// TCP port the provider HTTPS server is listening on.
    pub port: u16,
    /// Bech32 address of the provider key (derived from the mnemonic at HD index 99).
    pub address: String,
}

impl TestProviderHandle {
    /// Start the test-provider and wait until the provider is registered on-chain.
    ///
    /// The default timeout is 90 s — long enough for the binary's registration
    /// retry loop (12 × 5 s = 60 s) plus port-bind overhead.
    pub async fn start(
        mnemonic: &str,
        rpc: &str,
        grpc: &str,
        rest: &str,
        port: u16,
    ) -> Result<Self, String> {
        Self::start_with_timeout(mnemonic, rpc, grpc, rest, port, 90).await
    }

    /// Start with an explicit timeout (seconds).
    ///
    /// Two phases:
    /// 1. TCP connect — waits for the HTTPS port to bind (max 15 s).
    /// 2. `/readiness` poll — waits for MsgCreateProvider to be acknowledged
    ///    on-chain (remaining budget after phase 1).
    pub async fn start_with_timeout(
        mnemonic: &str,
        rpc: &str,
        grpc: &str,
        rest: &str,
        port: u16,
        wait_secs: u64,
    ) -> Result<Self, String> {
        let binary = Self::find_binary()?;

        // Derive the provider address at HD index 99 (must match PROVIDER_HD_INDEX
        // default in the test-provider binary to avoid self-bid conflicts).
        let address = crate::accounts::child_address_str(mnemonic, 99, "akash")
            .unwrap_or_else(|_| "<unknown>".into());

        let host_uri = format!("https://127.0.0.1:{}", port);

        let mut cmd = Command::new(&binary);
        cmd.env("PROVIDER_RPC", rpc)
            .env("PROVIDER_GRPC", grpc)
            .env("PROVIDER_REST", rest)
            .env("PROVIDER_MNEMONIC", mnemonic)
            .env("PROVIDER_PORT", port.to_string())
            .env("PROVIDER_HOST_URI", &host_uri)
            .env("PROVIDER_BID_PRICE", "1")
            .env("PROVIDER_BID_DEPOSIT", "5000000")
            .env("PROVIDER_HD_INDEX", "99")
            .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // Forward PROVIDER_SPAWN_CONTAINERS if set in the parent environment.
        if let Ok(v) = std::env::var("PROVIDER_SPAWN_CONTAINERS") {
            cmd.env("PROVIDER_SPAWN_CONTAINERS", v);
        }

        let child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn test-provider ({}): {}", binary.display(), e))?;

        let mut handle = Self {
            process: child,
            port,
            address,
        };

        let overall_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
        let tcp_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(wait_secs.min(15));

        // Phase 1: wait for HTTPS port to bind.
        loop {
            if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                tracing::info!(port, "test-provider HTTPS port open");
                break;
            }
            if std::time::Instant::now() >= tcp_deadline {
                handle.kill();
                return Err(format!(
                    "test-provider did not open port {} within {}s",
                    port,
                    wait_secs.min(15)
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Phase 2: poll /readiness until provider is registered on-chain.
        // Uses reqwest with TLS validation disabled (self-signed cert).
        let https_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("reqwest build failed: {}", e))?;
        let readiness_url = format!("https://127.0.0.1:{}/readiness", port);

        loop {
            match https_client.get(&readiness_url).send().await {
                Ok(resp) if resp.status().as_u16() == 200 => {
                    tracing::info!(port, "test-provider registered and ready ✓");
                    return Ok(handle);
                }
                Ok(resp) => {
                    tracing::debug!(
                        port,
                        status = resp.status().as_u16(),
                        "provider not yet registered — waiting"
                    );
                }
                Err(e) => {
                    tracing::debug!(port, error = %e, "readiness check error — will retry");
                }
            }
            if std::time::Instant::now() >= overall_deadline {
                handle.kill();
                return Err(format!(
                    "test-provider port {} is open but did not register within {}s — \
                     check provider logs for MsgCreateProvider errors",
                    port, wait_secs
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Query the provider's `/status` endpoint.
    ///
    /// Returns the parsed JSON body, including `registered`, `bids_placed`,
    /// `bids_rejected`, and `manifests_received` counters.
    pub async fn query_status(&self) -> Result<serde_json::Value, String> {
        let https_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("reqwest build: {}", e))?;
        let url = format!("https://127.0.0.1:{}/status", self.port);
        let resp = https_client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET {}: {}", url, e))?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format!("parse status response: {}", e))
    }

    /// Kill the provider process (also called automatically on Drop).
    pub fn kill(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }

    /// Return the provider's HTTPS base URL.
    pub fn https_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// Find the test-provider binary.
    fn find_binary() -> Result<PathBuf, String> {
        // 1. Relative to CARGO_MANIFEST_DIR (set by cargo during `cargo test`)
        if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let p = PathBuf::from(&dir).join("target/debug/test-provider");
            if p.exists() {
                return Ok(p);
            }
        }

        // 2. cwd fallback
        let p = PathBuf::from("target/debug/test-provider");
        if p.exists() {
            return Ok(p);
        }

        // 3. Explicit override
        if let Ok(s) = std::env::var("TEST_PROVIDER_BIN") {
            let p = PathBuf::from(s);
            if p.exists() {
                return Ok(p);
            }
        }

        Err(
            "test-provider binary not found.\n\
             Build it first: cargo build --bin test-provider\n\
             Or set TEST_PROVIDER_BIN=/path/to/test-provider."
                .to_string(),
        )
    }
}

impl Drop for TestProviderHandle {
    fn drop(&mut self) {
        self.kill();
        Self::cleanup_containers();
    }
}

impl TestProviderHandle {
    /// Clean up any leftover docker-compose projects from container-spawning mode.
    ///
    /// Scans `/tmp/oline-provider-*` directories for compose files and runs
    /// `docker compose down --remove-orphans` for each.  This handles the case
    /// where the provider process was killed with SIGKILL (which bypasses its
    /// own ctrl_c teardown handler).
    fn cleanup_containers() {
        let pattern = "/tmp/oline-provider-";
        let entries: Vec<_> = match std::fs::read_dir("/tmp") {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .to_str()
                        .map(|s| s.starts_with(pattern))
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => return,
        };

        for entry in entries {
            let dir = entry.path();
            let compose_file = dir.join("docker-compose.yml");
            if !compose_file.exists() {
                continue;
            }
            // Derive project name from directory: /tmp/oline-provider-{dseq} → oline-test-{dseq}
            let project = dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("oline-provider-"))
                .map(|dseq| format!("oline-test-{}", dseq))
                .unwrap_or_default();
            if project.is_empty() {
                continue;
            }
            tracing::info!(project = %project, dir = %dir.display(), "cleaning up docker compose");
            let _ = std::process::Command::new("docker")
                .args(["compose", "-p", &project, "down", "--remove-orphans"])
                .current_dir(&dir)
                .status();
            // Remove the temp directory.
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
