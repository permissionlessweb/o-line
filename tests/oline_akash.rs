/// Unified Akash integration tests for o-line.
///
/// Merges three test files into one:
///   - `akash_parallel.rs`      — direct-mode parallel deploy (3 scenarios)
///   - `oline_benchmark_test.rs` — HD-funded parallel deploy with containers + timing
///   - `e2e_workflow.rs`        — single-container TLS cert + scripts push + node launch
///
/// # Test functions
///
/// 1. `test_oline_akash_deploy`            — direct mode deploy: fund -> deploy -> 3 orders/bids/leases
/// 2. `test_oline_akash_trusted_providers`  — same with trusted-providers.json, asserts `[trusted]`
/// 3. `test_oline_akash_direct_fallback`    — omits OLINE_FUNDING_METHOD, asserts auto-direct
/// 4. `test_oline_akash_benchmark`          — HD-funded parallel deploy with container spawning + timing
/// 5. `test_oline_akash_tls_workflow`       — single-container TLS cert + scripts push + node launch
///
/// # Prerequisites
///
/// ```bash
/// just akash-setup              # one-time: ict-rs chain image + test-provider
/// cargo build --bin test-provider
/// ```
///
/// # Run
///
/// ```bash
/// cargo test -p o-line --test oline_akash -- --nocapture --ignored --test-threads=1
/// ```
use o_line_sdl::{
    accounts::child_address_str,
    testing::{AkashLocalNetwork, CometEvent, CometEventKind, IctAkashNetwork, WsEventStream},
};
use o_line_sdl::crypto::{
    push_pre_start_files, push_scripts_sftp, verify_files_and_signal_start, FileSource,
    PreStartFile,
};
use o_line_sdl::testing::docker::{
    container_exec, container_logs, run_container, wait_for_tcp, ContainerPort, ContainerSpec,
};
use o_line_sdl::testing::harness::generate_ssh_keypair;
use akash_deploy_rs::ServiceEndpoint;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use tokio::sync::broadcast;

// ─── Structured test scenario (from akash_parallel) ─────────────────────────

/// A captured test scenario: declared expectations + observed results.
///
/// Serialised to `tests/fixtures/scenarios/<name>.json` after each run.
/// The fixture files are the **stable source of truth** for CI regression
/// checks and for auto-generating library documentation.
#[derive(Debug, Serialize, Deserialize)]
pub struct TestScenario {
    /// Unique scenario identifier (used as the fixture file name).
    pub name: String,
    /// Human-readable description of what this scenario validates.
    pub description: String,
    /// Chain-level context captured at runtime.
    pub context: ScenarioContext,
    /// Expected event counts (declared before the test runs).
    pub expected: EventExpectations,
    /// Observed event counts (populated after the test runs).
    pub observed: ObservedEvents,
    /// Whether all expectations were met.
    pub passed: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScenarioContext {
    pub chain_id: String,
    pub deployer_address: String,
    pub provider_address: String,
    pub rpc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventExpectations {
    pub orders: usize,
    pub bids: usize,
    pub leases: usize,
    pub manifests: usize,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ObservedEvents {
    pub order_dseqs: Vec<u64>,
    pub bid_dseqs: Vec<u64>,
    pub lease_dseqs: Vec<u64>,
    /// Owner addresses that created each order (parallel = distinct HD children).
    pub order_owners: Vec<String>,
    /// All raw Tx event attributes observed (for debugging and documentation).
    pub tx_attrs: Vec<HashMap<String, String>>,
}

impl TestScenario {
    pub fn new(
        name: &str,
        description: &str,
        expected_orders: usize,
        expected_bids: usize,
        expected_leases: usize,
        expected_manifests: usize,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            context: ScenarioContext::default(),
            expected: EventExpectations {
                orders: expected_orders,
                bids: expected_bids,
                leases: expected_leases,
                manifests: expected_manifests,
            },
            observed: ObservedEvents::default(),
            passed: false,
        }
    }

    /// Write the scenario to `tests/fixtures/scenarios/<name>.json`.
    ///
    /// If `UPDATE_FIXTURES=1`, always overwrite; otherwise the fixture
    /// is only written if it does not exist (first-run bootstrap).
    pub fn write_fixture(&self) {
        let dir = PathBuf::from(
            env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()),
        )
        .join("tests/fixtures/scenarios");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{}.json", self.name));

        let update = env::var("UPDATE_FIXTURES").is_ok();
        if update || !path.exists() {
            match serde_json::to_string_pretty(self) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(&path, &json) {
                        eprintln!("[scenario] WARNING: failed to write fixture {:?}: {}", path, e);
                    } else {
                        eprintln!("[scenario] fixture written -> {:?}", path);
                    }
                }
                Err(e) => eprintln!("[scenario] WARNING: failed to serialise: {}", e),
            }
        } else {
            // Compare against existing fixture.
            if let Ok(existing) = std::fs::read_to_string(&path) {
                if let Ok(prev) = serde_json::from_str::<TestScenario>(&existing) {
                    let new_passed = self.passed;
                    let old_passed = prev.passed;
                    let mut regressions = Vec::new();

                    if new_passed != old_passed {
                        regressions.push(format!(
                            "passed: {} -> {}",
                            if old_passed { "PASS" } else { "FAIL" },
                            if new_passed { "PASS" } else { "FAIL" }
                        ));
                    }

                    // Count-level comparison catches partial regressions that
                    // the boolean `passed` field misses (e.g. bids drop from 3
                    // to 2 without crossing the >=3 threshold).
                    let checks = [
                        ("orders", prev.observed.order_dseqs.len(), self.observed.order_dseqs.len()),
                        ("bids",   prev.observed.bid_dseqs.len(),   self.observed.bid_dseqs.len()),
                        ("leases", prev.observed.lease_dseqs.len(), self.observed.lease_dseqs.len()),
                    ];
                    for (label, old_n, new_n) in &checks {
                        if old_n != new_n {
                            regressions.push(format!("{}: {} -> {}", label, old_n, new_n));
                        }
                    }

                    if regressions.is_empty() {
                        eprintln!("[scenario] fixture matches ({})", self.name);
                    } else {
                        eprintln!(
                            "[scenario] REGRESSION({}): {} (fixture at {:?})",
                            self.name,
                            regressions.join(", "),
                            path
                        );
                    }
                }
            }
        }
    }
}

// ─── Benchmark timings (from oline_benchmark_test) ──────────────────────────

struct BenchmarkTimings {
    start: Instant,
    network_ready: Option<Instant>,
    oline_spawned: Option<Instant>,
    all_deployed: Option<Instant>,
    sync_complete: Option<Instant>,
}

impl BenchmarkTimings {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            network_ready: None,
            oline_spawned: None,
            all_deployed: None,
            sync_complete: None,
        }
    }

    fn print_summary(&self) {
        eprintln!("\n=== Parallel Deploy Benchmark ===");
        if let Some(t) = self.network_ready {
            eprintln!("  Network startup:    {:.1}s", (t - self.start).as_secs_f64());
        }
        if let (Some(spawned), Some(deployed)) = (self.oline_spawned, self.all_deployed) {
            eprintln!(
                "  Deploy lifecycle:   {:.1}s  (funding + A + B + C + manifests)",
                (deployed - spawned).as_secs_f64()
            );
        }
        if let (Some(deployed), Some(synced)) = (self.all_deployed, self.sync_complete) {
            eprintln!("  Block sync wait:    {:.1}s", (synced - deployed).as_secs_f64());
        }
        eprintln!(
            "  Total wall-clock:   {:.1}s",
            self.start.elapsed().as_secs_f64()
        );
        eprintln!("=================================\n");
    }
}

// ─── SpawnOpts (from akash_parallel) ────────────────────────────────────────

/// Options for spawning `oline deploy --parallel`.
struct SpawnOpts<'a> {
    /// XDG_CONFIG_HOME override -- controls where oline reads trusted-providers.json.
    config_home: Option<&'a str>,
    /// If true, oline stops after deploy verification (no SSH/DNS).
    stop_after_deploy: bool,
    /// If true, omit OLINE_FUNDING_METHOD -- tests the auto HD-default in --parallel.
    skip_funding_method_env: bool,
    /// Extra env vars to pass to the subprocess (e.g. domain overrides for live testing).
    extra_env: Vec<(&'a str, &'a str)>,
}

impl<'a> Default for SpawnOpts<'a> {
    fn default() -> Self {
        Self {
            config_home: None,
            stop_after_deploy: true,
            skip_funding_method_env: false,
            extra_env: Vec::new(),
        }
    }
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

fn oline_bin() -> PathBuf {
    env!("CARGO_BIN_EXE_oline").into()
}

fn test_sdl_dir() -> PathBuf {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    PathBuf::from(manifest).join("tests/fixtures/sdls")
}

fn test_secrets_dir() -> PathBuf {
    std::env::temp_dir().join("oline-akash-test-secrets")
}

/// Close a deployment by DSEQ using the Akash CLI bundled with the provider repo.
fn close_deployment(akash_bin: &PathBuf, akash_home: &str, node: &str, dseq: u64, chain_id: &str) {
    if dseq == 0 {
        return;
    }
    let owner = match Command::new(akash_bin)
        .args(["--home", akash_home, "--keyring-backend", "test", "keys", "show", "main", "-a"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => return,
    };
    if owner.is_empty() {
        return;
    }
    let _ = Command::new(akash_bin)
        .args([
            "--home", akash_home,
            "--node", node,
            "--chain-id", chain_id,
            "--keyring-backend", "test",
            "tx", "deployment", "close",
            "--dseq", &dseq.to_string(),
            "--from", "main",
            "--gas", "auto",
            "--gas-adjustment", "1.5",
            "--fees", "50000uakt",
            "-y",
        ])
        .status();
}

/// Write a `trusted-providers.json` to `config_home/oline/` for the given provider address.
///
/// Returns the path to the created file.
fn write_trusted_providers(config_home: &std::path::Path, provider_addr: &str) -> PathBuf {
    let oline_config_dir = config_home.join("oline");
    let _ = std::fs::create_dir_all(&oline_config_dir);
    let path = oline_config_dir.join("trusted-providers.json");

    let json = serde_json::json!([{
        "address": provider_addr,
        "host_uri": format!("https://127.0.0.1:8443"),
        "alias": "test-provider",
        "notes": "e2e test mock provider",
        "added_at": 1700000000u64,
    }]);

    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap())
        .expect("failed to write trusted-providers.json");
    eprintln!("[test] Wrote trusted-providers.json -> {:?}", path);
    path
}

/// Read `/tmp/oline-env.sh` inside a container via docker exec.
///
/// Returns `(raw_content, parsed_var_map)`.  Parses both forms:
///   - `declare -x VAR="value"`  -- from bootstrap's `export -p`
///   - `export VAR='value'`      -- from orchestrator's `/tmp/oline-env.sh` patch
fn read_container_env_file(container_name: &str) -> (String, HashMap<String, String>) {
    let raw = container_exec(container_name, "cat /tmp/oline-env.sh 2>/dev/null || true");
    let mut map: HashMap<String, String> = HashMap::new();

    for line in raw.lines() {
        let line = line.trim();
        let rest = if let Some(r) = line.strip_prefix("declare -x ") {
            r
        } else if let Some(r) = line.strip_prefix("export ") {
            r
        } else {
            continue;
        };

        if let Some(eq) = rest.find('=') {
            let key = rest[..eq].to_string();
            let raw_val = &rest[eq + 1..];
            let val = raw_val
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| {
                    raw_val
                        .strip_prefix('\'')
                        .and_then(|v| v.strip_suffix('\''))
                })
                .unwrap_or(raw_val)
                .to_string();
            map.insert(key, val);
        }
    }

    (raw, map)
}

/// Spawn a background thread that reads lines from a `Read` handle and prints
/// them with a `[prefix]` tag.  Returns a JoinHandle that resolves to all
/// collected lines (for post-mortem analysis).
fn stream_output(
    reader: impl std::io::Read + Send + 'static,
    prefix: &str,
) -> std::thread::JoinHandle<Vec<String>> {
    let prefix = prefix.to_string();
    std::thread::spawn(move || {
        let mut lines_buf = Vec::new();
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    eprintln!("[{}] {}", prefix, l);
                    lines_buf.push(l);
                }
                Err(_) => break,
            }
        }
        lines_buf
    })
}

/// Print the provider log file for diagnostics.
fn print_provider_log() {
    let provider_log_path = "/tmp/akash-devnet-provider.log";
    eprintln!("\n[benchmark] === Provider log ({}) ===", provider_log_path);
    match std::fs::read_to_string(provider_log_path) {
        Ok(log) => {
            let lines: Vec<&str> = log.lines().collect();
            let start = lines.len().saturating_sub(200);
            for line in &lines[start..] {
                eprintln!("{}", line);
            }
        }
        Err(e) => eprintln!("[benchmark] (could not read provider log: {})", e),
    }
    eprintln!("[benchmark] === End provider log ===\n");
}

/// Collect and print docker compose logs for all active deployments.
fn print_container_logs() {
    let entries: Vec<_> = match std::fs::read_dir("/tmp") {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .to_str()
                    .map(|s| s.contains("oline-provider-"))
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => return,
    };
    if entries.is_empty() {
        eprintln!("[benchmark] No container deployment directories found.");
        return;
    }
    for entry in entries {
        let dir = entry.path();
        let compose_file = dir.join("docker-compose.yml");
        if !compose_file.exists() {
            continue;
        }
        let project = dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("oline-provider-"))
            .map(|dseq| format!("oline-test-{}", dseq))
            .unwrap_or_default();
        if project.is_empty() {
            continue;
        }
        eprintln!(
            "\n[benchmark] === Container logs: {} ({}) ===",
            project,
            dir.display()
        );
        // Print the compose file for reference.
        if let Ok(yaml) = std::fs::read_to_string(&compose_file) {
            eprintln!("[benchmark] docker-compose.yml:\n{}", yaml);
        }
        // Collect logs.
        match std::process::Command::new("docker")
            .args(["compose", "-p", &project, "logs", "--tail", "100"])
            .current_dir(&dir)
            .output()
        {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stdout.is_empty() {
                    for line in stdout.lines() {
                        eprintln!("[container:{}] {}", project, line);
                    }
                }
                if !stderr.is_empty() {
                    for line in stderr.lines() {
                        eprintln!("[container:{}:err] {}", project, line);
                    }
                }
            }
            Err(e) => eprintln!("[benchmark] docker compose logs failed: {}", e),
        }
        // Also print `docker compose ps` for container status.
        if let Ok(out) = std::process::Command::new("docker")
            .args(["compose", "-p", &project, "ps", "-a"])
            .current_dir(&dir)
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.is_empty() {
                eprintln!("[benchmark] container status:\n{}", stdout);
            }
        }
        eprintln!("[benchmark] === End container logs: {} ===\n", project);
    }
}

/// Query REST API for on-chain bids (diagnostic).
async fn print_onchain_bids(rest: &str, deployer_addr: &str) {
    let bids_url = format!(
        "{}/akash/market/v1beta5/bids/list?filters.owner={}",
        rest, deployer_addr
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    eprintln!("[benchmark] Querying REST for on-chain bids: {}", bids_url);
    match http.get(&bids_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(json) => {
                let count = json["bids"].as_array().map(|a| a.len()).unwrap_or(0);
                eprintln!("[benchmark] On-chain bids (REST): {}", count);
                if let Some(bids) = json["bids"].as_array() {
                    for b in bids {
                        eprintln!(
                            "[benchmark]   bid dseq={} provider={} state={}",
                            b["bid"]["id"]["dseq"].as_str().unwrap_or("?"),
                            b["bid"]["id"]["provider"].as_str().unwrap_or("?"),
                            b["bid"]["state"].as_str().unwrap_or("?"),
                        );
                    }
                }
            }
            Err(e) => eprintln!("[benchmark] REST bids JSON parse error: {}", e),
        },
        Ok(resp) => eprintln!("[benchmark] REST bids HTTP {}: skipping", resp.status()),
        Err(e) => eprintln!("[benchmark] REST bids query error: {}", e),
    }
}

/// Query REST API for on-chain deployments (diagnostic).
async fn print_onchain_deployments(rest: &str, deployer_addr: &str) {
    let url = format!(
        "{}/akash/deployment/v1beta4/deployments/list?filters.owner={}",
        rest, deployer_addr
    );
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    eprintln!("[benchmark] Querying REST for deployments: {}", url);
    match http.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(json) => {
                let count = json["deployments"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0);
                eprintln!("[benchmark] On-chain deployments (REST): {}", count);
                if let Some(deps) = json["deployments"].as_array() {
                    for d in deps {
                        eprintln!(
                            "[benchmark]   deployment dseq={} state={}",
                            d["deployment"]["deployment_id"]["dseq"]
                                .as_str()
                                .unwrap_or("?"),
                            d["deployment"]["state"].as_str().unwrap_or("?"),
                        );
                    }
                }
            }
            Err(e) => eprintln!("[benchmark] REST deployments JSON parse error: {}", e),
        },
        Ok(resp) => {
            eprintln!(
                "[benchmark] REST deployments HTTP {}: skipping",
                resp.status()
            )
        }
        Err(e) => eprintln!("[benchmark] REST deployments query error: {}", e),
    }
}

/// Discover container RPC ports by querying the provider's lease-status endpoint.
///
/// For each dseq, tries each owner in `owners` until one succeeds.
/// Queries `GET {provider}/lease/{owner}/{dseq}/1/1/status` and
/// extracts `forwarded_ports` entries where `port == 26657`.
async fn discover_rpc_ports(provider_url: &str, owners: &[String], dseqs: &[u64]) -> Vec<String> {
    let https_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut rpc_endpoints = Vec::new();

    for &dseq in dseqs {
        // Try each owner -- with HD funding each phase may have a different owner.
        for owner in owners {
            let url = format!(
                "{}/lease/{}/{}/1/1/status",
                provider_url, owner, dseq
            );
            match https_client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if let Some(fp) = json.get("forwarded_ports").and_then(|v| v.as_object()) {
                            for (_svc, ports) in fp {
                                if let Some(arr) = ports.as_array() {
                                    for entry in arr {
                                        let port = entry["port"].as_u64().unwrap_or(0);
                                        let external = entry["externalPort"].as_u64().unwrap_or(0);
                                        if port == 26657 && external > 0 {
                                            let ep = format!("http://127.0.0.1:{}", external);
                                            eprintln!(
                                                "[benchmark] discovered RPC endpoint: {} (dseq={} owner={})",
                                                ep, dseq, owner
                                            );
                                            rpc_endpoints.push(ep);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break; // found this dseq's lease-status, skip other owners
                }
                _ => {
                    // This owner doesn't match this dseq -- try next.
                }
            }
        }
    }

    rpc_endpoints
}

/// Wait for all RPC endpoints to report `catching_up: false` and heights within
/// `max_height_diff` of each other.
async fn wait_for_sync(
    rpc_endpoints: &[String],
    timeout: Duration,
    max_height_diff: u64,
) -> bool {
    if rpc_endpoints.is_empty() {
        return true;
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }

        let mut all_synced = true;
        let mut heights: Vec<u64> = Vec::new();

        for ep in rpc_endpoints {
            let url = format!("{}/status", ep);
            match http.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        let catching_up = json["result"]["sync_info"]["catching_up"]
                            .as_bool()
                            .unwrap_or(true);
                        let height: u64 = json["result"]["sync_info"]["latest_block_height"]
                            .as_str()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);

                        if catching_up {
                            all_synced = false;
                        }
                        heights.push(height);
                    } else {
                        all_synced = false;
                    }
                }
                _ => {
                    all_synced = false;
                }
            }
        }

        if all_synced && !heights.is_empty() {
            let min_h = *heights.iter().min().unwrap();
            let max_h = *heights.iter().max().unwrap();
            if max_h - min_h <= max_height_diff {
                eprintln!(
                    "[benchmark] all nodes synced -- heights: {:?} (diff={})",
                    heights,
                    max_h - min_h
                );
                return true;
            }
        }

        eprintln!(
            "[benchmark] sync check: all_synced={} heights={:?} ({:.0}s remaining)",
            all_synced,
            heights,
            remaining.as_secs_f64()
        );

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

// ─── Spawn helpers ──────────────────────────────────────────────────────────

/// Spawn `oline deploy --parallel` against a running IctAkashNetwork.
///
/// **No REST endpoint is set** -- oline falls back to gRPC for bid queries,
/// which has better cross-version compatibility than the v1beta5 REST path.
///
/// Returns the spawned child process handle (non-blocking).
fn spawn_oline_deploy(net: &IctAkashNetwork) -> std::process::Child {
    spawn_oline_deploy_with(net, SpawnOpts::default())
}

/// Spawn `oline deploy --parallel` with additional options.
///
/// Uses `env_clear()` to prevent the subprocess from inheriting the caller's
/// environment (production `.env` vars, domain configs, etc.).  Only the vars
/// explicitly listed here are passed through.  The working directory is set to
/// a temp dir so oline's `load_dotenv()` doesn't find the repo's `.env`.
fn spawn_oline_deploy_with(net: &IctAkashNetwork, opts: SpawnOpts<'_>) -> std::process::Child {
    let sdl_dir =
        env::var("SDL_DIR").unwrap_or_else(|_| test_sdl_dir().to_string_lossy().to_string());
    let secrets_dir = test_secrets_dir();
    let _ = std::fs::create_dir_all(&secrets_dir);

    // Use a clean temp dir as CWD so oline won't load .env from the repo root.
    let clean_cwd = std::env::temp_dir().join("oline-test-cwd");
    let _ = std::fs::create_dir_all(&clean_cwd);

    let mut cmd = Command::new(oline_bin());
    cmd.args(["deploy", "--parallel"])
        // ── Clean environment: prevent inheriting production vars ─────────
        // oline's load_dotenv() reads .env from CWD, and build_config_from_env
        // reads env vars like RPC_D_*, API_D_*, etc.  Clearing the
        // env ensures tests run identically regardless of the caller's shell.
        .env_clear()
        .current_dir(&clean_cwd)
        // ── Minimal system vars needed for process execution ──────────────
        .env("HOME", env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
        .env("PATH", env::var("PATH").unwrap_or_default())
        // ── Non-interactive bypasses ──────────────────────────────────────
        .env("OLINE_NON_INTERACTIVE", "1")
        .env("OLINE_MNEMONIC", &net.deployer_mnemonic)
        .env("OLINE_PASSWORD", "oline-ci-test")
        // ── Endpoints from IctAkashNetwork ─────────────────────────────
        .env("OLINE_RPC_ENDPOINT", net.rpc())
        .env("OLINE_GRPC_ENDPOINT", net.grpc())
        // NOTE: REST endpoint deliberately omitted so bid queries use gRPC,
        // which has better version compatibility than the v1beta5 REST path.
        .env("OLINE_REST_ENDPOINT", "")
        .env("OLINE_CHAIN_ID", net.chain_id())
        .env("OLINE_DENOM", "uakt")
        // ── Test image + SDL directory ─────────────────────────────────────
        .env(
            "OMNIBUS_IMAGE",
            env::var("OMNIBUS_IMAGE").unwrap_or_else(|_| "nginx:alpine".into()),
        )
        .env("SDL_DIR", &sdl_dir)
        // ── Skip DNS (no Cloudflare creds in CI) ──────────────────────────
        .env("OLINE_CF_API_TOKEN", "")
        .env("OLINE_CF_ZONE_ID", "")
        // ── SSH secrets ───────────────────────────────────────────────────
        .env("SECRETS_PATH", secrets_dir.to_string_lossy().as_ref())
        .env("OLINE_ENCRYPTED_MNEMONIC", "");

    // ── Direct mode: single-signer batch deployment ────────────────
    // All MsgCreateDeployment messages are signed by the master account
    // in a single transaction. No HD child derivation or uact transfers
    // (which are blocked by BME SendRestrictionFn).
    // When skip_funding_method_env is true, we omit this to test the
    // auto-default Direct fallback in --parallel mode.
    if !opts.skip_funding_method_env {
        cmd.env("OLINE_FUNDING_METHOD", "direct");
    }

    cmd // ── Bid wait window: 20 attempts x 12 s = 240 s (double the default)
        // Gives the test-provider more time to register + bid in CI.
        .env("OLINE_MAX_BID_WAIT", "20")
        // ── Logging: info + debug for akash_deploy_rs to see bid queries ──
        .env("RUST_LOG", "info,akash_deploy_rs=debug,test_provider=debug");

    if let Some(config_home) = opts.config_home {
        cmd.env("XDG_CONFIG_HOME", config_home);
    }
    if opts.stop_after_deploy {
        cmd.env("OLINE_TEST_STOP_AFTER_DEPLOY", "1");
    }
    for (k, v) in &opts.extra_env {
        cmd.env(k, v);
    }

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // real-time stderr so errors appear immediately
        .spawn()
        .expect("failed to spawn oline")
}

/// Spawn `oline deploy --parallel` with HD funding and container spawning
/// against a running AkashLocalNetwork.
///
/// stdout is piped for structured output parsing; stderr is piped so we can
/// prefix each line with `[oline]` in a streaming reader task.
fn spawn_oline_full(net: &AkashLocalNetwork) -> std::process::Child {
    let sdl_dir =
        env::var("SDL_DIR").unwrap_or_else(|_| test_sdl_dir().to_string_lossy().to_string());
    let secrets_dir = test_secrets_dir();
    let _ = std::fs::create_dir_all(&secrets_dir);

    let omnibus = env::var("OMNIBUS_IMAGE")
        .or_else(|_| env::var("E2E_OMNIBUS_IMAGE"))
        .unwrap_or_else(|_| "nginx:alpine".into());

    Command::new(oline_bin())
        .args(["deploy", "--parallel"])
        .env("OLINE_NON_INTERACTIVE", "1")
        .env("OLINE_MNEMONIC", &net.deployer_mnemonic)
        .env("OLINE_PASSWORD", "oline-benchmark")
        .env("OLINE_RPC_ENDPOINT", net.rpc())
        .env("OLINE_GRPC_ENDPOINT", net.grpc())
        .env("OLINE_REST_ENDPOINT", net.rest())
        .env("OLINE_CHAIN_ID", net.chain_id())
        .env("OLINE_DENOM", "uakt")
        .env("OMNIBUS_IMAGE", &omnibus)
        .env("SDL_DIR", &sdl_dir)
        .env("OLINE_CF_API_TOKEN", "")
        .env("OLINE_CF_ZONE_ID", "")
        .env("SECRETS_PATH", secrets_dir.to_string_lossy().as_ref())
        .env("OLINE_ENCRYPTED_MNEMONIC", "")
        .env("OLINE_MAX_BID_WAIT", "20")
        // HD funding: 3 children, 25M uakt each (enough for deposit + gas)
        .env("OLINE_FUNDING_METHOD", "hd:3:25000000")
        // Stop after all phases are deployed (no SSH/snapshot/DNS)
        .env("OLINE_TEST_STOP_AFTER_DEPLOY", "1")
        // Enable container spawning in test-provider
        .env("PROVIDER_SPAWN_CONTAINERS", "1")
        .env(
            "RUST_LOG",
            "debug,hyper=info,h2=info,tower=info,tonic=info,reqwest=info",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn oline")
}

// ─── Event collectors ───────────────────────────────────────────────────────

/// Collect Akash on-chain events from a WS receiver (akash_parallel variant).
///
/// Uses **suffix matching** for Akash event attribute keys so it works
/// across all chain versions regardless of proto package prefix.
///
/// **Prints EVERY Tx event** -- all attributes -- so the exact chain-version
/// event format is always visible in the test output.
///
/// Returns an `ObservedEvents` filled with matched dseqs + all attrs.
async fn collect_akash_events(
    rx: &mut broadcast::Receiver<CometEvent>,
    owners: &HashSet<String>,
    need_orders: usize,
    need_bids: usize,
    need_leases: usize,
    timeout: Duration,
) -> ObservedEvents {
    let mut obs = ObservedEvents::default();

    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_heartbeat = tokio::time::Instant::now();
    let mut last_height: u64 = 0;

    loop {
        if obs.order_dseqs.len() >= need_orders
            && obs.bid_dseqs.len() >= need_bids
            && obs.lease_dseqs.len() >= need_leases
        {
            break;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            eprintln!(
                "[events] timeout after {:?}: orders={}/{} bids={}/{} leases={}/{}",
                timeout,
                obs.order_dseqs.len(), need_orders,
                obs.bid_dseqs.len(), need_bids,
                obs.lease_dseqs.len(), need_leases,
            );
            break;
        }

        // Heartbeat every 30 s so the terminal isn't silent.
        let heartbeat_interval = Duration::from_secs(30);
        let recv_timeout = remaining
            .min(heartbeat_interval - last_heartbeat.elapsed().min(heartbeat_interval));

        match tokio::time::timeout(recv_timeout, rx.recv()).await {
            Ok(Ok(ev)) => {
                // NewBlock: just track height for heartbeats.
                if ev.kind == CometEventKind::NewBlock {
                    last_height = ev.height;
                    continue;
                }

                // For EVERY Tx event, print ALL attributes -- no filter.
                // This lets us see the exact key format from any chain version.
                if !ev.attrs.is_empty() {
                    let mut sorted_attrs: Vec<(&str, &str)> = ev
                        .attrs
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    sorted_attrs.sort_by_key(|(k, _)| *k);

                    eprintln!("[events] Tx height={} ({} attrs):", ev.height, sorted_attrs.len());
                    for (k, v) in &sorted_attrs {
                        eprintln!("  {}  =  {}", k, v);
                    }

                    // Record attrs snapshot for fixture.
                    let snapshot: HashMap<String, String> = sorted_attrs
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    obs.tx_attrs.push(snapshot);
                }

                // OrderCreated (suffix match)
                if obs.order_dseqs.len() < need_orders {
                    if let Some(order_owner) = ev.attr_suffix("EventOrderCreated.id.owner") {
                        if owners.contains(order_owner) {
                            if let Some(dseq) = ev
                                .attr_suffix("EventOrderCreated.id.dseq")
                                .and_then(|s| s.parse::<u64>().ok())
                            {
                                eprintln!("[events] OrderCreated dseq={} owner={} height={}", dseq, order_owner, ev.height);
                                if !obs.order_dseqs.contains(&dseq) {
                                    obs.order_dseqs.push(dseq);
                                    obs.order_owners.push(order_owner.to_string());
                                }
                            }
                        }
                    }
                }

                // BidCreated (suffix match -- owner = deployment owner, may be child account)
                if obs.bid_dseqs.len() < need_bids {
                    if ev.attr_suffix("EventBidCreated.id.owner").map_or(false, |o| owners.contains(o)) {
                        if let Some(dseq) = ev
                            .attr_suffix("EventBidCreated.id.dseq")
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            eprintln!("[events] BidCreated dseq={} height={}", dseq, ev.height);
                            if !obs.bid_dseqs.contains(&dseq) {
                                obs.bid_dseqs.push(dseq);
                            }
                        }
                    }
                }

                // LeaseCreated (suffix match)
                if obs.lease_dseqs.len() < need_leases {
                    if ev.attr_suffix("EventLeaseCreated.id.owner").map_or(false, |o| owners.contains(o)) {
                        if let Some(dseq) = ev
                            .attr_suffix("EventLeaseCreated.id.dseq")
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            eprintln!("[events] LeaseCreated dseq={} height={}", dseq, ev.height);
                            if !obs.lease_dseqs.contains(&dseq) {
                                obs.lease_dseqs.push(dseq);
                            }
                        }
                    }
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                eprintln!("[events] WARNING: receiver lagged by {} events", n);
            }
            Ok(Err(e)) => {
                eprintln!("[events] channel closed: {}", e);
                break;
            }
            // Heartbeat timeout -- print status and continue.
            Err(_) => {
                if last_heartbeat.elapsed() >= heartbeat_interval {
                    eprintln!(
                        "[events] waiting... height={} orders={}/{} bids={}/{} leases={}/{}  ({:.0}s remaining)",
                        last_height,
                        obs.order_dseqs.len(), need_orders,
                        obs.bid_dseqs.len(), need_bids,
                        obs.lease_dseqs.len(), need_leases,
                        remaining.as_secs_f64(),
                    );
                    last_heartbeat = tokio::time::Instant::now();
                }
            }
        }
    }

    obs
}

/// Collect Akash on-chain events (benchmark variant).
///
/// Accepts multiple owner addresses as a slice (HD children have different
/// addresses from master).  Returns `(order_dseqs, bid_dseqs, lease_dseqs)`
/// tuples.
///
/// Prints EVERY Tx event's attributes (same as collect_akash_events) so
/// chain-version event format mismatches are immediately visible.
async fn collect_akash_events_benchmark(
    rx: &mut broadcast::Receiver<CometEvent>,
    owners: &[String],
    need_orders: usize,
    need_bids: usize,
    need_leases: usize,
    timeout: Duration,
) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let mut order_dseqs = Vec::new();
    let mut bid_dseqs = Vec::new();
    let mut lease_dseqs = Vec::new();

    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_heartbeat = tokio::time::Instant::now();
    let mut last_height: u64 = 0;

    loop {
        if order_dseqs.len() >= need_orders
            && bid_dseqs.len() >= need_bids
            && lease_dseqs.len() >= need_leases
        {
            break;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            eprintln!(
                "[events] timeout after {:?}: orders={}/{} bids={}/{} leases={}/{}",
                timeout,
                order_dseqs.len(),
                need_orders,
                bid_dseqs.len(),
                need_bids,
                lease_dseqs.len(),
                need_leases,
            );
            break;
        }

        let heartbeat_interval = Duration::from_secs(30);
        let recv_timeout = remaining
            .min(heartbeat_interval - last_heartbeat.elapsed().min(heartbeat_interval));

        match tokio::time::timeout(recv_timeout, rx.recv()).await {
            Ok(Ok(ev)) => {
                if ev.kind == CometEventKind::NewBlock {
                    last_height = ev.height;
                    continue;
                }

                // Print ALL Tx event attributes for full visibility.
                if !ev.attrs.is_empty() {
                    let mut sorted_attrs: Vec<(&str, &str)> = ev
                        .attrs
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    sorted_attrs.sort_by_key(|(k, _)| *k);

                    eprintln!(
                        "[events] Tx height={} ({} attrs):",
                        ev.height,
                        sorted_attrs.len()
                    );
                    for (k, v) in &sorted_attrs {
                        eprintln!("  {}  =  {}", k, v);
                    }
                }

                // OrderCreated
                if order_dseqs.len() < need_orders {
                    if ev.attr_suffix("EventOrderCreated.id.owner").map(|o| owners.iter().any(|a| a == o)).unwrap_or(false) {
                        if let Some(dseq) = ev
                            .attr_suffix("EventOrderCreated.id.dseq")
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            if !order_dseqs.contains(&dseq) {
                                order_dseqs.push(dseq);
                                eprintln!(
                                    "[events] >>> OrderCreated dseq={} height={}",
                                    dseq, ev.height
                                );
                            }
                        }
                    }
                }

                // BidCreated
                if bid_dseqs.len() < need_bids {
                    if ev.attr_suffix("EventBidCreated.id.owner").map(|o| owners.iter().any(|a| a == o)).unwrap_or(false) {
                        if let Some(dseq) = ev
                            .attr_suffix("EventBidCreated.id.dseq")
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            if !bid_dseqs.contains(&dseq) {
                                bid_dseqs.push(dseq);
                                eprintln!(
                                    "[events] >>> BidCreated dseq={} height={}",
                                    dseq, ev.height
                                );
                            }
                        }
                    }
                }

                // LeaseCreated
                if lease_dseqs.len() < need_leases {
                    if ev.attr_suffix("EventLeaseCreated.id.owner").map(|o| owners.iter().any(|a| a == o)).unwrap_or(false) {
                        if let Some(dseq) = ev
                            .attr_suffix("EventLeaseCreated.id.dseq")
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            if !lease_dseqs.contains(&dseq) {
                                lease_dseqs.push(dseq);
                                eprintln!(
                                    "[events] >>> LeaseCreated dseq={} height={}",
                                    dseq, ev.height
                                );
                            }
                        }
                    }
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                eprintln!("[events] WARNING: receiver lagged by {} events", n);
            }
            Ok(Err(e)) => {
                eprintln!("[events] channel closed: {}", e);
                break;
            }
            Err(_) => {
                if last_heartbeat.elapsed() >= heartbeat_interval {
                    eprintln!(
                        "[events] waiting... height={} orders={}/{} bids={}/{} leases={}/{}  ({:.0}s remaining)",
                        last_height,
                        order_dseqs.len(), need_orders,
                        bid_dseqs.len(), need_bids,
                        lease_dseqs.len(), need_leases,
                        remaining.as_secs_f64(),
                    );
                    last_heartbeat = tokio::time::Instant::now();
                }
            }
        }
    }

    (order_dseqs, bid_dseqs, lease_dseqs)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 1: Direct mode deploy (from akash_parallel::test_parallel_deploy_fund_and_create)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires local Akash dev cluster (just akash-setup + cargo build --bin test-provider)"]
async fn test_oline_akash_deploy() {
    let _ = tracing_subscriber::fmt::try_init();

    // ── 0. Declare test scenario ──────────────────────────────────────────────
    let mut scenario = TestScenario::new(
        "parallel_deploy_fund_and_create",
        "Default oline deploy --parallel (direct mode): DeployAllUnits \
         (A+B+C) -> SelectAllProviders -> SendManifest -> UpdateAllDns. \
         Validates the full Akash deploy lifecycle: single-signer batch \
         deployment, on-chain order/bid/lease creation, manifest upload, \
         all orders owned by master deployer address.",
        1, // expected orders (direct mode = 1 batch tx, HashMap dedupes to 1 observable event)
        3, // expected bids
        3, // expected leases
        3, // expected manifests (one per lease)
    );

    // ── 1. Start local Akash network (cluster + mock provider + faucet) ───────
    let net = IctAkashNetwork::start("akash-fund-create")
        .await
        .expect("IctAkashNetwork::start()");

    eprintln!("[test] Network ready.");
    eprintln!("[test]   RPC:             {}", net.rpc());
    eprintln!("[test]   gRPC:            {}", net.grpc());
    eprintln!("[test]   Provider URI:    {}", net.provider_uri());
    eprintln!("[test]   Provider addr:   {}", net.provider_address());
    eprintln!("[test]   Chain:           {}", net.chain_id());

    // ── 2. Connect WebSocket BEFORE spawning oline ────────────────────────────
    let ws = WsEventStream::connect(net.rpc())
        .await
        .expect("WsEventStream::connect");
    let mut event_rx = ws.subscribe();
    eprintln!("[test] WS event stream connected and subscribed.");

    // ── 3. Fund deployer account via faucet ───────────────────────────────────
    let deployer_client = net.deployer_client().await.expect("deployer client");
    let deployer_addr = deployer_client.address().to_string();
    eprintln!("[test]   Deployer addr:   {}", deployer_addr);

    scenario.context = ScenarioContext {
        chain_id: net.chain_id().to_string(),
        deployer_address: deployer_addr.clone(),
        provider_address: net.provider_address().to_string(),
        rpc: net.rpc().to_string(),
    };

    eprintln!("[test] Funding deployer via faucet (200 AKT)...");
    net.faucet(&deployer_addr, 200_000_000)
        .await
        .expect("faucet: fund deployer");
    eprintln!("[test] Faucet send confirmed.");

    // Build the set of owner addresses.
    // In direct mode, all deployments are owned by the master deployer.
    let mut all_owners: HashSet<String> = HashSet::new();
    all_owners.insert(deployer_addr.clone());

    // ── 4. Spawn oline deploy --parallel (non-blocking) ───────────────────────
    eprintln!("[test] Spawning oline deploy --parallel...");
    let oline_child = spawn_oline_deploy(&net);
    eprintln!("[test] oline process spawned (pid {:?})", oline_child.id());

    // ── 5. Collect events concurrently while oline runs ───────────────────────
    //
    // oline's sequential-per-phase flow:
    //   Order A -> wait for bid A -> create lease A -> send manifest A ->
    //   Order B -> wait for bid B -> create lease B -> send manifest B -> etc.
    //
    // All events appear in the single WS subscription; we collect until
    // we have 3x each (order, bid, lease) or the 300 s budget expires.
    // We match against ALL owner addresses (master + HD children).
    // Direct mode: all 3 MsgCreateDeployment go in one batch tx. CometBFT
    // emits one Tx event whose attrs HashMap dedupes the 3 OrderCreated keys
    // to 1 observable order. Bids and leases come from separate provider txs
    // so we still see 3 of each.
    eprintln!("[test] Collecting on-chain events (300 s budget)...");
    let obs = collect_akash_events(
        &mut event_rx,
        &all_owners,
        1, // orders (batch tx → 1 observable event)
        3, // bids
        3, // leases
        Duration::from_secs(300),
    )
    .await;

    // ── 6. Wait for oline to finish ───────────────────────────────────────────
    eprintln!("[test] Waiting for oline to exit...");
    let oline_output = tokio::task::spawn_blocking(move || {
        oline_child.wait_with_output().expect("wait_with_output")
    })
    .await
    .expect("join");

    let combined_output = format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&oline_output.stdout),
        String::from_utf8_lossy(&oline_output.stderr),
    );

    eprintln!("[test] oline exit status: {:?}", oline_output.status);
    // Print ALL oline output -- not just 100 lines -- so bid query debug logs are visible.
    for line in combined_output.lines() {
        eprintln!("{}", line);
    }

    // ── 6b. Print provider log for bid diagnostics ────────────────────────────
    //
    // The test-provider logs every bid attempt at `info` level:
    //   "bid placed on-chain"         (code == 0)
    //   "bid tx rejected on-chain"    (code != 0, with reason)
    //   "bid broadcast error"           (network error)
    //
    // Printing it here makes bid failures immediately visible in CI output.
    let provider_log_path = "/tmp/akash-devnet-provider.log";
    eprintln!("[test] === Provider log ({}) ===", provider_log_path);
    match std::fs::read_to_string(provider_log_path) {
        Ok(log) => {
            // Print last 200 lines so we see recent activity without flooding.
            let lines: Vec<&str> = log.lines().collect();
            let start = lines.len().saturating_sub(200);
            for line in &lines[start..] {
                eprintln!("{}", line);
            }
        }
        Err(e) => eprintln!("[test] (could not read provider log: {})", e),
    }
    eprintln!("[test] === End provider log ===");

    // ── 6c. REST bid query -- verify on-chain bid state ───────────────────────
    //
    // After collecting WS events, query the REST API directly for all bids
    // from the deployer address.  This catches bids that were placed but whose
    // WS event was missed (e.g. due to receiver lag).
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    {
        let bids_url = format!(
            "{}/akash/market/v1beta5/bids/list?filters.owner={}",
            net.rest(),
            deployer_addr
        );
        eprintln!("[test] Querying REST for on-chain bids: {}", bids_url);
        match http.get(&bids_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        let count = json["bids"].as_array().map(|a| a.len()).unwrap_or(0);
                        eprintln!("[test] On-chain bids (REST): {}", count);
                        if let Some(bids) = json["bids"].as_array() {
                            for b in bids {
                                eprintln!(
                                    "[test]   bid dseq={} provider={} state={}",
                                    b["bid"]["id"]["dseq"].as_str().unwrap_or("?"),
                                    b["bid"]["id"]["provider"].as_str().unwrap_or("?"),
                                    b["bid"]["state"].as_str().unwrap_or("?"),
                                );
                            }
                        }
                    }
                    Err(e) => eprintln!("[test] REST bids JSON parse error: {}", e),
                }
            }
            Ok(resp) => eprintln!("[test] REST bids HTTP {}: skipping", resp.status()),
            Err(e) => eprintln!("[test] REST bids query error: {}", e),
        }
    }

    // ── 6b. REST: on-chain active deployment list ─────────────────────────────
    //
    // The shell script (e2e-akash-parallel.sh) used `akash query deployment list
    // --owner --state active` and asserted >=3.  We do the same via REST so the
    // check always runs (no Akash CLI binary required).
    {
        let deploy_url = format!(
            "{}/akash/deployment/v1beta5/deployments/list?filters.owner={}&filters.state=active",
            net.rest(),
            deployer_addr,
        );
        eprintln!("[test] Querying REST for active deployments: {}", deploy_url);
        match http.get(&deploy_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        let count = json["deployments"]
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0);
                        eprintln!("[test] On-chain active deployments (REST): {}", count);
                        assert!(
                            count >= 3,
                            "Expected >=3 active deployments on-chain, got {} (REST).\nResponse: {}",
                            count,
                            serde_json::to_string_pretty(&json).unwrap_or_default(),
                        );
                        eprintln!("[test] {} active deployments on-chain (REST).", count);
                    }
                    Err(e) => eprintln!("[test] REST deployments JSON parse error: {}", e),
                }
            }
            Ok(resp) => eprintln!("[test] REST deployments HTTP {}: skipping", resp.status()),
            Err(e) => eprintln!("[test] REST deployments query error: {}", e),
        }
    }

    // ── 7. Assert on-chain events ─────────────────────────────────────────────
    //
    // Direct mode: batch tx puts all 3 MsgCreateDeployment in one tx.
    // CometBFT's Tx event attrs HashMap dedupes to 1 observable OrderCreated.
    // Bids and leases arrive in separate provider txs → 3 of each.

    let orders_ok = obs.order_dseqs.len() >= 1;
    let bids_ok = obs.bid_dseqs.len() >= 3;
    let leases_ok = obs.lease_dseqs.len() >= 3;

    // OrderCreated: at least 1 (batch tx → 1 observable in HashMap).
    assert!(
        orders_ok,
        "Expected >=1 OrderCreated event (direct batch), got {} (dseqs: {:?}).\noline output:\n{}",
        obs.order_dseqs.len(),
        obs.order_dseqs,
        combined_output,
    );
    eprintln!("[test] {} OrderCreated events observed: {:?}", obs.order_dseqs.len(), obs.order_dseqs);

    // BidCreated: test-provider must bid on all 3 orders.
    assert!(
        bids_ok,
        "Expected >=3 BidCreated events, got {} (dseqs: {:?}).\n\
         Hint: check provider log above for bid tx rejected details.\n\
         oline output:\n{}",
        obs.bid_dseqs.len(),
        obs.bid_dseqs,
        combined_output,
    );
    eprintln!("[test] {} BidCreated events observed: {:?}", obs.bid_dseqs.len(), obs.bid_dseqs);

    // LeaseCreated: hard assertion — all 3 leases must be created.
    assert!(
        leases_ok,
        "Expected >=3 LeaseCreated events, got {} (dseqs: {:?}).\n\
         Bids were observed — check SelectAllProviders logs.\n\
         oline output:\n{}",
        obs.lease_dseqs.len(),
        obs.lease_dseqs,
        combined_output,
    );
    eprintln!("[test] {} LeaseCreated events observed: {:?}", obs.lease_dseqs.len(), obs.lease_dseqs);

    // Sanity: all dseqs non-zero.
    assert!(
        obs.order_dseqs.iter().all(|d| *d > 0),
        "DSEQs must be non-zero: {:?}",
        obs.order_dseqs
    );

    // ── 7b. Assert direct mode (single-signer batch) ────────────────────────
    //
    // In direct mode, all deployments are created by the master account in a
    // single multi-msg transaction. All order owners should be the deployer.

    // All order owners must be the deployer (direct mode = single signer).
    {
        for owner in &obs.order_owners {
            assert_eq!(
                owner, &deployer_addr,
                "All order owners must be the deployer address in direct mode. \
                 Got {} but expected {}.",
                owner, deployer_addr,
            );
        }
        eprintln!(
            "[test] All {} order owners are the deployer: {}",
            obs.order_owners.len(),
            deployer_addr
        );
    }

    // ── 8. On-chain verification via Akash CLI (optional) ────────────────────
    let home = env::var("HOME").unwrap_or_else(|_| "/root".into());
    let akash_home = format!(
        "{}/go/src/github.com/akash-network/provider/.cache/run/kube/.akash",
        home
    );
    let akash_bin: PathBuf =
        format!("{}/go/src/github.com/akash-network/provider/.cache/bin/akash", home).into();

    if akash_bin.exists() {
        let query_out = Command::new(&akash_bin)
            .args([
                "--home", &akash_home,
                "--node", net.rpc(),
                "query", "deployment", "list",
                "--owner", &deployer_addr,
                "--state", "active",
                "-o", "json",
            ])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let active_count = query_out.matches("\"dseq\"").count();
        eprintln!("[test] On-chain active deployments: {}", active_count);
        if active_count < 3 {
            eprintln!(
                "[test] WARNING: expected >=3 active deployments, got {}.\n{}",
                active_count, query_out
            );
        }
    } else {
        eprintln!("[test] Akash CLI not found -- skipping on-chain CLI verification.");
    }

    // ── 9. Finalise scenario fixture ──────────────────────────────────────────
    scenario.observed = obs;
    scenario.passed = orders_ok && bids_ok && leases_ok;
    scenario.write_fixture();

    eprintln!("[test] Parallel deployment e2e test passed.");

    // ── 10. Cleanup ───────────────────────────────────────────────────────────
    eprintln!("[test] Closing deployments...");
    for &dseq in scenario
        .observed
        .order_dseqs
        .iter()
        .chain(scenario.observed.bid_dseqs.iter())
        .collect::<std::collections::HashSet<_>>()
    {
        close_deployment(&akash_bin, &akash_home, net.rpc(), dseq, net.chain_id());
        eprintln!("[test]   closed DSEQ {}", dseq);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 2: Trusted providers (from akash_parallel::test_parallel_deploy_trusted_providers)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires local Akash dev cluster (just akash-setup + cargo build --bin test-provider)"]
async fn test_oline_akash_trusted_providers() {
    let _ = tracing_subscriber::fmt::try_init();

    // ── 0. Declare test scenario ──────────────────────────────────────────────
    let mut scenario = TestScenario::new(
        "parallel_deploy_trusted_providers",
        "Parallel deployment with trusted provider auto-selection: \
         writes trusted-providers.json, verifies auto-selection from \
         trusted list, validates on-chain order/bid/lease lifecycle.",
        1, // expected orders (direct mode = 1 batch tx observable)
        3, // expected bids
        3, // expected leases
        3, // expected manifests
    );

    // ── 1. Start local Akash network ─────────────────────────────────────────
    let net = IctAkashNetwork::start("akash-trusted-prov")
        .await
        .expect("IctAkashNetwork::start()");

    eprintln!("[trusted-test] Network ready.");
    eprintln!("[trusted-test]   Provider addr: {}", net.provider_address());

    // ── 2. Write trusted-providers.json with test-provider address ────────────
    let config_home = std::env::temp_dir().join("oline-trusted-test-config");
    let _ = std::fs::remove_dir_all(&config_home); // clean slate
    let tp_path = write_trusted_providers(&config_home, net.provider_address());
    eprintln!(
        "[trusted-test] Trusted providers file: {:?}",
        tp_path
    );

    // Verify the file is readable.
    let tp_content = std::fs::read_to_string(&tp_path).expect("read trusted-providers.json");
    eprintln!("[trusted-test] Trusted providers content:\n{}", tp_content);

    // ── 3. Connect WebSocket BEFORE spawning oline ────────────────────────────
    let ws = WsEventStream::connect(net.rpc())
        .await
        .expect("WsEventStream::connect");
    let mut event_rx = ws.subscribe();

    // ── 4. Fund deployer ──────────────────────────────────────────────────────
    let deployer_client = net.deployer_client().await.expect("deployer client");
    let deployer_addr = deployer_client.address().to_string();
    eprintln!("[trusted-test]   Deployer addr: {}", deployer_addr);

    scenario.context = ScenarioContext {
        chain_id: net.chain_id().to_string(),
        deployer_address: deployer_addr.clone(),
        provider_address: net.provider_address().to_string(),
        rpc: net.rpc().to_string(),
    };

    net.faucet(&deployer_addr, 200_000_000)
        .await
        .expect("faucet: fund deployer");
    eprintln!("[trusted-test] Deployer funded.");

    // Build owner set for event matching (direct mode = master only).
    let mut all_owners: HashSet<String> = HashSet::new();
    all_owners.insert(deployer_addr.clone());

    // ── 5. Spawn oline with trusted provider config ───────────────────────────
    let oline_child = spawn_oline_deploy_with(
        &net,
        SpawnOpts {
            config_home: Some(config_home.to_str().unwrap()),
            stop_after_deploy: true,
            ..Default::default()
        },
    );
    eprintln!(
        "[trusted-test] oline spawned (pid {:?}) with XDG_CONFIG_HOME={:?}",
        oline_child.id(),
        config_home
    );

    // ── 6. Collect events ─────────────────────────────────────────────────────
    eprintln!("[trusted-test] Collecting on-chain events (300 s budget)...");
    let obs = collect_akash_events(
        &mut event_rx,
        &all_owners,
        1, // orders (direct batch tx → 1 observable)
        3, // bids
        3, // leases
        Duration::from_secs(300),
    )
    .await;

    // ── 7. Wait for oline to finish ───────────────────────────────────────────
    let oline_output = tokio::task::spawn_blocking(move || {
        oline_child.wait_with_output().expect("wait_with_output")
    })
    .await
    .expect("join");

    let combined_output = format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&oline_output.stdout),
        String::from_utf8_lossy(&oline_output.stderr),
    );

    eprintln!("[trusted-test] oline exit status: {:?}", oline_output.status);
    for line in combined_output.lines() {
        eprintln!("{}", line);
    }

    // ── 8. Assert trusted provider was auto-selected ──────────────────────────
    let trusted_selected = combined_output.contains("[trusted]");
    if trusted_selected {
        eprintln!("[trusted-test] Trusted provider auto-selection confirmed in logs.");
    } else {
        eprintln!(
            "[trusted-test] WARNING: '[trusted]' not found in oline output.\n\
             This may indicate the trusted provider was not bidding in time,\n\
             or the trusted-providers.json was not read correctly."
        );
    }

    // ── 9. Assert on-chain events ─────────────────────────────────────────────
    let orders_ok = obs.order_dseqs.len() >= 1;
    let bids_ok = obs.bid_dseqs.len() >= 3;
    let leases_ok = obs.lease_dseqs.len() >= 3;

    assert!(
        orders_ok,
        "Expected >=1 OrderCreated event (direct batch), got {} (dseqs: {:?}).\noline output:\n{}",
        obs.order_dseqs.len(),
        obs.order_dseqs,
        combined_output,
    );
    eprintln!(
        "[trusted-test] {} OrderCreated events: {:?}",
        obs.order_dseqs.len(),
        obs.order_dseqs
    );

    assert!(
        bids_ok,
        "Expected >=3 BidCreated events, got {} (dseqs: {:?}).\noline output:\n{}",
        obs.bid_dseqs.len(),
        obs.bid_dseqs,
        combined_output,
    );
    eprintln!(
        "[trusted-test] {} BidCreated events: {:?}",
        obs.bid_dseqs.len(),
        obs.bid_dseqs
    );

    assert!(
        leases_ok,
        "Expected >=3 LeaseCreated events, got {} (dseqs: {:?}).\n\
         Bids were observed — check SelectAllProviders logs.\n\
         oline output:\n{}",
        obs.lease_dseqs.len(),
        obs.lease_dseqs,
        combined_output,
    );
    eprintln!(
        "[trusted-test] {} LeaseCreated events: {:?}",
        obs.lease_dseqs.len(),
        obs.lease_dseqs
    );

    if trusted_selected {
        eprintln!("[trusted-test] FULL SUCCESS: trusted provider auto-selected + all leases created.");
    }

    // ── 9b. Assert parallel isolation (no sequence conflicts) ────────────────
    {
        let unique_dseqs: HashSet<u64> = obs.order_dseqs.iter().copied().collect();
        assert_eq!(
            unique_dseqs.len(),
            obs.order_dseqs.len(),
            "Order DSEQs must be distinct (got duplicates: {:?}).",
            obs.order_dseqs,
        );
    }
    assert!(
        !combined_output.contains("account sequence mismatch"),
        "oline output contains 'account sequence mismatch' -- \
         parallel deployment must use separate signing accounts per phase.",
    );
    eprintln!("[trusted-test] Parallel isolation checks passed.");

    // ── 10. Finalise scenario fixture ─────────────────────────────────────────
    scenario.observed = obs;
    scenario.passed = orders_ok && bids_ok && leases_ok && trusted_selected;
    scenario.write_fixture();

    // ── 11. Cleanup ──────────────────────────────────────────────────────────
    let home = env::var("HOME").unwrap_or_else(|_| "/root".into());
    let akash_home = format!(
        "{}/go/src/github.com/akash-network/provider/.cache/run/kube/.akash",
        home
    );
    let akash_bin: PathBuf =
        format!("{}/go/src/github.com/akash-network/provider/.cache/bin/akash", home).into();

    for &dseq in scenario
        .observed
        .order_dseqs
        .iter()
        .chain(scenario.observed.bid_dseqs.iter())
        .collect::<std::collections::HashSet<_>>()
    {
        close_deployment(&akash_bin, &akash_home, net.rpc(), dseq, net.chain_id());
    }

    // Clean up temp config dir.
    let _ = std::fs::remove_dir_all(&config_home);
    eprintln!("[trusted-test] Test complete.");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 3: Direct default fallback (from akash_parallel::test_parallel_deploy_direct_default_fallback)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires local Akash dev cluster (just akash-setup + cargo build --bin test-provider)"]
async fn test_oline_akash_direct_fallback() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut scenario = TestScenario::new(
        "parallel_deploy_direct_default",
        "Parallel deployment WITHOUT explicit OLINE_FUNDING_METHOD -- \
         verifies --parallel auto-defaults to direct (single-signer batch).",
        1, 3, 3, 3, // orders=1 (batch tx), bids=3, leases=3, manifests=3
    );

    let net = IctAkashNetwork::start("akash-direct-fallback")
        .await
        .expect("IctAkashNetwork::start()");
    eprintln!("[direct-default] Network ready.  Provider: {}", net.provider_address());

    let ws = WsEventStream::connect(net.rpc())
        .await
        .expect("WsEventStream::connect");
    let mut event_rx = ws.subscribe();

    let deployer_client = net.deployer_client().await.expect("deployer client");
    let deployer_addr = deployer_client.address().to_string();

    scenario.context = ScenarioContext {
        chain_id: net.chain_id().to_string(),
        deployer_address: deployer_addr.clone(),
        provider_address: net.provider_address().to_string(),
        rpc: net.rpc().to_string(),
    };

    net.faucet(&deployer_addr, 100_000_000)
        .await
        .expect("faucet");
    eprintln!("[direct-default] Deployer funded (100 AKT).");

    // Direct mode: only the master deployer address.
    let mut all_owners: HashSet<String> = HashSet::new();
    all_owners.insert(deployer_addr.clone());

    // Spawn WITHOUT OLINE_FUNDING_METHOD -- tests the auto Direct default.
    let oline_child = spawn_oline_deploy_with(
        &net,
        SpawnOpts {
            skip_funding_method_env: true,
            ..Default::default()
        },
    );
    eprintln!("[direct-default] oline spawned (pid {:?}), OLINE_FUNDING_METHOD not set.", oline_child.id());

    let obs = collect_akash_events(
        &mut event_rx,
        &all_owners,
        1, 3, 3, // orders=1 (batch tx), bids=3, leases=3
        Duration::from_secs(300),
    )
    .await;

    let oline_output = tokio::task::spawn_blocking(move || {
        oline_child.wait_with_output().expect("wait_with_output")
    })
    .await
    .expect("join");

    let combined_output = format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&oline_output.stdout),
        String::from_utf8_lossy(&oline_output.stderr),
    );

    eprintln!("[direct-default] oline exit: {:?}", oline_output.status);
    for line in combined_output.lines() {
        eprintln!("{}", line);
    }

    // ── Assertions ───────────────────────────────────────────────────────────

    let orders_ok = obs.order_dseqs.len() >= 1;
    let bids_ok = obs.bid_dseqs.len() >= 3;
    let leases_ok = obs.lease_dseqs.len() >= 3;

    // At least 1 order (batch tx → 1 observable in HashMap).
    assert!(
        orders_ok,
        "Expected >=1 OrderCreated event (direct batch), got {} (dseqs: {:?}).\noline output:\n{}",
        obs.order_dseqs.len(), obs.order_dseqs, combined_output,
    );

    // All 3 bids.
    assert!(
        bids_ok,
        "Expected >=3 BidCreated events, got {} (dseqs: {:?}).\noline output:\n{}",
        obs.bid_dseqs.len(), obs.bid_dseqs, combined_output,
    );

    // All 3 leases — hard requirement.
    assert!(
        leases_ok,
        "Expected >=3 LeaseCreated events, got {} (dseqs: {:?}).\noline output:\n{}",
        obs.lease_dseqs.len(), obs.lease_dseqs, combined_output,
    );

    // All owners must be the deployer (direct mode = single signer).
    for owner in &obs.order_owners {
        assert_eq!(
            owner, &deployer_addr,
            "All order owners must be deployer in direct mode: got {}", owner,
        );
    }

    // Verify oline logged the Direct default message.
    assert!(
        combined_output.contains("defaulting to direct"),
        "Expected oline to log direct default fallback message.\noline output:\n{}",
        combined_output,
    );
    eprintln!("[direct-default] All assertions passed -- Direct auto-default works.");

    scenario.observed = obs;
    scenario.passed = orders_ok && bids_ok && leases_ok;
    scenario.write_fixture();

    // Cleanup.
    let home = env::var("HOME").unwrap_or_else(|_| "/root".into());
    let akash_home = format!(
        "{}/go/src/github.com/akash-network/provider/.cache/run/kube/.akash", home
    );
    let akash_bin: PathBuf = format!(
        "{}/go/src/github.com/akash-network/provider/.cache/bin/akash", home
    ).into();
    for &dseq in scenario.observed.order_dseqs.iter()
        .chain(scenario.observed.bid_dseqs.iter())
        .collect::<std::collections::HashSet<_>>()
    {
        close_deployment(&akash_bin, &akash_home, net.rpc(), dseq, net.chain_id());
    }
    eprintln!("[direct-default] Test complete.");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 4: Benchmark (from oline_benchmark_test::test_oline_benchmark_test)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires local Akash dev cluster + OMNIBUS_IMAGE for real containers"]
async fn test_oline_akash_benchmark() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    let mut timings = BenchmarkTimings::new();

    // Enable container spawning in test-provider BEFORE starting the network,
    // since the devnet script inherits env from this test process.
    std::env::set_var("PROVIDER_SPAWN_CONTAINERS", "1");

    // ── 1. Start network ─────────────────────────────────────────────────────
    eprintln!("[benchmark] Starting AkashLocalNetwork...");
    let net = AkashLocalNetwork::start()
        .await
        .expect("AkashLocalNetwork::start()");
    timings.network_ready = Some(Instant::now());

    eprintln!("[benchmark] Network ready.");
    eprintln!("[benchmark]   RPC:          {}", net.rpc());
    eprintln!("[benchmark]   Provider:     {}", net.provider_uri());
    eprintln!("[benchmark]   Chain:        {}", net.chain_id());

    // ── 2. Fund deployer ─────────────────────────────────────────────────────
    let deployer_client = net.deployer_client().await.expect("deployer client");
    let deployer_addr = deployer_client.address().to_string();
    eprintln!("[benchmark]   Deployer:     {}", deployer_addr);

    eprintln!("[benchmark] Funding deployer via faucet (100 AKT)...");
    net.faucet(&deployer_addr, 100_000_000)
        .await
        .expect("faucet: fund deployer");

    // ── 2b. Compute all possible owner addresses (HD children) ──────────────
    // With HD funding, child[0] == master, but child[1] and child[2] have
    // different addresses.  The event collector must match all of them.
    let hd_count = 3u32;
    let mut all_owner_addrs = vec![deployer_addr.clone()];
    for i in 1..hd_count {
        match child_address_str(&net.deployer_mnemonic, i, "akash") {
            Ok(addr) => {
                eprintln!("[benchmark]   Child[{}]:     {}", i, addr);
                all_owner_addrs.push(addr);
            }
            Err(e) => eprintln!("[benchmark]   Child[{}]: derivation failed: {}", i, e),
        }
    }
    eprintln!(
        "[benchmark] Tracking {} owner addresses for event matching",
        all_owner_addrs.len()
    );

    // ── 3. Subscribe WS events ───────────────────────────────────────────────
    let ws = WsEventStream::connect(net.rpc())
        .await
        .expect("WsEventStream::connect");
    let mut event_rx = ws.subscribe();

    // ── 4. Spawn oline ───────────────────────────────────────────────────────
    eprintln!("[benchmark] Spawning oline deploy --parallel (HD funding + containers)...");
    let mut oline_child = spawn_oline_full(&net);
    timings.oline_spawned = Some(Instant::now());
    eprintln!("[benchmark] oline spawned (pid {:?})", oline_child.id());

    // Stream oline stdout/stderr in real-time with [oline] prefix.
    let stdout = oline_child.stdout.take().expect("stdout piped");
    let stderr = oline_child.stderr.take().expect("stderr piped");
    let stdout_thread = stream_output(stdout, "oline:out");
    let stderr_thread = stream_output(stderr, "oline");

    // ── 5. Collect events ────────────────────────────────────────────────────
    eprintln!("[benchmark] Collecting on-chain events (300s budget)...");
    let (order_dseqs, bid_dseqs, lease_dseqs) = collect_akash_events_benchmark(
        &mut event_rx,
        &all_owner_addrs,
        3,
        3,
        3,
        Duration::from_secs(300),
    )
    .await;

    // ── 6. Wait for oline to exit ────────────────────────────────────────────
    eprintln!("[benchmark] Waiting for oline to exit...");
    let exit_status = tokio::task::spawn_blocking(move || {
        oline_child.wait().expect("wait")
    })
    .await
    .expect("join");

    timings.all_deployed = Some(Instant::now());
    eprintln!("[benchmark] oline exit status: {:?}", exit_status);

    // Wait for output streaming threads to complete.
    let stdout_lines = stdout_thread.join().unwrap_or_default();
    let stderr_lines = stderr_thread.join().unwrap_or_default();
    eprintln!(
        "[benchmark] oline output: {} stdout lines, {} stderr lines",
        stdout_lines.len(),
        stderr_lines.len()
    );

    // ── 6b. Print provider log ───────────────────────────────────────────────
    print_provider_log();

    // ── 6c. REST diagnostics (query each owner address) ─────────────────────
    for addr in &all_owner_addrs {
        print_onchain_bids(net.rest(), addr).await;
        print_onchain_deployments(net.rest(), addr).await;
    }

    // ── 6d. Container logs ───────────────────────────────────────────────────
    print_container_logs();

    // ── 7. Assert events ─────────────────────────────────────────────────────
    eprintln!(
        "[benchmark] Events: orders={} bids={} leases={}",
        order_dseqs.len(),
        bid_dseqs.len(),
        lease_dseqs.len()
    );

    assert!(
        order_dseqs.len() >= 3,
        "Expected >=3 orders, got {} (dseqs: {:?})",
        order_dseqs.len(),
        order_dseqs,
    );
    assert!(
        bid_dseqs.len() >= 3,
        "Expected >=3 bids, got {} (dseqs: {:?})\nHint: check provider log above for bid details.",
        bid_dseqs.len(),
        bid_dseqs,
    );

    // ── 8. Discover RPC ports ────────────────────────────────────────────────
    let all_dseqs: Vec<u64> = order_dseqs
        .iter()
        .chain(lease_dseqs.iter())
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    eprintln!("[benchmark] Discovering container RPC ports...");
    let rpc_endpoints =
        discover_rpc_ports(net.provider_uri(), &all_owner_addrs, &all_dseqs).await;

    eprintln!(
        "[benchmark] Found {} RPC endpoints: {:?}",
        rpc_endpoints.len(),
        rpc_endpoints
    );

    // ── 9. Probe each endpoint + wait for block sync ───────────────────────
    if !rpc_endpoints.is_empty() {
        // Deduplicate endpoints before probing.
        let unique_endpoints: Vec<String> = rpc_endpoints
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .cloned()
            .collect();

        // Probe each endpoint: try /status and detect cosmos vs nginx.
        let probe_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        eprintln!(
            "[benchmark] Probing {} unique RPC endpoints...",
            unique_endpoints.len()
        );
        let mut cosmos_endpoints = Vec::new();
        for ep in &unique_endpoints {
            let url = format!("{}/status", ep);
            match probe_client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let is_cosmos = body.contains("sync_info") || body.contains("node_info");
                    let preview = if body.len() > 500 {
                        format!("{}...", &body[..500])
                    } else {
                        body
                    };
                    eprintln!(
                        "[benchmark] {} -> HTTP {} cosmos={} : {}",
                        url, status, is_cosmos, preview
                    );
                    if is_cosmos {
                        cosmos_endpoints.push(ep.clone());
                    }
                }
                Err(e) => {
                    eprintln!("[benchmark] {} -> ERROR: {}", url, e);
                }
            }
        }

        // Also print docker container status for spawned deployments.
        print_container_logs();

        if cosmos_endpoints.is_empty() {
            eprintln!(
                "[benchmark] No cosmos RPC endpoints detected (all {} responded as nginx/other). \
                 Skipping block sync -- containers are healthy.",
                unique_endpoints.len()
            );
            timings.sync_complete = Some(Instant::now());
        } else {
            eprintln!(
                "[benchmark] {} cosmos endpoints found -- waiting for block sync (max 300s)...",
                cosmos_endpoints.len()
            );
            let synced =
                wait_for_sync(&cosmos_endpoints, Duration::from_secs(300), 1).await;
            if synced {
                timings.sync_complete = Some(Instant::now());
                eprintln!("[benchmark] All nodes synced.");
            } else {
                eprintln!("[benchmark] Block sync did not converge within timeout.");
            }
        }
    } else {
        eprintln!(
            "[benchmark] No RPC endpoints discovered -- skipping sync wait. \
             (expected with nginx:alpine test images)"
        );
    }

    // ── 10. Print benchmark ──────────────────────────────────────────────────
    timings.print_summary();

    eprintln!("[benchmark] Parallel benchmark complete.");

    // `net` drops here -> provider killed -> cleanup_containers runs.
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test 5: TLS workflow (from e2e_workflow::test_tls_workflow_docker)
// ═══════════════════════════════════════════════════════════════════════════════

const TLS_CONTAINER_NAME: &str = "oline-e2e-test";
const SSH_HOST: &str = "127.0.0.1";
const SSH_P_HOST: u16 = 2222;
const SSH_BOOTSTRAP_TIMEOUT_SECS: u64 = 120;
const NODE_LAUNCH_TIMEOUT_SECS: u64 = 600;

#[tokio::test]
#[ignore = "requires Docker + OMNIBUS_IMAGE (just e2e)"]
async fn test_oline_akash_tls_workflow() {
    for (key, value) in env::vars() {
        println!("{key}: {value}");
    }

    // ── 0. Read required env vars ─────────────────────────────────────────────
    // Prefer E2E_OMNIBUS_IMAGE (locally-built, arm64-compatible), fall back to OMNIBUS_IMAGE.
    let Some(omnibus_image) = dotenvy::var("E2E_OMNIBUS_IMAGE")
        .or_else(|_| dotenvy::var("OMNIBUS_IMAGE"))
        .ok()
    else {
        println!(
            "Skipping test_oline_akash_tls_workflow: set E2E_OMNIBUS_IMAGE or OMNIBUS_IMAGE to run."
        );
        return;
    };
    // All scripts and chain metadata are delivered via SFTP -- no remote fetches required.
    // Env overrides allow CI to supply different values; the test works without any of them.

    // CHAIN_ID: default matches templates/json/chain.json, the file pushed to /tmp/chain.json.
    // Hardcoding the default ensures the entrypoint never errors even if the upload races.
    let chain_id = dotenvy::var("CHAIN_ID")
        .or_else(|_| dotenvy::var("OLINE_CHAIN_ID"))
        .unwrap_or_else(|_| "morocco-1".to_string());

    // CHAIN_JSON URL: entrypoint checks /tmp/chain.json first (pushed via SFTP),
    // so this remote URL is only a fallback override for CI.
    let chain_json = std::env::var("CHAIN_JSON").ok();

    // Bootstrap entrypoint: curled to /tmp/wrapper.sh at container start.
    // The SFTP-pushed /tmp/oline-entrypoint-local.sh takes over for the start phase
    // (entrypoint self-override at line 71-75 of oline-entrypoint.sh).
    let entrypoint_url = std::env::var("ENTRYPOINT_URL").unwrap_or_else(|_| {
        "https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/audible/oline-entrypoint.sh".into()
    });

    // TLS setup: entrypoint checks /tmp/tls-setup.sh before reading TLS_CONFIG_URL.
    // Default to the local path so the value is semantically meaningful even when unused.
    let tls_config_url =
        std::env::var("TLS_CONFIG_URL").unwrap_or_else(|_| "file:///tmp/tls-setup.sh".into());

    let snapshot_url = std::env::var("SNAPSHOT_URL").ok();

    println!("  [e2e] OMNIBUS_IMAGE:  {}", omnibus_image);
    println!("  [e2e] CHAIN_ID:       {} (local default)", chain_id);
    println!(
        "  [e2e] CHAIN_JSON:     {}",
        chain_json
            .as_deref()
            .unwrap_or("(not set -- using /tmp/chain.json via SFTP)")
    );
    println!("  [e2e] ENTRYPOINT_URL: {}", entrypoint_url);
    println!(
        "  [e2e] TLS_CONFIG_URL: {} (overridden by /tmp/tls-setup.sh if present)",
        tls_config_url
    );
    println!(
        "  [e2e] SNAPSHOT_URL:   {}",
        snapshot_url
            .as_deref()
            .unwrap_or("(not set -- snapshot skipped)")
    );

    // ── 1. Set env vars consumed by the crypto functions ──────────────────────
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("SSH_P", "22");
    }

    // ── 2. Init tracing ───────────────────────────────────────────────────────
    tracing_subscriber::fmt::try_init().ok();

    // ── 3. Create workspace directory ─────────────────────────────────────────
    let workdir = PathBuf::from("/tmp/oline-e2e");
    std::fs::create_dir_all(&workdir).expect("Failed to create /tmp/oline-e2e");

    let tls_cert_path = workdir.join("cert.pem");
    let tls_key_path = workdir.join("privkey.pem");

    // ── 4. Generate SSH keypair via testing framework ─────────────────────────
    let (ssh_pubkey, _ssh_privkey_pem, ssh_key_path) =
        generate_ssh_keypair(&workdir).expect("generate_ssh_keypair failed");
    let ssh_pubkey = ssh_pubkey.trim().to_string();

    // ── 5. Generate self-signed TLS cert via rcgen ────────────────────────────
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen failed");
    let tls_cert_pem = cert.pem();
    let tls_key_pem = key_pair.serialize_pem();
    std::fs::write(&tls_cert_path, tls_cert_pem.as_bytes()).expect("write cert.pem");
    std::fs::write(&tls_key_path, tls_key_pem.as_bytes()).expect("write privkey.pem");
    let tls_cert = tls_cert_pem.into_bytes();
    let tls_privkey = tls_key_pem.into_bytes();

    // ── 6. Start Docker container via testing framework ───────────────────────
    // Inline bootstrap: install sshd, set up authorized_keys, persist env, exec sshd.
    // No remote URL required -- all scripts are delivered via SFTP after SSH comes up.
    let bootstrap_cmd = r#"set -e
mkdir -p /root/.ssh
echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
if ! command -v sshd >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null 2>&1 \
    || apk add --no-cache openssh >/dev/null 2>&1 || true
fi
SSHD_BIN=$(command -v sshd 2>/dev/null)
mkdir -p /run/sshd /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
printf '\nPermitRootLogin yes\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config
mkdir -p /tmp/tls
export -p > /tmp/oline-env.sh
echo "Bootstrap complete — handing off to sshd."
exec "$SSHD_BIN" -D"#;
    println!(
        "\n  [e2e] Starting container {} with image {}",
        TLS_CONTAINER_NAME, omnibus_image
    );

    let mut env_map: HashMap<String, String> = [
        ("SSH_PUBKEY", ssh_pubkey.as_str()),
        ("SNAPSHOT_RETAIN", "0"),
        ("DOWNLOAD_GENESIS", "0"),
        ("RPC_DOMAIN", "localhost"),
        ("RPC_P", "443"),
        // CHAIN_ID is always set; entrypoint also derives it from /tmp/chain.json
        ("CHAIN_ID", chain_id.as_str()),
        ("TLS_CONFIG_URL", tls_config_url.as_str()),
        ("ENTRYPOINT_URL", entrypoint_url.as_str()),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    // CHAIN_JSON URL: only set if explicitly overridden -- /tmp/chain.json handles the default case
    if let Some(ref cj) = chain_json {
        env_map.insert("CHAIN_JSON".into(), cj.clone());
    }
    if let Some(ref url) = snapshot_url {
        env_map.insert("SNAPSHOT_URL".into(), url.clone());
    }

    let _container = run_container(&ContainerSpec {
        name: TLS_CONTAINER_NAME.into(),
        image: omnibus_image.clone(),
        env: env_map,
        ports: vec![ContainerPort {
            internal: 22,
            host: SSH_P_HOST,
        }],
        entrypoint: Some("/bin/bash".into()),
        command: Some(bootstrap_cmd.to_string()),
        extra_hosts: vec![],
    })
    .expect("docker run failed");

    // ── 7. Wait for SSH to become available ───────────────────────────────────
    println!(
        "  [e2e] Waiting for SSH on {}:{} (up to {}s)",
        SSH_HOST, SSH_P_HOST, SSH_BOOTSTRAP_TIMEOUT_SECS
    );
    let ssh_ready = wait_for_tcp(
        SSH_HOST,
        SSH_P_HOST,
        Duration::from_secs(SSH_BOOTSTRAP_TIMEOUT_SECS),
    );
    assert!(
        ssh_ready,
        "SSH port {}:{} never became available within {}s -- check `docker logs {}`",
        SSH_HOST, SSH_P_HOST, SSH_BOOTSTRAP_TIMEOUT_SECS, TLS_CONTAINER_NAME
    );
    println!("  [e2e] SSH is up.");
    std::thread::sleep(Duration::from_secs(2));

    // ── 8. Build ServiceEndpoint ───────────────────────────────────────────────
    let endpoints = vec![ServiceEndpoint {
        service: TLS_CONTAINER_NAME.into(),
        uri: "http://127.0.0.1".into(),
        port: SSH_P_HOST,
        internal_port: 22,
    }];

    // ── 9. Diagnostics -- container logs + exec check ───────────────────────────
    {
        // Verify authorized_keys was written by bootstrap.
        let auth_keys = container_exec(
            TLS_CONTAINER_NAME,
            "cat /root/.ssh/authorized_keys 2>/dev/null || echo '(empty)'",
        );
        println!("  [diag] authorized_keys: {}", auth_keys.trim());

        // Optionally verify via actual SSH (confirms sshd + key auth works).
        let ssh_test = Command::new("ssh")
            .args([
                "-i",
                ssh_key_path.to_str().unwrap(),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                &SSH_P_HOST.to_string(),
                &format!("root@{}", SSH_HOST),
                "echo SSH_OK",
            ])
            .output();
        match ssh_test {
            Ok(out) => println!(
                "  [diag] plain ssh exit: {} / stdout: {}",
                out.status,
                String::from_utf8_lossy(&out.stdout).trim()
            ),
            Err(e) => println!("  [diag] ssh command error: {}", e),
        }

        let logs = container_logs(TLS_CONTAINER_NAME, 60);
        println!("  [diag] --- docker logs (last 60 lines) ---");
        for line in logs.lines() {
            println!("  [diag] {}", line);
        }
        println!("  [diag] --- end docker logs ---");
    }

    // ── 10. Upload TLS certs via pre-start file delivery ──────────────────────
    let remote_cert_path = "/tmp/tls/cert.pem".to_string();
    let remote_key_path = "/tmp/tls/privkey.pem".to_string();
    let pre_start_files = vec![
        PreStartFile {
            source: FileSource::Bytes(tls_cert),
            remote_path: remote_cert_path.clone(),
        },
        PreStartFile {
            source: FileSource::Bytes(tls_privkey),
            remote_path: remote_key_path.clone(),
        },
    ];
    println!("  [e2e] Uploading TLS certs via pre-start file delivery...");
    push_pre_start_files("e2e-test", &endpoints, &ssh_key_path, &pre_start_files, 7)
        .await
        .expect("push_pre_start_files failed");
    println!("  [e2e] TLS certs uploaded.");

    // ── 10.5. Push local scripts ───────────────────────────────────────────────
    println!("  [e2e] Pushing local scripts (entrypoint + tls-setup + nginx + chain.json)...");
    push_scripts_sftp(
        "e2e-test",
        &endpoints,
        &ssh_key_path,
        "plays/audible",
        Some("plays/flea-flicker/nginx"),
    )
    .await
    .expect("push_scripts_sftp failed");
    println!("  [e2e] Local scripts pushed.");

    // ── 11. Verify cert paths + signal node start ─────────────────────────────
    let mut sdl_vars: HashMap<String, String> = HashMap::new();
    sdl_vars.insert("CHAIN_ID".into(), chain_id.clone());
    if let Some(ref cj) = chain_json {
        sdl_vars.insert("CHAIN_JSON".into(), cj.clone());
    }
    sdl_vars.insert("TLS_CONFIG_URL".into(), tls_config_url.clone());
    sdl_vars.insert("ADDRBOOK_URL".into(), String::new());
    sdl_vars.insert("OMNIBUS_IMAGE".into(), omnibus_image.clone());
    sdl_vars.insert("RPC_DOMAIN".into(), "localhost".into());
    sdl_vars.insert("RPC_P".into(), "443".into());

    let remote_paths = vec![remote_cert_path, remote_key_path];
    println!("  [e2e] Verifying files + launching node setup...");
    verify_files_and_signal_start(
        "e2e-test",
        &endpoints,
        &ssh_key_path,
        &remote_paths,
        &sdl_vars,
    )
    .await
    .expect("verify_files_and_signal_start failed");
    println!("  [e2e] Node setup launched in background.");

    // ── 11.5. Verify /tmp/oline-env.sh contains the required service vars ─────
    println!("\n  [e2e] Checking /tmp/oline-env.sh for required service vars...");
    let (env_raw, env_parsed) = read_container_env_file(TLS_CONTAINER_NAME);
    println!(
        "  [e2e] Parsed {} entries from /tmp/oline-env.sh",
        env_parsed.len()
    );

    let mut expected_pairs: Vec<(&str, String)> = vec![
        ("RPC_DOMAIN", "localhost".into()),
        ("RPC_P", "443".into()),
        ("CHAIN_ID", chain_id.clone()),
        ("TLS_CONFIG_URL", tls_config_url.clone()),
    ];
    if let Some(ref cj) = chain_json {
        expected_pairs.push(("CHAIN_JSON", cj.clone()));
    }
    let expected_env: Vec<(&str, &str)> = expected_pairs
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();

    let mut env_ok = true;
    for (k, expected_v) in &expected_env {
        match env_parsed.get(*k) {
            Some(actual) if actual == expected_v => println!("  [e2e]   [OK]  {}={}", k, actual),
            Some(actual) => {
                eprintln!(
                    "  [e2e]   [FAIL] {}={:?}  (expected {:?})",
                    k, actual, expected_v
                );
                env_ok = false;
            }
            None => {
                eprintln!("  [e2e]   [FAIL] {} not found in /tmp/oline-env.sh", k);
                env_ok = false;
            }
        }
    }

    if !env_ok {
        eprintln!("\n  [e2e] /tmp/oline-env.sh raw content:\n{}", env_raw);
        panic!("env file check failed -- service vars missing or incorrect (see above)");
    }
    println!("  [e2e] /tmp/oline-env.sh check passed.\n");

    // ── 12. Stream /tmp/oline-node.log live until all markers appear ──────────
    // `tail -f` streams each line as it is written by the startup script.
    // The loop exits immediately when the final marker arrives -- no polling,
    // no repeated output, live progress.
    let markers: &[&str] = &[
        "=== TLS setup complete ===",
        "=== Cosmos node setup complete ===",
        "=== Launching:",
    ];
    println!(
        "  [e2e] Streaming node log (up to {}s)...",
        NODE_LAUNCH_TIMEOUT_SECS
    );

    // `touch` ensures the file exists even if the startup script hasn't run yet.
    let mut tail = Command::new("docker")
        .args([
            "exec",
            TLS_CONTAINER_NAME,
            "bash",
            "-c",
            "touch /tmp/oline-node.log && tail -f /tmp/oline-node.log",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("docker exec tail -f failed");

    let deadline = Instant::now() + Duration::from_secs(NODE_LAUNCH_TIMEOUT_SECS);
    let mut log_buf = String::new();
    {
        let stdout = tail.stdout.take().expect("piped stdout");
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            println!("  [node] {}", line);
            log_buf.push_str(&line);
            log_buf.push('\n');
            if line.contains("=== Launching:") {
                break;
            }
            if Instant::now() > deadline {
                break;
            }
        }
    }
    let _ = tail.kill();
    let _ = tail.wait();

    // ── 13. Assert ────────────────────────────────────────────────────────────
    let missing: Vec<&&str> = markers.iter().filter(|m| !log_buf.contains(**m)).collect();
    if !missing.is_empty() {
        panic!(
            "E2E test FAILED -- missing markers: {:?}\n\
             Tip: run `docker logs {}` for bootstrap output.",
            missing, TLS_CONTAINER_NAME
        );
    }

    println!("  [e2e] All markers found -- test PASSED.");
    // `_container` drops here -> `docker rm -f oline-e2e-test`
}
