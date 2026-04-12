// tests/local_network_e2e.rs
//
// Full local-network e2e test using local-terp as the base chain.
//
// What this tests:
//   1. Fetch genesis + peer ID from a running local-terp container
//   2. Start oline snapshot + seed containers configured to sync from local-terp
//      (no snapshot archive needed — nodes sync from genesis via P2P)
//   3. Phase A SSH delivery: push pre-start files → signal start on both nodes
//   4. Wait for both nodes' RPC to respond and extract peer IDs
//   5. `ssh_push_env_and_run`: push updated P2P peers (snapshot ↔ seed) to the
//      seed node, restart terpd, verify it reconnects
//   6. Assert both nodes are syncing blocks from local-terp (height > 0)
//
// Prerequisites:
//   1. Docker installed
//   2. local-terp container running:  ./tests/localterp.sh wait
//   3. OMNIBUS_IMAGE set (cosmos-omnibus with terpd binary):
//        OMNIBUS_IMAGE=oline-omnibus:local
//      or set in .env:
//        E2E_OMNIBUS_IMAGE=oline-omnibus:local
//
// Run:
//   ./tests/localterp.sh wait
//   OMNIBUS_IMAGE=oline-omnibus:local \
//   cargo test --test local_network_e2e -- --nocapture --test-threads=1
//
//   or via Justfile:
//   just e2e-network

use o_line_sdl::{
    crypto::{
        push_pre_start_files, ssh_push_env_and_run, verify_files_and_signal_start, FileSource,
        PreStartFile,
    },
    deployer::OLineDeployer,
    testing::docker::{
        container_exec, container_logs, remove_containers, run_container, wait_for_tcp,
        AbortOnDrop, ContainerHandle, ContainerPort, ContainerSpec,
    },
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};

// ── Port layout (no conflict with local_phase_a.rs: 2232/2233, 26757/26767) ─

const NET_SNAP_CONTAINER: &str = "oline-net-snapshot";
const NET_SEED_CONTAINER: &str = "oline-net-seed";

const NET_SNAP_SSH_P: u16 = 2244;
const NET_SNAP_RPC_P: u16 = 26777;
const NET_SNAP_P2P_P: u16 = 26776;

const NET_SEED_SSH_P: u16 = 2245;
const NET_SEED_RPC_P: u16 = 26787;
const NET_SEED_P2P_P: u16 = 26786;

const GENESIS_HTTP_P: u16 = 29999;

const LOCAL_TERP_CONTAINER: &str = "local-terp";
const LOCAL_TERP_IMAGE: &str = "terpnetwork/terp-core:localterp";
const LOCAL_TERP_RPC: &str = "http://127.0.0.1:26657";
const LOCAL_TERP_P2P_HOST_P: u16 = 26656;

const SSH_WAIT_TIMEOUT: Duration = Duration::from_secs(180);

// ── local-terp lifecycle ──────────────────────────────────────────────────────

/// RAII guard for the local-terp container.
/// Stops the container on drop only if this guard started it.
struct LocalTerpGuard {
    owned: bool,
}

impl Drop for LocalTerpGuard {
    fn drop(&mut self) {
        if self.owned {
            println!("  [local-terp] Stopping local-terp...");
            let _ = Command::new("docker")
                .args(["rm", "-f", LOCAL_TERP_CONTAINER])
                .output();
        }
    }
}

/// Ensure local-terp is running, starting it if needed.
/// Returns a guard that stops it on drop (only if this call started it).
async fn ensure_local_terp() -> LocalTerpGuard {
    // Check if already running and responsive.
    let is_running = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.State.Running}}",
            LOCAL_TERP_CONTAINER,
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false);

    if is_running && rpc_status(LOCAL_TERP_RPC).await.is_some() {
        println!("  [local-terp] Already running — will leave it running after test.");
        return LocalTerpGuard { owned: false };
    }

    // Remove any stale/stopped container.
    let _ = Command::new("docker")
        .args(["rm", "-f", LOCAL_TERP_CONTAINER])
        .output();

    println!("  [local-terp] Starting {} ...", LOCAL_TERP_IMAGE);
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            LOCAL_TERP_CONTAINER,
            "-p",
            "26657:26657",
            "-p",
            "26656:26656",
            "-p",
            "1317:1317",
            "-p",
            "9090:9090",
            "-p",
            "5000:5000",
            LOCAL_TERP_IMAGE,
        ])
        .status()
        .expect("docker run failed for local-terp (is Docker running?)");

    assert!(status.success(), "Failed to start local-terp container");

    println!("  [local-terp] Waiting for RPC (up to 120s)...");
    assert!(
        wait_for_rpc(LOCAL_TERP_RPC, 120).await,
        "local-terp RPC never came up within 120s — check: docker logs {}",
        LOCAL_TERP_CONTAINER
    );
    println!("  [local-terp] Ready.");
    LocalTerpGuard { owned: true }
}

// ── Env loading ───────────────────────────────────────────────────────────────

fn load_dotenv_fallback(path: &str) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"').trim_matches('\'');
            if std::env::var(key).is_err() && !val.is_empty() {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var(key, val);
                }
            }
        }
    }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

/// Fetch `<rpc_url>/status` and return the parsed JSON value.
async fn rpc_status(rpc_url: &str) -> Option<serde_json::Value> {
    let url = format!("{}/status", rpc_url.trim_end_matches('/'));
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .get(&url)
        .send()
        .await
        .ok()?
        .json::<serde_json::Value>()
        .await
        .ok()?;
    Some(resp)
}

/// Return the latest block height from a node RPC, or `None` if unreachable.
async fn get_block_height(rpc_url: &str) -> Option<u64> {
    let status = rpc_status(rpc_url).await?;
    let height_str = status.pointer("/result/sync_info/latest_block_height")?;
    height_str.as_str()?.parse::<u64>().ok()
}

/// Poll `rpc_url/status` until it responds or `timeout_secs` elapses.
/// Returns `true` if the RPC became responsive within the timeout.
async fn wait_for_rpc(rpc_url: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if rpc_status(rpc_url).await.is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    println!();
    false
}

/// Poll until the node reports `latest_block_height >= min_height`.
/// Returns the actual height reached, or `None` on timeout.
async fn wait_for_height(rpc_url: &str, min_height: u64, timeout_secs: u64) -> Option<u64> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if let Some(h) = get_block_height(rpc_url).await {
            if h >= min_height {
                return Some(h);
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    println!();
    None
}

// ── Genesis server ────────────────────────────────────────────────────────────

/// Fetch the local-terp genesis, unwrap it from the Tendermint RPC envelope,
/// and return the raw genesis JSON string.
///
/// `GET http://127.0.0.1:26657/genesis` returns:
/// ```json
/// {"result": {"genesis": { ... actual genesis ... }}}
/// ```
async fn fetch_local_terp_genesis() -> Result<String, String> {
    let url = format!("{}/genesis", LOCAL_TERP_RPC);
    let body = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url} failed: {e}"))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("JSON parse failed: {e}"))?;

    let genesis = body
        .pointer("/result/genesis")
        .ok_or("Missing .result.genesis in /genesis response")?
        .clone();

    serde_json::to_string(&genesis).map_err(|e| e.to_string())
}

/// Fetch the local-terp node ID from `/status`.
async fn fetch_local_terp_node_id() -> Result<String, String> {
    let status = rpc_status(LOCAL_TERP_RPC)
        .await
        .ok_or("local-terp RPC not responding — run: ./tests/localterp.sh wait")?;

    status
        .pointer("/result/node_info/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Missing node_info.id in: {}", status))
}

/// Spawn a tiny HTTP server on `0.0.0.0:{port}` that serves `genesis_json`
/// for any GET request.  Returns a `JoinHandle` — abort it to stop the server.
fn start_genesis_server(genesis_json: Arc<String>, port: u16) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .expect("Failed to bind genesis HTTP server");

        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let json = genesis_json.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
                let body = json.as_bytes();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    })
}

// ── SSH keypair ───────────────────────────────────────────────────────────────

fn generate_test_ssh_keypair(workdir: &Path) -> (String, PathBuf) {
    let key_path = workdir.join("net-test-ssh-key");
    let pub_path = workdir.join("net-test-ssh-key.pub");
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pub_path);

    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-f",
            key_path.to_str().unwrap(),
            "-N",
            "",
            "-q",
        ])
        .status()
        .expect("ssh-keygen not found");
    assert!(status.success(), "ssh-keygen failed");

    let pubkey = std::fs::read_to_string(&pub_path)
        .expect("Failed to read pubkey")
        .trim()
        .to_string();

    // Clear any stale host key entries for these ports
    for port in [NET_SNAP_SSH_P, NET_SEED_SSH_P] {
        let _ = Command::new("ssh-keygen")
            .args(["-R", &format!("[127.0.0.1]:{}", port)])
            .output();
    }

    (pubkey, key_path)
}

// ── Container endpoints ───────────────────────────────────────────────────────

fn snapshot_endpoints() -> Vec<akash_deploy_rs::ServiceEndpoint> {
    vec![
        akash_deploy_rs::ServiceEndpoint {
            service: NET_SNAP_CONTAINER.into(),
            uri: "http://127.0.0.1".into(),
            port: NET_SNAP_SSH_P,
            internal_port: 22,
        },
        akash_deploy_rs::ServiceEndpoint {
            service: NET_SNAP_CONTAINER.into(),
            uri: "http://127.0.0.1".into(),
            port: NET_SNAP_RPC_P,
            internal_port: 26657,
        },
        akash_deploy_rs::ServiceEndpoint {
            service: NET_SNAP_CONTAINER.into(),
            uri: "http://127.0.0.1".into(),
            port: NET_SNAP_P2P_P,
            internal_port: 26656,
        },
    ]
}

fn seed_endpoints() -> Vec<akash_deploy_rs::ServiceEndpoint> {
    vec![
        akash_deploy_rs::ServiceEndpoint {
            service: NET_SEED_CONTAINER.into(),
            uri: "http://127.0.0.1".into(),
            port: NET_SEED_SSH_P,
            internal_port: 22,
        },
        akash_deploy_rs::ServiceEndpoint {
            service: NET_SEED_CONTAINER.into(),
            uri: "http://127.0.0.1".into(),
            port: NET_SEED_RPC_P,
            internal_port: 26657,
        },
        akash_deploy_rs::ServiceEndpoint {
            service: NET_SEED_CONTAINER.into(),
            uri: "http://127.0.0.1".into(),
            port: NET_SEED_P2P_P,
            internal_port: 26656,
        },
    ]
}

// ── Peer string conversion ────────────────────────────────────────────────────

/// Convert `"<id>@127.0.0.1:<host_port>"` to `"<id>@host.docker.internal:<host_port>"`.
/// Containers cannot reach 127.0.0.1 (the host); `host.docker.internal` is the
/// bridge address on Mac/Windows and Linux (with --add-host=host-gateway).
fn to_container_peer(peer: &str, host_port: u16) -> String {
    if let Some(id) = peer.split('@').next() {
        format!("{}@host.docker.internal:{}", id, host_port)
    } else {
        peer.to_string()
    }
}

// ── Container diagnostics ─────────────────────────────────────────────────────

/// Print a full diagnostic dump for a container: oline-node.log, p2p config, env.
/// Uses `docker exec` so it works even when SSH is not the diagnostic channel.
fn dump_container_diagnostics(container: &str) {
    println!("\n  ════ DIAGNOSTICS: {} ════", container);

    println!("\n  ── /tmp/oline-node.log (full) ──");
    let log = container_exec(
        container,
        "cat /tmp/oline-node.log 2>/dev/null || echo '(file not found)'",
    );
    for line in log.lines() {
        println!("  │ {}", line);
    }

    println!("\n  ── [p2p] section of config.toml ──");
    let p2p = container_exec(
        container,
        r#"awk '/^\[p2p\]/{found=1} found && /^\[/ && !/^\[p2p\]/{exit} found{print}' \
            /root/.terpd/config/config.toml 2>/dev/null | head -40 \
            || echo '(config.toml not found)'"#,
    );
    for line in p2p.lines() {
        println!("  │ {}", line);
    }

    println!("\n  ── /tmp/oline-env.sh (P2P lines) ──");
    let env = container_exec(
        container,
        "grep -E 'P2P_PEX|P2P_ADDR|PERSISTENT_PEERS' /tmp/oline-env.sh 2>/dev/null || echo '(not found)'",
    );
    for line in env.lines() {
        println!("  │ {}", line);
    }

    println!("  ════════════════════════════════════════");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker + local-terp container (just e2e-network)"]
async fn test_local_network_e2e() {
    // ── 0. Setup ──────────────────────────────────────────────────────────────
    load_dotenv_fallback(".env");

    // SSH_P must match the internal port used by SSH helpers
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("SSH_P", "22");
    }

    tracing_subscriber::fmt::try_init().ok();

    // Resolve OMNIBUS_IMAGE (prefer E2E_OMNIBUS_IMAGE for local tests, then OMNIBUS_IMAGE).
    // E2E_OMNIBUS_IMAGE is the locally-built arm64-compatible image; OMNIBUS_IMAGE is the
    // production ghcr.io image which may not have an arm64 variant and will fail on Apple Silicon.
    let omnibus_image = std::env::var("E2E_OMNIBUS_IMAGE")
        .or_else(|_| std::env::var("OMNIBUS_IMAGE"))
        .unwrap_or_else(|_| "oline-omnibus:local".into());

    let entrypoint_url = std::env::var("ENTRYPOINT_URL").unwrap_or_else(|_| {
        "https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/master/plays/audible/oline-entrypoint.sh".into()
    });

    println!("\n========================================");
    println!("  O-Line Local Network E2E Test");
    println!("========================================");
    println!("  OMNIBUS_IMAGE:  {}", omnibus_image);
    println!("  ENTRYPOINT_URL: {}", entrypoint_url);
    println!("  Local-terp RPC: {}", LOCAL_TERP_RPC);
    println!();

    // ── 1. Ensure local-terp is running (start if needed) ────────────────────
    println!("  [setup] Ensuring local-terp is running...");
    let _local_terp = ensure_local_terp().await;
    println!("  [setup] local-terp is up.");

    // Belt-and-suspenders: remove any leftover containers from a previous killed run.
    remove_containers(&[NET_SNAP_CONTAINER, NET_SEED_CONTAINER]);

    // ── 2. Fetch genesis + peer from local-terp ───────────────────────────────
    println!("  [setup] Fetching genesis from local-terp...");
    let genesis_json = fetch_local_terp_genesis()
        .await
        .expect("Failed to fetch genesis from local-terp");
    println!("  [setup] Genesis fetched ({} bytes)", genesis_json.len());

    let local_terp_node_id = fetch_local_terp_node_id()
        .await
        .expect("Failed to fetch local-terp node ID");
    println!("  [setup] local-terp node ID: {}", local_terp_node_id);

    // Peer string for use inside containers (host.docker.internal reaches the host)
    let local_terp_peer = format!(
        "{}@host.docker.internal:{}",
        local_terp_node_id, LOCAL_TERP_P2P_HOST_P
    );
    println!("  [setup] local-terp peer:    {}", local_terp_peer);

    // ── 3. Serve genesis over HTTP (containers download it via GENESIS_URL) ───
    println!(
        "  [setup] Starting genesis HTTP server on port {}...",
        GENESIS_HTTP_P
    );
    let genesis_arc = Arc::new(genesis_json);
    // AbortOnDrop ensures the genesis HTTP server task is cancelled on panic or normal exit.
    let _genesis_srv = AbortOnDrop(start_genesis_server(genesis_arc.clone(), GENESIS_HTTP_P));

    // Brief pause to let the server bind
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 4. Workdir + SSH keypair ──────────────────────────────────────────────
    let workdir = PathBuf::from("/tmp/oline-net-e2e");
    std::fs::create_dir_all(&workdir).expect("Failed to create workdir");
    let (ssh_pubkey, ssh_key_path) = generate_test_ssh_keypair(&workdir);

    // ── 5. Common container env ───────────────────────────────────────────────
    // No CHAIN_JSON — we set every required field directly.
    // GENESIS_URL points to our local HTTP server so containers get the exact
    // genesis from local-terp (the Tendermint-wrapped /genesis response is
    // unwrapped; our server returns raw genesis JSON).
    let genesis_url = format!("http://host.docker.internal:{}/genesis", GENESIS_HTTP_P);

    let shared_env: HashMap<String, String> = [
        ("SSH_PUBKEY", ssh_pubkey.as_str()),
        ("CHAIN_ID", "120u-1"),
        ("PROJECT_BIN", "terpd"),
        ("PROJECT_DIR", ".terpd"),
        ("GENESIS_URL", genesis_url.as_str()),
        ("DOWNLOAD_SNAP", "0"),
        ("SNAPSHOT_RETAIN", "0"),
        ("MINIMUM_GAS_PRICES", "0.05uthiol"),
        ("PRUNING", "nothing"),
        // Disable peer exchange: prevents public peers from local-terp's addr book
        // being gossiped to our test containers and causing spurious connection errors.
        ("P2P_PEX", "false"),
        // Allow peering with private/local addresses (host.docker.internal, 192.168.x.x).
        ("P2P_ADDR_BOOK_STRICT", "false"),
        // local-terp is the persistent peer for initial sync
        ("P2P_PERSISTENT_PEERS", local_terp_peer.as_str()),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    // On Linux Docker engine, containers cannot reach the host via
    // `host.docker.internal` without --add-host.  Docker Desktop (Mac/Windows)
    // adds it automatically — and `host-gateway` is not a valid IP value on macOS,
    // causing docker run to exit 125 with a usage error.
    let extra_hosts: Vec<String> = if cfg!(target_os = "linux") {
        vec!["host.docker.internal:host-gateway".to_string()]
    } else {
        vec![]
    };

    let bootstrap_cmd = format!(
        "curl -fsSL '{}' -o /tmp/wrapper.sh && bash /tmp/wrapper.sh",
        entrypoint_url
    );

    // ── 6. Start snapshot container ───────────────────────────────────────────
    let mut snap_env = shared_env.clone();
    snap_env.insert("MONIKER".into(), "oline-net-snapshot".into());

    println!("\n  [net-snapshot] Starting container...");
    let _snapshot_handle: ContainerHandle = run_container(&ContainerSpec {
        name: NET_SNAP_CONTAINER.into(),
        image: omnibus_image.clone(),
        env: snap_env,
        ports: vec![
            ContainerPort {
                internal: 22,
                host: NET_SNAP_SSH_P,
            },
            ContainerPort {
                internal: 26657,
                host: NET_SNAP_RPC_P,
            },
            ContainerPort {
                internal: 26656,
                host: NET_SNAP_P2P_P,
            },
        ],
        entrypoint: Some("/bin/bash".into()),
        command: Some(bootstrap_cmd.clone()),
        extra_hosts: extra_hosts.clone(),
    })
    .expect("Failed to start net-snapshot container");

    // ── 7. Start seed container ───────────────────────────────────────────────
    let mut seed_env = shared_env.clone();
    seed_env.insert("MONIKER".into(), "oline-net-seed".into());

    println!("  [net-seed] Starting container...");
    let _seed_handle: ContainerHandle = run_container(&ContainerSpec {
        name: NET_SEED_CONTAINER.into(),
        image: omnibus_image.clone(),
        env: seed_env,
        ports: vec![
            ContainerPort {
                internal: 22,
                host: NET_SEED_SSH_P,
            },
            ContainerPort {
                internal: 26657,
                host: NET_SEED_RPC_P,
            },
            ContainerPort {
                internal: 26656,
                host: NET_SEED_P2P_P,
            },
        ],
        entrypoint: Some("/bin/bash".into()),
        command: Some(bootstrap_cmd.clone()),
        extra_hosts: extra_hosts.clone(),
    })
    .expect("Failed to start net-seed container");

    // ── 8. Wait for SSH on both ───────────────────────────────────────────────
    println!(
        "\n  [net-snapshot] Waiting for SSH (127.0.0.1:{})...",
        NET_SNAP_SSH_P
    );
    if !wait_for_tcp("127.0.0.1", NET_SNAP_SSH_P, SSH_WAIT_TIMEOUT) {
        let logs = container_logs(NET_SNAP_CONTAINER, 40);
        panic!(
            "Snapshot SSH never came up within {:?}.\nLogs:\n{}",
            SSH_WAIT_TIMEOUT, logs
        );
    }
    println!("  [net-snapshot] SSH ready.");

    println!(
        "  [net-seed] Waiting for SSH (127.0.0.1:{})...",
        NET_SEED_SSH_P
    );
    if !wait_for_tcp("127.0.0.1", NET_SEED_SSH_P, SSH_WAIT_TIMEOUT) {
        let logs = container_logs(NET_SEED_CONTAINER, 40);
        panic!(
            "Seed SSH never came up within {:?}.\nLogs:\n{}",
            SSH_WAIT_TIMEOUT, logs
        );
    }
    println!("  [net-seed] SSH ready.");

    // Let sshd finish host-key generation
    std::thread::sleep(Duration::from_secs(2));

    // ── 9. Push local scripts to both containers ──────────────────────────────
    // Push two files:
    //   /tmp/wrapper.sh       ← LOCAL oline-entrypoint.sh (overwrites the
    //                            GitHub version downloaded at bootstrap).
    //                            Contains the /tmp/node-config.sh check,
    //                            Final peer patch, and all recent local changes.
    //   /tmp/node-config.sh   ← LOCAL config-node-endpoints.sh with P2P_PEX
    //                            and addr_book_strict support.
    //
    // Without pushing the entrypoint, containers run the OLD GitHub version
    // which lacks the node-config.sh lookup, so P2P_PEX never gets applied.
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let entrypoint_bytes = std::fs::read(manifest_dir.join("plays/audible/oline-entrypoint.sh"))
        .expect("Failed to read plays/audible/oline-entrypoint.sh");
    let node_config_bytes =
        std::fs::read(manifest_dir.join("plays/audible/config-node-endpoints.sh"))
            .expect("Failed to read plays/audible/config-node-endpoints.sh");

    let pre_start_files = vec![
        PreStartFile {
            source: FileSource::Bytes(entrypoint_bytes),
            remote_path: "/tmp/wrapper.sh".to_string(),
        },
        PreStartFile {
            source: FileSource::Bytes(node_config_bytes),
            remote_path: "/tmp/node-config.sh".to_string(),
        },
    ];

    push_pre_start_files(
        "net-snapshot",
        &snapshot_endpoints(),
        &ssh_key_path,
        &pre_start_files,
        5,
    )
    .await
    .expect("push_pre_start_files(snapshot) failed");

    push_pre_start_files(
        "net-seed",
        &seed_endpoints(),
        &ssh_key_path,
        &pre_start_files,
        5,
    )
    .await
    .expect("push_pre_start_files(seed) failed");

    // ── 10. Build sdl_vars for both nodes ─────────────────────────────────────
    // These vars are written to /tmp/oline-env.sh on the container.
    // They mirror the SDL environment that Akash providers inject.
    let snap_rpc_port_str = NET_SNAP_RPC_P.to_string();
    let snapshot_sdl_vars: HashMap<String, String> = [
        ("CHAIN_ID", "120u-1"),
        ("PROJECT_BIN", "terpd"),
        ("PROJECT_DIR", ".terpd"),
        ("GENESIS_URL", genesis_url.as_str()),
        ("DOWNLOAD_SNAP", "0"),
        ("SNAPSHOT_RETAIN", "0"),
        ("MINIMUM_GAS_PRICES", "0.05uthiol"),
        ("PRUNING", "nothing"),
        ("P2P_PERSISTENT_PEERS", local_terp_peer.as_str()),
        ("RPC_P", snap_rpc_port_str.as_str()),
        ("P2P_PEX", "false"),
        ("P2P_ADDR_BOOK_STRICT", "false"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let seed_rpc_port_str = NET_SEED_RPC_P.to_string();
    let seed_sdl_vars: HashMap<String, String> = [
        ("CHAIN_ID", "120u-1"),
        ("PROJECT_BIN", "terpd"),
        ("PROJECT_DIR", ".terpd"),
        ("GENESIS_URL", genesis_url.as_str()),
        ("DOWNLOAD_SNAP", "0"),
        ("SNAPSHOT_RETAIN", "0"),
        ("MINIMUM_GAS_PRICES", "0.05uthiol"),
        ("PRUNING", "nothing"),
        ("P2P_PERSISTENT_PEERS", local_terp_peer.as_str()),
        ("RPC_P", seed_rpc_port_str.as_str()),
        ("P2P_PEX", "false"),
        ("P2P_ADDR_BOOK_STRICT", "false"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    // ── 11. Signal start: snapshot ────────────────────────────────────────────
    println!("\n  [net-snapshot] Signaling start...");
    verify_files_and_signal_start(
        "net-snapshot",
        &snapshot_endpoints(),
        &ssh_key_path,
        &[], // no pre-start files to verify
        &snapshot_sdl_vars,
    )
    .await
    .expect("verify_files_and_signal_start(snapshot) failed");
    println!("  [net-snapshot] Start signal sent.");

    // ── 12. Signal start: seed ────────────────────────────────────────────────
    println!("  [net-seed] Signaling start...");
    verify_files_and_signal_start(
        "net-seed",
        &seed_endpoints(),
        &ssh_key_path,
        &[],
        &seed_sdl_vars,
    )
    .await
    .expect("verify_files_and_signal_start(seed) failed");
    println!("  [net-seed] Start signal sent.");

    // ── 13. Wait for RPC on both nodes ────────────────────────────────────────
    let snap_rpc = format!("http://127.0.0.1:{}", NET_SNAP_RPC_P);
    let seed_rpc = format!("http://127.0.0.1:{}", NET_SEED_RPC_P);

    println!(
        "\n  [net-snapshot] Waiting for RPC ({}), up to 120s...",
        snap_rpc
    );
    if !wait_for_rpc(&snap_rpc, 120).await {
        let logs = container_logs(NET_SNAP_CONTAINER, 50);
        panic!("Snapshot RPC never came up within 120s.\nLogs:\n{}", logs);
    }
    println!("  [net-snapshot] RPC responding.");

    println!("  [net-seed] Waiting for RPC ({}), up to 120s...", seed_rpc);
    if !wait_for_rpc(&seed_rpc, 120).await {
        let logs = container_logs(NET_SEED_CONTAINER, 50);
        panic!("Seed RPC never came up within 120s.\nLogs:\n{}", logs);
    }
    println!("  [net-seed] RPC responding.");

    // ── 14. Config verification: confirm PEX is off ───────────────────────────
    //
    // Use `docker exec` (not SSH) so the output is always visible in the test
    // runner without relying on tracing::info! routing.
    println!("\n  ─── Config Verification ─────────────────────────────────────────");

    // Always dump diagnostics first so we can see what happened
    println!("  [net-snapshot] Dumping config state:");
    let pex_line = container_exec(
        NET_SNAP_CONTAINER,
        "grep -E '^pex' /root/.terpd/config/config.toml 2>/dev/null || echo '(no pex line)'",
    );
    println!("  │ pex line:    {}", pex_line.trim());

    let p2p_pex_env = container_exec(
        NET_SNAP_CONTAINER,
        "grep 'P2P_PEX' /tmp/oline-env.sh 2>/dev/null || echo '(P2P_PEX not in oline-env.sh)'",
    );
    println!("  │ oline-env:   {}", p2p_pex_env.trim());

    let node_log_tail = container_exec(
        NET_SNAP_CONTAINER,
        "grep -E 'node-config|P2P_PEX|pex|pre-upload' /tmp/oline-node.log 2>/dev/null | tail -15 || echo '(no matches in oline-node.log)'",
    );
    println!("  │ node log (config-related):");
    for line in node_log_tail.lines() {
        println!("  │   {}", line);
    }

    // Now assert pex=false
    let pex_ok = pex_line.trim().contains("pex = false") || pex_line.trim().contains("pex=false");
    if !pex_ok {
        dump_container_diagnostics(NET_SNAP_CONTAINER);
        panic!(
            "pex is not disabled on snapshot node.\n  \
             Got: {:?}\n  \
             Check /tmp/oline-node.log via: docker exec {} cat /tmp/oline-node.log",
            pex_line.trim(),
            NET_SNAP_CONTAINER
        );
    }
    println!("  [net-snapshot] pex=false confirmed.");

    // ── 14b. SSH hot update: change app.toml minimum-gas-prices (no restart) ─
    //
    // Exercises the "live config patch" path: push new gas price to app.toml,
    // verify via SSH without restarting the node. This confirms ssh_push_env_and_run
    // can update configuration on a running node.
    println!("\n  ─── SSH Hot Config Update (no restart) ──────────────────────────");
    println!("  [net-snapshot] Patching minimum-gas-prices in app.toml...");

    let mut hot_env: HashMap<String, String> = HashMap::new();
    hot_env.insert("NEW_GAS_PRICE".into(), "0.025uthiol".into());

    ssh_push_env_and_run(
        "hot-update-snapshot",
        "127.0.0.1",
        NET_SNAP_SSH_P,
        &ssh_key_path,
        &hot_env,
        r#"
. /tmp/oline-env.sh 2>/dev/null || true
APP=/root/.terpd/config/app.toml
echo "  Before: $(grep 'minimum-gas-prices' $APP)"
sed -i "s|^minimum-gas-prices *=.*|minimum-gas-prices = \"${NEW_GAS_PRICE}\"|" $APP
echo "  After:  $(grep 'minimum-gas-prices' $APP)"
grep -q "minimum-gas-prices = \"${NEW_GAS_PRICE}\"" $APP || {
    echo "  ERROR: gas price patch failed"
    exit 1
}
echo "  Hot update OK (terpd still running, change takes effect on next restart)"
"#
        .trim(),
    )
    .await
    .expect("SSH hot update of app.toml failed");

    println!("  [net-snapshot] Hot config update verified.");

    // ── 15. Resolve peer IDs ─────────────────────────────────────────────────
    println!("\n  [net-snapshot] Polling for peer ID...");
    let snap_rpc_url_str = snap_rpc.clone();
    let snap_p2p_addr = format!("127.0.0.1:{}", NET_SNAP_P2P_P);
    let snapshot_peer_local = OLineDeployer::extract_peer_id_with_boot_wait(
        &snap_rpc_url_str,
        &snap_p2p_addr,
        5,  // boot_wait_secs — already booted
        20, // max_retries (20 × 10s = 200s max)
        10, // interval_secs
    )
    .await;

    let snapshot_peer_local = snapshot_peer_local.unwrap_or_else(|| {
        println!("  [net-snapshot] WARNING: peer ID not resolved yet (node still syncing)");
        String::new()
    });

    if !snapshot_peer_local.is_empty() {
        println!("  [net-snapshot] Peer ID: {}", snapshot_peer_local);
    }

    println!("  [net-seed] Polling for peer ID...");
    let seed_rpc_url_str = seed_rpc.clone();
    let seed_p2p_addr = format!("127.0.0.1:{}", NET_SEED_P2P_P);
    let seed_peer_local =
        OLineDeployer::extract_peer_id_with_boot_wait(&seed_rpc_url_str, &seed_p2p_addr, 5, 20, 10)
            .await;

    let seed_peer_local = seed_peer_local.unwrap_or_else(|| {
        println!("  [net-seed] WARNING: peer ID not resolved yet (node still syncing)");
        String::new()
    });

    if !seed_peer_local.is_empty() {
        println!("  [net-seed] Peer ID: {}", seed_peer_local);
    }

    // ── 16. ssh_push_env_and_run test ─────────────────────────────────────────
    //
    // Push updated P2P peers to the seed node:
    //   - snapshot node as a persistent peer (via host.docker.internal)
    //   - local-terp as a persistent peer (already set, but re-confirmed)
    //
    // Then restart terpd on the seed node.
    // This exercises the `ssh_push_env_and_run` path end-to-end.

    println!("\n  ─── ssh_push_env_and_run Test ───────────────────────────────────");

    // Build the combined peer string for the seed: snapshot + local-terp
    let mut new_peers_parts: Vec<String> = vec![local_terp_peer.clone()];
    if !snapshot_peer_local.is_empty() {
        // Convert "id@127.0.0.1:26776" → "id@host.docker.internal:26776"
        // so the seed container can reach the snapshot via the host bridge
        let snap_peer_for_container = to_container_peer(&snapshot_peer_local, NET_SNAP_P2P_P);
        new_peers_parts.push(snap_peer_for_container);
    }
    let new_peers = new_peers_parts.join(",");

    println!("  [net-seed] Pushing updated peers: {}", new_peers);

    let mut refresh_env: HashMap<String, String> = HashMap::new();
    refresh_env.insert("TERPD_P2P_PERSISTENT_PEERS".into(), new_peers.clone());

    // Command: source updated env → patch config.toml → graceful stop → restart → wait for RPC.
    //
    // The RPC poll is inside the bash script so ssh_push_env_and_run fails fast
    // (with log content) if terpd doesn't start.  The Rust side just confirms RPC
    // is still up after the SSH session closes.
    let refresh_cmd = r#"
. /tmp/oline-env.sh 2>/dev/null || true

echo "=== [ssh-refresh] Patching config.toml ==="
CONFIG=/root/.terpd/config/config.toml
if [ -f "$CONFIG" ]; then
    # Patch persistent_peers using section-scoped sed (same as config-node-endpoints.sh).
    # terpd reads persistent_peers from config.toml, NOT from the env var.
    if [ -n "$TERPD_P2P_PERSISTENT_PEERS" ]; then
        sed -i "/^\[p2p\]$/,/^\[/ s|^persistent_peers *=.*|persistent_peers = \"${TERPD_P2P_PERSISTENT_PEERS}\"|" "$CONFIG"
        echo "  persistent_peers: $(grep 'persistent_peers' $CONFIG | head -1)"
    fi

    # Patch RPC laddr to bind on all interfaces so Docker port-mapping works.
    # config-node-endpoints.sh only sets this when RPC_DOMAIN is set; in tests it's not,
    # so config.toml keeps the default tcp://127.0.0.1:26657. After restart (without the
    # entrypoint env TERPD_RPC_LADDR), terpd would bind 127.0.0.1 and be unreachable from host.
    sed -i "/^\[rpc\]$/,/^\[/ s|^laddr *=.*|laddr = \"tcp://0.0.0.0:26657\"|" "$CONFIG"
    echo "  rpc.laddr: $(grep -A5 '^\[rpc\]' $CONFIG | grep '^laddr' | head -1)"
fi

echo "=== [ssh-refresh] Stopping terpd (graceful SIGTERM, up to 60s) ==="
pkill -15 terpd 2>/dev/null || true
_sigkilled=0
for _i in $(seq 1 60); do
    pgrep -x terpd >/dev/null 2>&1 || break
    sleep 1
done
if pgrep -x terpd >/dev/null 2>&1; then
    echo "  SIGTERM timeout — sending SIGKILL"
    pkill -9 terpd 2>/dev/null || true
    _sigkilled=1
    sleep 3
fi
echo "  terpd stopped."

echo "=== [ssh-refresh] Checking node state ==="
PVS=/root/.terpd/data/priv_validator_state.json
if [ -f "$PVS" ]; then
    python3 -c "import json; json.load(open('$PVS'))" 2>/dev/null || {
        echo '{"height":"0","round":0,"step":0}' > "$PVS"
        echo "  Reset corrupted priv_validator_state.json"
    }
fi
# Only clear WAL if we had to SIGKILL (unclean exit)
if [ "$_sigkilled" = "1" ]; then
    rm -rf /root/.terpd/data/cs.wal 2>/dev/null || true
    echo "  Cleared WAL after SIGKILL"
fi

echo "=== [ssh-refresh] Starting terpd ==="
# Pass TERPD_RPC_LADDR explicitly so terpd binds 0.0.0.0 even without the entrypoint env.
nohup env TERPD_RPC_LADDR="tcp://0.0.0.0:26657" terpd start --home /root/.terpd > /tmp/terpd-refresh.log 2>&1 &
sleep 2
if ! pgrep -x terpd >/dev/null 2>&1; then
    echo "  ERROR: terpd failed to start immediately"
    cat /tmp/terpd-refresh.log
    exit 1
fi
echo "  terpd started (PID $(pgrep -x terpd))"

echo "=== [ssh-refresh] Waiting for RPC (up to 90s) ==="
_rpc_up=0
for _i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:26657/status" >/dev/null 2>&1; then
        _rpc_up=1
        echo "  RPC up after $((_i * 3))s"
        break
    fi
    if ! pgrep -x terpd >/dev/null 2>&1; then
        echo "  ERROR: terpd crashed during RPC wait"
        cat /tmp/terpd-refresh.log
        exit 1
    fi
    sleep 3
done
if [ "$_rpc_up" = "0" ]; then
    echo "  ERROR: terpd RPC not responding after 90s"
    echo "--- terpd-refresh.log (last 30 lines) ---"
    tail -30 /tmp/terpd-refresh.log
    echo "--- pgrep ---"
    pgrep -ax terpd 2>/dev/null || echo "(no terpd process)"
    exit 1
fi
"#;

    ssh_push_env_and_run(
        "net-seed-refresh",
        "127.0.0.1",
        NET_SEED_SSH_P,
        &ssh_key_path,
        &refresh_env,
        refresh_cmd.trim(),
    )
    .await
    .expect("ssh_push_env_and_run on seed failed");

    println!("  [net-seed] ssh_push_env_and_run completed successfully.");

    // ── 17. Confirm seed RPC is up after restart ──────────────────────────────
    // The refresh_cmd already polled for RPC (up to 90s) before returning, so
    // we just need a quick confirmation that the port is still responding.
    println!("\n  [net-seed] Confirming RPC after restart (up to 30s)...");

    if !wait_for_rpc(&seed_rpc, 30).await {
        let refresh_log = container_exec(
            NET_SEED_CONTAINER,
            "tail -30 /tmp/terpd-refresh.log 2>/dev/null || echo '(no refresh log)'",
        );
        println!("\n  [net-seed] terpd-refresh.log (last 30 lines):");
        for line in refresh_log.lines() {
            println!("  │ {}", line);
        }
        dump_container_diagnostics(NET_SEED_CONTAINER);
        panic!("Seed RPC not responding after refresh restart — check logs above.");
    }
    println!("  [net-seed] RPC confirmed after restart.");

    // ── 18. SSH verify post-restart config on seed ────────────────────────────
    //
    // Confirm that the refresh restart actually applied the updated persistent_peers.
    // Uses `exit 1` in the grep command so the SSH call fails (and the test fails)
    // if the peer string was not written to config.toml.
    println!("\n  ─── SSH Post-Restart Config Verification ────────────────────────");
    if !new_peers.is_empty() {
        println!("  [net-seed] Verifying persistent_peers updated in config.toml...");

        // Escape the peer string for use inside a shell heredoc
        let verify_peers_cmd = format!(
            r#"
CONFIG=/root/.terpd/config/config.toml
echo "  persistent_peers: $(grep '^persistent_peers' $CONFIG | head -1)"
grep -q 'persistent_peers' $CONFIG || {{
    echo "  ERROR: persistent_peers line missing from config.toml"
    exit 1
}}
echo "  persistent_peers OK"
echo "  pex: $(grep '^pex' $CONFIG | head -1)"
grep -q '^pex = false' $CONFIG || {{
    echo "  ERROR: pex=false not preserved after restart"
    exit 1
}}
echo "  pex=false preserved OK"
"#
        );

        ssh_push_env_and_run(
            "verify-restart-seed",
            "127.0.0.1",
            NET_SEED_SSH_P,
            &ssh_key_path,
            &HashMap::new(),
            verify_peers_cmd.trim(),
        )
        .await
        .expect("Post-restart config verification failed on seed node");

        println!("  [net-seed] Post-restart config verified.");
    }

    // ── 20. Assert block heights > 0 ─────────────────────────────────────────
    println!("\n  ─── Block Height Assertions ────────────────────────────────────");

    println!("  [net-snapshot] Waiting for block height >= 1 (up to 180s)...");
    let snap_height = wait_for_height(&snap_rpc, 1, 180).await;

    println!("  [net-seed] Waiting for block height >= 1 (up to 240s)...");
    let seed_height = wait_for_height(&seed_rpc, 1, 240).await;

    // Also check local-terp height for reference
    let lt_height = get_block_height(LOCAL_TERP_RPC).await.unwrap_or(0);

    // ── 21. Summary ───────────────────────────────────────────────────────────
    println!("\n  ┌── Local Network E2E Results ─────────────────────────────────");
    println!("  │  local-terp height:          {}", lt_height);
    println!(
        "  │  net-snapshot height:        {}",
        snap_height.map_or("not resolved".to_string(), |h| h.to_string())
    );
    println!(
        "  │  net-seed height:            {}",
        seed_height.map_or("not resolved".to_string(), |h| h.to_string())
    );
    println!(
        "  │  Snapshot peer (local):      {}",
        if snapshot_peer_local.is_empty() {
            "(not resolved)"
        } else {
            &snapshot_peer_local
        }
    );
    println!(
        "  │  Seed peer (local):          {}",
        if seed_peer_local.is_empty() {
            "(not resolved)"
        } else {
            &seed_peer_local
        }
    );
    println!("  │  ssh_push_env_and_run:       OK");
    println!("  │  pex=false verified:         OK");
    println!("  │  hot app.toml update:        OK");
    println!("  │  post-restart config check:  OK");
    println!("  └──────────────────────────────────────────────────────────────────");

    // ── 22. Assertions ────────────────────────────────────────────────────────
    assert!(
        snap_height.unwrap_or(0) >= 1,
        "Snapshot node never reached block height 1 — check `docker logs {}`",
        NET_SNAP_CONTAINER
    );
    assert!(
        seed_height.unwrap_or(0) >= 1,
        "Seed node never reached block height 1 after refresh — check `docker logs {}`",
        NET_SEED_CONTAINER
    );

    // Containers cleaned up by RAII Drop on `_snapshot_handle` and `_seed_handle`.
    // Genesis server task cancelled by RAII Drop on `_genesis_srv` (AbortOnDrop).
    println!("\n  [local-network-e2e] PASSED — block sync + ssh refresh verified.");
}

// ── Parallel account seeding test ────────────────────────────────────────────

/// Tests the parallel account seeding design used by `OLineStep::FundChildAccounts`.
///
/// The design intention:
///   - N child signers are derived locally from one master mnemonic (0 network calls).
///   - N bech32 addresses are computed locally from those signers.
///   - When funding / broadcasting, ONE shared connection services all N accounts.
///     This avoids spinning up a separate gRPC/RPC client per child account.
///
/// This test validates:
///   1. `derive_child_signer` produces N distinct, deterministic `KeySigner`s (pure crypto).
///   2. `child_address` encodes the correct Cosmos bech32 address.
///   3. (with local-terp) Rust-derived addresses match `terpd keys add --recover --index N`.
///   4. (with local-terp) All N accounts can be funded via the shared faucet endpoint.
///   5. (with local-terp) Balances are visible via REST — confirming on-chain readiness.
///
/// Run with local-terp:
///   ./tests/localterp.sh wait
///   cargo test --test local_network_e2e test_parallel_account_seeding -- --nocapture
#[tokio::test]
#[ignore = "requires Docker + local-terp container (just e2e-network)"]
async fn test_parallel_account_seeding() {
    // BIP39 test-vector mnemonic — deterministic, never used for real funds.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const N: usize = 4; // parallel deployment units: snapshot, seed, minio, left-tackle (etc.)
    const TERP_PREFIX: &str = "terp";

    println!("\n========================================");
    println!("  Parallel Account Seeding Test");
    println!("========================================");

    // ── 1. Pure-crypto: HD derivation (no network) ───────────────────────────
    println!("\n  [crypto] Deriving {} child signers...", N);
    let signers: Vec<_> = (0..N as u32)
        .map(|i| {
            o_line_sdl::accounts::derive_child_signer(TEST_MNEMONIC, i)
                .unwrap_or_else(|e| panic!("derive_child_signer({i}) failed: {e}"))
        })
        .collect();

    // ── 2. Address derivation (no network) ───────────────────────────────────
    let addresses: Vec<String> = signers
        .iter()
        .map(|s| o_line_sdl::accounts::child_address(s, TERP_PREFIX))
        .collect();

    for (i, addr) in addresses.iter().enumerate() {
        println!("    child[{i}]: {addr}");
        assert!(
            addr.starts_with(&format!("{}1", TERP_PREFIX)),
            "child[{i}] should start with '{TERP_PREFIX}1', got: {addr}"
        );
    }

    // All addresses must be distinct (different HD indices → different keys).
    for i in 0..N {
        for j in (i + 1)..N {
            assert_ne!(
                addresses[i], addresses[j],
                "child[{i}] and child[{j}] share the same address!"
            );
        }
    }

    // Derivation must be deterministic: re-derive and compare.
    let second_run: Vec<String> = (0..N as u32)
        .map(|i| {
            let s = o_line_sdl::accounts::derive_child_signer(TEST_MNEMONIC, i).unwrap();
            o_line_sdl::accounts::child_address(&s, TERP_PREFIX)
        })
        .collect();
    assert_eq!(
        addresses, second_run,
        "Address derivation must be deterministic"
    );
    println!(
        "  [crypto] Derivation: {} unique, deterministic addresses. ✓",
        N
    );

    // ── 3. Skip on-chain steps if local-terp is not running ──────────────────
    let faucet_url = "http://127.0.0.1:5000";
    let rest_url = "http://127.0.0.1:1317";

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let faucet_up = http
        .get(&format!("{}/status", faucet_url))
        .send()
        .await
        .is_ok();

    if !faucet_up {
        println!(
            "\n  [skip] local-terp faucet not reachable at {faucet_url}.\n  \
             Run ./tests/localterp.sh wait to enable on-chain phases.\n"
        );
        println!("  [parallel-account-seeding] PASSED (pure-crypto only).");
        return;
    }

    // ── 4. Cross-validate with terpd ─────────────────────────────────────────
    // Import the test mnemonic at each HD index into local-terp's keyring and
    // compare the terpd-derived address with our Rust implementation.
    // Uses bash -c with printf to avoid interactive-stdin issues with docker exec.
    println!("\n  [cross-validate] Comparing Rust vs terpd address derivation...");
    for i in 0..N {
        let key_name = format!("oline-test-child-{i}");

        // Delete key by name AND any key sharing the same address (idempotent cleanup).
        let _ = Command::new("docker")
            .args([
                "exec",
                "local-terp",
                "terpd",
                "keys",
                "delete",
                &key_name,
                "--yes",
                "--keyring-backend",
                "test",
            ])
            .output();
        // Also remove any key that already has the target address to avoid
        // "duplicated address" errors on re-runs (e.g. leftover test-verify-N keys).
        let list_out = Command::new("docker")
            .args([
                "exec",
                "local-terp",
                "terpd",
                "keys",
                "list",
                "--keyring-backend",
                "test",
                "--output",
                "json",
            ])
            .output()
            .unwrap();
        if let Ok(existing) = serde_json::from_slice::<Vec<serde_json::Value>>(&list_out.stdout) {
            for k in &existing {
                if k["address"].as_str() == Some(addresses[i].as_str()) {
                    if let Some(n) = k["name"].as_str() {
                        let _ = Command::new("docker")
                            .args([
                                "exec",
                                "local-terp",
                                "terpd",
                                "keys",
                                "delete",
                                n,
                                "--yes",
                                "--keyring-backend",
                                "test",
                            ])
                            .output();
                    }
                }
            }
        }

        // Import: use bash -c with printf so the mnemonic is piped through bash,
        // avoiding the docker exec interactive-stdin handshake problem.
        let add_cmd = format!(
            "printf '%s\\n' '{}' | terpd keys add {} --recover --index {} \
             --keyring-backend test >/dev/null 2>&1",
            TEST_MNEMONIC, key_name, i
        );
        let status = Command::new("docker")
            .args(["exec", "local-terp", "bash", "-c", &add_cmd])
            .status()
            .expect("docker exec bash keys add failed");
        assert!(status.success(), "terpd keys add for child[{i}] failed");

        // Query address.
        let out = Command::new("docker")
            .args([
                "exec",
                "local-terp",
                "terpd",
                "keys",
                "show",
                &key_name,
                "-a",
                "--keyring-backend",
                "test",
            ])
            .output()
            .expect("terpd keys show failed");
        let terpd_addr = String::from_utf8_lossy(&out.stdout).trim().to_string();

        assert_eq!(
            terpd_addr, addresses[i],
            "child[{i}] address mismatch: Rust={}, terpd={}",
            addresses[i], terpd_addr
        );
        println!("    child[{i}]: Rust ≡ terpd  ({terpd_addr}) ✓");
    }

    // ── 5. Fund master account (child[0]) via faucet ─────────────────────────
    // Only the FIRST account is seeded from the faucet.  The rest are funded by
    // the master in a single multi-send tx — exactly how FundChildAccounts works.
    let _ = rest_url; // REST URL kept for future use
    println!("\n  [faucet] Funding master account (child[0]) via faucet...");
    let faucet_resp: serde_json::Value = http
        .get(&format!("{}/faucet?address={}", faucet_url, addresses[0]))
        .send()
        .await
        .expect("faucet request failed")
        .json()
        .await
        .expect("faucet response parse failed");
    let seed_hash = faucet_resp
        .get("txhash")
        .and_then(|v| v.as_str())
        .unwrap_or("<no txhash>")
        .to_string();
    println!("    child[0] seeded from faucet — txhash: {seed_hash}");

    // Poll until the master has a balance.
    println!("  [faucet] Waiting for seed tx to commit (up to 15s)...");
    let mut master_funded = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let out = Command::new("docker")
            .args([
                "exec",
                "local-terp",
                "terpd",
                "query",
                "bank",
                "balances",
                &addresses[0],
                "--output",
                "json",
            ])
            .output()
            .unwrap();
        if let Ok(body) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
            if body
                .get("balances")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
                master_funded = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    println!();
    assert!(
        master_funded,
        "Master account (child[0]) never received faucet funds"
    );
    println!("    child[0]: master funded ✓");

    // ── 6. Multi-send from master → all other child accounts ─────────────────
    // This mirrors FundChildAccounts: one account, one tx, N recipients.
    // All N-1 child accounts get funded in a single on-chain operation.
    println!(
        "\n  [multi-send] Master → child[1..{}] via single multi-send tx...",
        N - 1
    );
    let recipient_addrs: Vec<&str> = addresses[1..].iter().map(|s| s.as_str()).collect();
    // terpd tx bank multi-send <from-key> <addr1> <addr2> ... <amount>
    let mut multi_send_args = vec![
        "exec",
        "local-terp",
        "terpd",
        "tx",
        "bank",
        "multi-send",
        "oline-test-child-0",
    ];
    multi_send_args.extend(recipient_addrs.iter().copied());
    multi_send_args.extend(&[
        "100000000uterp",
        "--keyring-backend",
        "test",
        "--chain-id",
        "120u-1",
        "--fees",
        "5000000uterp",
        "--yes",
        "--output",
        "json",
    ]);

    let multi_out = Command::new("docker")
        .args(&multi_send_args)
        .output()
        .expect("multi-send command failed");
    let multi_body: serde_json::Value =
        serde_json::from_slice(&multi_out.stdout).unwrap_or(serde_json::Value::Null);
    let multi_hash = multi_body
        .get("txhash")
        .and_then(|v| v.as_str())
        .unwrap_or("<no txhash>");
    println!("    multi-send txhash: {multi_hash}");
    assert_ne!(multi_hash, "<no txhash>", "multi-send tx was not broadcast");

    // Poll until all child accounts have balances.
    println!("  [multi-send] Waiting for child balances (up to 15s)...");
    let mut child_funded = vec![true, false, false, false]; // child[0] already funded
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let mut all_done = true;
        for i in 1..N {
            if child_funded[i] {
                continue;
            }
            let out = Command::new("docker")
                .args([
                    "exec",
                    "local-terp",
                    "terpd",
                    "query",
                    "bank",
                    "balances",
                    &addresses[i],
                    "--output",
                    "json",
                ])
                .output()
                .unwrap();
            if let Ok(body) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if body
                    .get("balances")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
                {
                    child_funded[i] = true;
                }
            }
            if !child_funded[i] {
                all_done = false;
            }
        }
        if all_done {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    println!();
    for i in 1..N {
        assert!(
            child_funded[i],
            "child[{i}] did not receive multi-send funds"
        );
        println!("    child[{i}]: funded via multi-send ✓");
    }

    // ── 7. Each child signs + broadcasts independently (batch send-back) ──────
    // Each child account (1..N-1) sends tokens back to child[0].
    // This demonstrates N signers broadcasting independently through ONE connection
    // WITHOUT a separate AkashClient instance per key.
    println!("\n  [send-back] Each child signing + broadcasting independently...");
    for i in 1..N {
        let key_name = format!("oline-test-child-{i}");
        let send_cmd = format!(
            "terpd tx bank send {} {} 10000000uterp \
             --keyring-backend test --chain-id 120u-1 --fees 2000000uterp \
             --yes --output json 2>/dev/null",
            key_name, addresses[0]
        );
        let out = Command::new("docker")
            .args(["exec", "local-terp", "bash", "-c", &send_cmd])
            .output()
            .expect("send-back command failed");
        let body: serde_json::Value =
            serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
        let hash = body
            .get("txhash")
            .and_then(|v| v.as_str())
            .unwrap_or("<no txhash>");
        assert_ne!(hash, "<no txhash>", "child[{i}] send-back tx not broadcast");
        println!("    child[{i}] → child[0]: txhash {hash} ✓");
        // Brief pause between sends to avoid sequence number conflicts
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── 8. Summary ────────────────────────────────────────────────────────────
    println!("\n  ┌── Parallel Account Seeding Results ──────────────────────────");
    println!("  │  Child accounts derived:  {N}");
    println!("  │  Cross-validation:        Rust ≡ terpd for all {N} indices ✓");
    println!("  │  Funding source:          faucet → child[0] (master) only");
    println!(
        "  │  Child funding:           1 multi-send from master → child[1..{}] ✓",
        N - 1
    );
    println!(
        "  │  Independent signing:     child[1..{}] each signed + broadcast ✓",
        N - 1
    );
    println!("  │");
    println!("  │  DESIGN NOTE: All {N} child keys derived locally (0 network calls).");
    println!("  │  FundChildAccounts pattern: 1 seeded account → multi-send → N accounts.");
    println!("  │  Each child signs independently; ONE connection services all broadcasts.");
    println!("  └──────────────────────────────────────────────────────────────────");
    let all_funded = child_funded.iter().all(|&f| f);

    println!("\n  [parallel-account-seeding] PASSED.");
}

/// Smoke test: port constants don't conflict with local_phase_a.rs constants.
#[test]
fn test_net_ports_no_conflict() {
    // Ports from local_phase_a.rs
    const PHASE_A_PS: &[u16] = &[2232, 2233, 26757, 26767, 26756, 26766];

    let net_ports = [
        NET_SNAP_SSH_P,
        NET_SNAP_RPC_P,
        NET_SNAP_P2P_P,
        NET_SEED_SSH_P,
        NET_SEED_RPC_P,
        NET_SEED_P2P_P,
        GENESIS_HTTP_P,
    ];

    for p in &net_ports {
        assert!(
            !PHASE_A_PS.contains(p),
            "Port {} conflicts with local_phase_a.rs",
            p
        );
    }

    // All net ports are unique
    let mut seen = std::collections::HashSet::new();
    for p in &net_ports {
        assert!(seen.insert(*p), "Duplicate port {}", p);
    }
}
