// E2E integration test for the TLS cert delivery → tls-setup.sh → cosmos node start workflow.
//
// Exercises the REAL push_tls_certs_sftp and verify_certs_and_signal_start functions
// against a real cosmos-omnibus Docker container with real scripts — no mocks.
//
// Storage: DOWNLOAD_SNAPSHOT=0 skips the multi-GB snapshot download.
// Expected disk usage: ~500MB (chain binary + genesis + node init).
// DOWNLOAD_GENESIS is intentionally NOT disabled — genesis is small (~few MB)
// and full node init is part of what we're verifying.
//
// Run with:
//   OMNIBUS_IMAGE=ghcr.io/akash-network/cosmos-omnibus:v0.5.0-terp-v2.0.0 \
//   CHAIN_JSON=https://raw.githubusercontent.com/.../chain.json \
//   cargo test -p o-line-sdl --test e2e_workflow -- --nocapture --test-threads=1

use akash_deploy_rs::ServiceEndpoint;
use o_line_sdl::crypto::{push_tls_certs_sftp, verify_certs_and_signal_start};

use std::{
    collections::HashMap,
    fs,
    net::TcpStream,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

/// SSH into the container and read a remote file, returning `(raw_content, parsed_var_map)`.
///
/// Parses both forms written by the oline bootstrap/refresh mechanism:
///   - `declare -x VAR="value"`  — from bootstrap's `export -p`
///   - `export VAR='value'`      — from orchestrator's `/tmp/oline-env.sh` patch
///
/// Only the LAST assignment wins if a var appears multiple times (mimics shell sourcing).
fn read_container_env_file(ssh_key_path: &str) -> (String, HashMap<String, String>) {
    let output = Command::new("ssh")
        .args([
            "-i",
            ssh_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-p",
            &SSH_PORT_HOST.to_string(),
            &format!("root@{}", SSH_HOST),
            "cat /tmp/oline-env.sh 2>/dev/null",
        ])
        .output()
        .expect("ssh failed during env file check");

    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
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
            // strip outer " or ' quotes — handles the two forms above
            let val = raw_val
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| raw_val.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(raw_val)
                .to_string();
            map.insert(key, val);
        }
    }

    (raw, map)
}

const CONTAINER_NAME: &str = "oline-e2e-test";
const SSH_HOST: &str = "127.0.0.1";
const SSH_PORT_HOST: u16 = 2222;
const SSH_BOOTSTRAP_TIMEOUT_SECS: u64 = 120;
const NODE_LAUNCH_TIMEOUT_SECS: u64 = 600;
const POLL_INTERVAL_SECS: u64 = 5;

/// RAII cleanup — removes the Docker container when this value is dropped,
/// regardless of whether the test passes or panics.
struct TestContainer {
    name: String,
}

impl Drop for TestContainer {
    fn drop(&mut self) {
        Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output()
            .ok();
    }
}

/// Poll `/tmp/oline-node.log` inside the container via SSH every POLL_INTERVAL_SECS
/// until all `markers` are present in the log, or `timeout` elapses.
///
/// Returns `(all_found, full_log_text)`.
fn poll_ssh_log(ssh_key_path: &str, markers: &[&str], timeout: Duration) -> (bool, String) {
    let deadline = Instant::now() + timeout;
    let mut last_log = String::new();

    while Instant::now() < deadline {
        let output = Command::new("ssh")
            .args([
                "-i",
                ssh_key_path,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                "-p",
                &SSH_PORT_HOST.to_string(),
                &format!("root@{}", SSH_HOST),
                "cat /tmp/oline-node.log 2>/dev/null || true",
            ])
            .output();

        if let Ok(out) = output {
            let log = String::from_utf8_lossy(&out.stdout).to_string();
            if !log.is_empty() {
                last_log = log;
            }
        }

        let found: Vec<&&str> = markers.iter().filter(|m| last_log.contains(**m)).collect();
        println!(
            "  [poll] {}/{} markers found",
            found.len(),
            markers.len()
        );
        if found.len() == markers.len() {
            return (true, last_log);
        }

        std::thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
    }

    (false, last_log)
}

/// Poll a TCP address until connectable or timeout elapses. Prints dots while waiting.
fn wait_for_tcp(host: &str, port: u16, timeout: Duration) -> bool {
    let addr: std::net::SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
            println!();
            return true;
        }
        print!(".");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        std::thread::sleep(Duration::from_secs(2));
    }

    println!();
    false
}

#[tokio::test]
async fn test_tls_workflow_docker() {
    // ── 0. Read required env vars ─────────────────────────────────────────────
    let omnibus_image =
        std::env::var("OMNIBUS_IMAGE").expect("OMNIBUS_IMAGE must be set to run this test");
    let chain_json =
        std::env::var("CHAIN_JSON").expect("CHAIN_JSON must be set to run this test");
    let entrypoint_url = std::env::var("ENTRYPOINT_URL").unwrap_or_else(|_| {
        "https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/tls/plays/scripts/oline-entrypoint.sh".into()
    });
    let tls_config_url = std::env::var("TLS_CONFIG_URL").unwrap_or_else(|_| {
        "https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/tls/plays/scripts/tls-setup.sh".into()
    });

    println!("  [e2e] OMNIBUS_IMAGE:  {}", omnibus_image);
    println!("  [e2e] CHAIN_JSON:     {}", chain_json);
    println!("  [e2e] ENTRYPOINT_URL: {}", entrypoint_url);
    println!("  [e2e] TLS_CONFIG_URL: {}", tls_config_url);

    // ── 1. Set env vars consumed by the crypto functions ──────────────────────
    // SSH_PORT=22 — internal_port in our endpoint; prevents a stale SSH_PORT from leaking in
    // TLS_REMOTE_*  — leave at defaults (/tmp/tls/cert.pem, /tmp/tls/privkey.pem)
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("SSH_PORT", "22");
    }

    // ── 2. Init tracing so crypto function logs are visible during the test ───
    tracing_subscriber::fmt::try_init().ok();

    // ── 3. Create workspace directory ─────────────────────────────────────────
    let workdir = PathBuf::from("/tmp/oline-e2e");
    fs::create_dir_all(&workdir).expect("Failed to create /tmp/oline-e2e");

    let ssh_key_path = workdir.join("ssh-key");
    let ssh_pub_path = workdir.join("ssh-key.pub");
    let tls_cert_path = workdir.join("cert.pem");
    let tls_key_path = workdir.join("privkey.pem");

    // ── 4. Idempotent cleanup of any leftover container + stale known_hosts ──
    // Remove the container from a previous run first.
    Command::new("docker")
        .args(["rm", "-f", CONTAINER_NAME])
        .output()
        .ok();
    // Evict any stale host-key entry for 127.0.0.1:2222 from ~/.ssh/known_hosts.
    // Each new container generates a fresh SSH host key; without this removal the
    // openssh SessionBuilder (KnownHosts::Add) rejects the changed key and every
    // SFTP attempt fails with "failed to connect to the remote host".
    Command::new("ssh-keygen")
        .args(["-R", &format!("[{}]:{}", SSH_HOST, SSH_PORT_HOST)])
        .output()
        .ok();

    // ── 5. Generate SSH keypair ───────────────────────────────────────────────
    // Remove old keys first — ssh-keygen refuses to overwrite without -f confirmation
    let _ = fs::remove_file(&ssh_key_path);
    let _ = fs::remove_file(&ssh_pub_path);

    let status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-f",
            ssh_key_path.to_str().unwrap(),
            "-N",
            "",
            "-q",
        ])
        .status()
        .expect("ssh-keygen not found — install openssh-client");
    assert!(status.success(), "ssh-keygen failed");

    let ssh_pubkey = fs::read_to_string(&ssh_pub_path).expect("Failed to read SSH pubkey");
    let ssh_privkey_pem = fs::read_to_string(&ssh_key_path).expect("Failed to read SSH privkey");
    let ssh_pubkey = ssh_pubkey.trim();

    // ── 6. Generate self-signed TLS cert (RSA 2048, 1 day) ───────────────────
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            tls_key_path.to_str().unwrap(),
            "-out",
            tls_cert_path.to_str().unwrap(),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .status()
        .expect("openssl not found — install openssl");
    assert!(status.success(), "openssl req -x509 failed");

    let tls_cert = fs::read(&tls_cert_path).expect("Failed to read TLS cert");
    let tls_privkey = fs::read(&tls_key_path).expect("Failed to read TLS key");

    // ── 7. Start Docker container ─────────────────────────────────────────────
    // --entrypoint /bin/bash bypasses the omnibus image's own entrypoint so that
    // oline-entrypoint.sh runs as the MAIN process. This ensures that
    // `exec sshd -D` in bootstrap mode makes sshd PID 1 with no parent shell
    // running cosmos setup in parallel (which caused connection resets when the
    // omnibus entrypoint invoked our script in a subshell via its ENTRYPOINT_URL
    // handling).
    // SSH_PUBKEY is injected into /root/.ssh/authorized_keys by the bootstrap script.
    // DOWNLOAD_SNAPSHOT=0: skip multi-GB snapshot. Genesis (~few MB) is still downloaded.
    let bootstrap_cmd = format!(
        "curl -fsSL '{}' -o /tmp/wrapper.sh && bash /tmp/wrapper.sh",
        entrypoint_url
    );
    println!(
        "\n  [e2e] Starting container {} with image {}",
        CONTAINER_NAME, omnibus_image
    );
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            CONTAINER_NAME,
            "--entrypoint",
            "/bin/bash",
            "-e",
            &format!("SSH_PUBKEY={}", ssh_pubkey),
            "-e",
            "SNAPSHOT_RETAIN=0",
            "-e",
            "RPC_DOMAIN=localhost",
            "-e",
            "RPC_PORT=443",
            "-e",
            &format!("TLS_CONFIG_URL={}", tls_config_url),
            "-e",
            &format!("ENTRYPOINT_URL={}", entrypoint_url),
            "-e",
            &format!("CHAIN_JSON={}", chain_json),
            "-e",
            "DOWNLOAD_SNAPSHOT=0",
            "-p",
            "2222:22",
            &omnibus_image,
            "-c",
            &bootstrap_cmd,
        ])
        .status()
        .expect("docker not found — install Docker");
    assert!(status.success(), "docker run failed");

    // RAII cleanup — container is removed when _container is dropped (test end or panic)
    let _container = TestContainer {
        name: CONTAINER_NAME.into(),
    };

    // ── 8. Wait for SSH to become available ───────────────────────────────────
    // Bootstrap downloads oline-entrypoint.sh, installs openssh-server, and
    // exec's sshd as PID 1. This takes some time (apt-get + sshd key gen).
    println!(
        "  [e2e] Waiting for SSH on {}:{} (up to {}s)",
        SSH_HOST, SSH_PORT_HOST, SSH_BOOTSTRAP_TIMEOUT_SECS
    );
    let ssh_ready = wait_for_tcp(
        SSH_HOST,
        SSH_PORT_HOST,
        Duration::from_secs(SSH_BOOTSTRAP_TIMEOUT_SECS),
    );
    assert!(
        ssh_ready,
        "SSH port {}:{} never became available within {}s — check `docker logs {}`",
        SSH_HOST, SSH_PORT_HOST, SSH_BOOTSTRAP_TIMEOUT_SECS, CONTAINER_NAME
    );
    println!("  [e2e] SSH is up.");
    // Give sshd a moment to finish initializing host keys
    std::thread::sleep(Duration::from_secs(2));

    // ── 9. Build ServiceEndpoint ──────────────────────────────────────────────
    // internal_port=22: matches SSH_PORT env (what push_tls_certs_sftp searches for)
    // port=2222: host-mapped external port (what ssh_dest_path uses to form the URI)
    // uri=http://127.0.0.1: scheme is stripped by ssh_dest_path to get "127.0.0.1"
    let endpoints = vec![ServiceEndpoint {
        service: CONTAINER_NAME.into(),
        uri: "http://127.0.0.1".into(),
        port: SSH_PORT_HOST,
        internal_port: 22,
    }];

    // ── 9.5 Diagnostics — plain SSH + container logs ──────────────────────────
    // Run before SFTP to confirm auth works and bootstrap completed as expected.
    {
        let ssh_test = Command::new("ssh")
            .args([
                "-v",
                "-i", ssh_key_path.to_str().unwrap(),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                "-p", &SSH_PORT_HOST.to_string(),
                &format!("root@{}", SSH_HOST),
                "echo SSH_OK && cat /root/.ssh/authorized_keys",
            ])
            .output();
        match ssh_test {
            Ok(out) => {
                println!("  [diag] plain ssh exit: {}", out.status);
                println!("  [diag] stdout: {}", String::from_utf8_lossy(&out.stdout).trim());
                for line in String::from_utf8_lossy(&out.stderr).lines().filter(|l| !l.starts_with("debug1:")) {
                    println!("  [diag] ssh stderr: {}", line);
                }
            }
            Err(e) => println!("  [diag] ssh command error: {}", e),
        }

        let logs = Command::new("docker").args(["logs", "--tail", "60", CONTAINER_NAME]).output();
        if let Ok(out) = logs {
            println!("  [diag] --- docker logs (last 60 lines) ---");
            let combined = [out.stdout.as_slice(), out.stderr.as_slice()].concat();
            for line in String::from_utf8_lossy(&combined).lines() {
                println!("  [diag] {}", line);
            }
            println!("  [diag] --- end docker logs ---");
        }
    }

    // ── 10. Upload TLS certs via SFTP ─────────────────────────────────────────
    println!("  [e2e] Uploading TLS certs via SFTP...");
    push_tls_certs_sftp(
        "e2e-test",
        &endpoints,
        &ssh_privkey_pem,
        &ssh_key_path,
        &tls_cert,
        &tls_privkey,
    )
    .await
    .expect("push_tls_certs_sftp failed");
    println!("  [e2e] TLS certs uploaded.");

    // ── 11. Verify cert paths + signal node start via SSH ─────────────────────
    // This confirms cert files landed at /tmp/tls/, patches /tmp/oline-env.sh with
    // SDL vars, then launches `OLINE_PHASE=start wrapper.sh` under nohup.
    //
    // RPC_DOMAIN and RPC_PORT are added here to exercise the orchestrator refresh path
    // for domain/port vars — mirroring the production fix where node_refresh_vars()
    // maps suffixed SDL vars (RPC_DOMAIN_SNAPSHOT) to the unsuffixed names the container
    // uses (RPC_DOMAIN).  Values match the -e flags set on docker run above.
    let mut sdl_vars: HashMap<String, String> = HashMap::new();
    sdl_vars.insert("CHAIN_ID".into(), String::new()); // populated from CHAIN_JSON by entrypoint
    sdl_vars.insert("CHAIN_JSON".into(), chain_json.clone());
    sdl_vars.insert("TLS_CONFIG_URL".into(), tls_config_url.clone());
    sdl_vars.insert("ADDRBOOK_URL".into(), String::new());
    sdl_vars.insert("OMNIBUS_IMAGE".into(), omnibus_image.clone());
    sdl_vars.insert("RPC_DOMAIN".into(), "localhost".into()); // matches -e RPC_DOMAIN=localhost
    sdl_vars.insert("RPC_PORT".into(), "443".into());         // matches -e RPC_PORT=443

    println!("  [e2e] Verifying certs + launching node setup...");
    verify_certs_and_signal_start(
        "e2e-test",
        &endpoints,
        &ssh_key_path,
        "/tmp/tls/cert.pem",
        "/tmp/tls/privkey.pem",
        &entrypoint_url,
        &sdl_vars,
    )
    .await
    .expect("verify_certs_and_signal_start failed");
    println!("  [e2e] Node setup launched in background.");

    // ── 11.5. Verify /tmp/oline-env.sh contains the required service vars ─────
    // This is the regression guard for the production bug where tls-setup.sh failed
    // because RPC_DOMAIN and RPC_PORT were not being patched into /tmp/oline-env.sh
    // by the orchestrator (verify_certs_and_signal_start only refreshed CHAIN_ID,
    // CHAIN_JSON, etc. — the service domain/port vars were never written).
    //
    // After the fix:
    //   - node_refresh_vars() maps RPC_DOMAIN_SNAPSHOT → RPC_DOMAIN before the call
    //   - REFRESH_VARS now includes RPC_DOMAIN, RPC_PORT, etc.
    //   - verify_certs_and_signal_start appends them to /tmp/oline-env.sh
    //
    // We read the file right after the call (it is patched before the nohup launch)
    // so the node is already running in the background, but the file is already final.
    println!("\n  [e2e] Checking /tmp/oline-env.sh for required service vars...");
    let (env_raw, env_map) = read_container_env_file(ssh_key_path.to_str().unwrap());
    println!(
        "  [e2e] Parsed {} entries from /tmp/oline-env.sh",
        env_map.len()
    );

    // These vars must be present with correct values.
    // The values come from sdl_vars above — the orchestrator refresh wrote them.
    let expected_env: &[(&str, &str)] = &[
        ("RPC_DOMAIN", "localhost"),
        ("RPC_PORT", "443"),
        ("TLS_CONFIG_URL", tls_config_url.as_str()),
        ("CHAIN_JSON", chain_json.as_str()),
    ];

    let mut env_ok = true;
    for (k, expected_v) in expected_env {
        match env_map.get(*k) {
            Some(actual) if actual == expected_v => {
                println!("  [e2e]   [OK]  {}={}", k, actual);
            }
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
        panic!("env file check failed — service vars missing or incorrect (see above)");
    }
    println!("  [e2e] /tmp/oline-env.sh check passed.\n");

    // ── 12. Poll /tmp/oline-node.log for success markers ─────────────────────
    // tls-setup.sh  → "=== TLS setup complete ==="
    // entrypoint    → "=== Cosmos node setup complete ==="
    // entrypoint    → "=== Launching:"    (node binary actually started)
    let markers: &[&str] = &[
        "=== TLS setup complete ===",
        "=== Cosmos node setup complete ===",
        "=== Launching:",
    ];
    println!(
        "  [e2e] Polling /tmp/oline-node.log for markers (up to {}s)...",
        NODE_LAUNCH_TIMEOUT_SECS
    );
    let (all_found, log) = poll_ssh_log(
        ssh_key_path.to_str().unwrap(),
        markers,
        Duration::from_secs(NODE_LAUNCH_TIMEOUT_SECS),
    );

    // ── 13. Print full log regardless of pass/fail ────────────────────────────
    println!("\n  [e2e] ===== /tmp/oline-node.log =====");
    for line in log.lines() {
        println!("  {}", line);
    }
    println!("  [e2e] ===== end log =====\n");

    // ── 14. Assert ────────────────────────────────────────────────────────────
    if !all_found {
        let missing: Vec<&&str> = markers.iter().filter(|m| !log.contains(**m)).collect();
        panic!(
            "E2E test FAILED — missing markers: {:?}\n\
             Tip: run `docker logs {}` for bootstrap output, /tmp/oline-node.log has start-mode output.",
            missing, CONTAINER_NAME
        );
    }

    println!("  [e2e] All markers found — test PASSED.");
}
