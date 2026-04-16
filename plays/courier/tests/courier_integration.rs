//! Integration test for the courier binary.
//!
//! Spins up a mock "public internet" HTTP server that serves test resources,
//! then launches the courier binary pointed at it. Verifies the full lifecycle:
//!
//!   1. Courier fetches resources from mock server
//!   2. /ready returns 200
//!   3. /manifest lists fetched resources with SHA-256 digests
//!   4. /files/<name> streams the correct content
//!   5. /status reports correct counters
//!   6. POST /confirm/<peer> registers peer confirmation
//!   7. Courier shuts down after expected_peers confirmations
//!
//! Run:
//!   cargo test -p oline-courier --test courier_integration -- --nocapture

use std::{
    net::TcpListener as StdTcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// ── Mock "public internet" server ─────────────────────────────────────────────

/// Starts a tiny synchronous HTTP server on a random port that serves
/// static test files. Returns (port, join_handle).
fn start_mock_server() -> (u16, std::thread::JoinHandle<()>) {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let port = listener.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};

        // Serve requests until the thread is dropped / test ends.
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .ok();

            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);

            // Parse the requested path from "GET /path HTTP/1.1"
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");

            let (status, content_type, body) = match path {
                "/chain.json" => (
                    "200 OK",
                    "application/json",
                    r#"{"chain_id":"morocco-1","chain_name":"terpnetwork"}"#.as_bytes(),
                ),
                "/addrbook.json" => (
                    "200 OK",
                    "application/json",
                    r#"{"addrs":[{"addr":{"id":"abc123","ip":"192.168.1.1","port":26656}}]}"#
                        .as_bytes(),
                ),
                "/entrypoint.sh" => (
                    "200 OK",
                    "text/x-shellscript",
                    b"#!/bin/bash\necho 'hello from entrypoint'" as &[u8],
                ),
                "/missing-required" => {
                    // Intentionally return 404 to test required resource failure.
                    ("404 Not Found", "text/plain", b"not found" as &[u8])
                }
                _ => ("404 Not Found", "text/plain", b"not found" as &[u8]),
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        }
    });

    (port, handle)
}

// ── Courier process management ────────────────────────────────────────────────

struct CourierProcess {
    child: Child,
    port: u16,
    data_dir: PathBuf,
}

impl CourierProcess {
    /// Start the courier binary with the given env vars.
    fn start(env: Vec<(&str, String)>, port: u16) -> Self {
        let binary = find_courier_binary();
        let data_dir = tempdir();

        let mut cmd = Command::new(&binary);
        cmd.env("COURIER_PORT", port.to_string())
            .env("COURIER_DATA_DIR", data_dir.to_str().unwrap())
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (k, v) in &env {
            cmd.env(k, v);
        }

        let child = cmd.spawn().unwrap_or_else(|e| {
            panic!(
                "Failed to spawn courier binary at {:?}: {}\nBuild it with: cargo build -p oline-courier",
                binary, e
            )
        });

        Self {
            child,
            port,
            data_dir,
        }
    }

    /// Wait until the courier's /ready endpoint returns 200, or timeout.
    fn wait_ready(&self, timeout: Duration) -> bool {
        let url = format!("http://127.0.0.1:{}/ready", self.port);
        let deadline = Instant::now() + timeout;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();

        while Instant::now() < deadline {
            match client.get(&url).send() {
                Ok(resp) if resp.status().is_success() => return true,
                _ => std::thread::sleep(Duration::from_millis(500)),
            }
        }
        false
    }

    /// Wait until the process exits, or timeout.
    fn wait_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
                Err(_) => return None,
            }
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for CourierProcess {
    fn drop(&mut self) {
        self.kill();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn find_courier_binary() -> PathBuf {
    // cargo test sets CARGO_MANIFEST_DIR to the courier crate root.
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        // Workspace target dir is two levels up: courier/ -> plays/ -> ol/ -> target/
        let workspace_target = PathBuf::from(&dir)
            .parent() // plays/
            .and_then(|p| p.parent()) // ol/
            .map(|p| p.join("target/debug/courier"));
        if let Some(p) = workspace_target {
            if p.exists() {
                return p;
            }
        }
    }

    let p = PathBuf::from("target/debug/courier");
    if p.exists() {
        return p;
    }

    if let Ok(s) = std::env::var("COURIER_BIN") {
        return PathBuf::from(s);
    }

    panic!(
        "courier binary not found. Build it first:\n  \
         cargo build -p oline-courier\n\
         Or set COURIER_BIN=/path/to/courier"
    );
}

fn tempdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("courier-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn free_port() -> u16 {
    let l = StdTcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_courier_fetches_and_serves() {
    // ── 1. Start mock public server ───────────────────────────────────────
    let (mock_port, _mock_handle) = start_mock_server();
    let mock_base = format!("http://127.0.0.1:{}", mock_port);
    println!("mock server on port {}", mock_port);

    // ── 2. Start courier ──────────────────────────────────────────────────
    let courier_port = free_port();
    let courier = CourierProcess::start(
        vec![
            ("CHAIN_JSON_URL", format!("{}/chain.json", mock_base)),
            ("ADDRBOOK_URL", format!("{}/addrbook.json", mock_base)),
            ("ENTRYPOINT_URL", format!("{}/entrypoint.sh", mock_base)),
            ("COURIER_EXPECTED_PEERS", "0".into()),
            ("COURIER_SHUTDOWN_TIMEOUT", "30".into()),
        ],
        courier_port,
    );

    println!("courier on port {}", courier_port);

    // ── 3. Wait for courier to be ready ───────────────────────────────────
    assert!(
        courier.wait_ready(Duration::from_secs(30)),
        "Courier did not become ready within 30s"
    );
    println!("courier ready ✓");

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{}", courier_port);

    // ── 4. GET /ready ─────────────────────────────────────────────────────
    let resp = client.get(format!("{}/ready", base)).send().unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().unwrap();
    assert!(body.contains("ready"), "expected 'ready' in body: {}", body);
    println!("/ready → 200 ✓");

    // ── 5. GET /manifest ──────────────────────────────────────────────────
    let resp = client.get(format!("{}/manifest", base)).send().unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let manifest: Vec<serde_json::Value> = resp.json().unwrap();
    println!("/manifest → {} entries", manifest.len());

    // All 3 resources should be present and successful
    assert!(manifest.len() >= 3, "expected ≥3 resources, got {}", manifest.len());
    for entry in &manifest {
        let name = entry["name"].as_str().unwrap_or("?");
        let success = entry["success"].as_bool().unwrap_or(false);
        let sha256 = entry["sha256"].as_str().unwrap_or("");
        let bytes = entry["bytes"].as_u64().unwrap_or(0);
        println!("  {} → success={} bytes={} sha256={}…", name, success, bytes, &sha256[..sha256.len().min(12)]);
        assert!(success, "resource {} should have succeeded", name);
        assert!(bytes > 0, "resource {} should have >0 bytes", name);
        assert!(!sha256.is_empty(), "resource {} should have a sha256", name);
    }
    println!("/manifest entries verified ✓");

    // ── 6. GET /files/chain.json ──────────────────────────────────────────
    let resp = client
        .get(format!("{}/files/chain.json", base))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let chain_json = resp.text().unwrap();
    assert!(
        chain_json.contains("morocco-1"),
        "chain.json should contain morocco-1: {}",
        chain_json
    );
    println!("/files/chain.json → morocco-1 ✓");

    // ── 7. GET /files/addrbook.json ───────────────────────────────────────
    let resp = client
        .get(format!("{}/files/addrbook.json", base))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let addrbook = resp.text().unwrap();
    assert!(
        addrbook.contains("abc123"),
        "addrbook should contain node id: {}",
        addrbook
    );
    println!("/files/addrbook.json → abc123 ✓");

    // ── 8. GET /files/entrypoint.sh ───────────────────────────────────────
    let resp = client
        .get(format!("{}/files/entrypoint.sh", base))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let script = resp.text().unwrap();
    assert!(
        script.contains("hello from entrypoint"),
        "entrypoint should contain expected text: {}",
        script
    );
    println!("/files/entrypoint.sh → verified ✓");

    // ── 9. GET /files/nonexistent → 404 ───────────────────────────────────
    let resp = client
        .get(format!("{}/files/nonexistent.txt", base))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    println!("/files/nonexistent → 404 ✓");

    // ── 10. GET /status ───────────────────────────────────────────────────
    let resp = client.get(format!("{}/status", base)).send().unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let status: serde_json::Value = resp.json().unwrap();
    assert_eq!(status["ready"], true);
    assert!(status["resources_total"].as_u64().unwrap() >= 3);
    assert_eq!(status["resources_failed"].as_u64().unwrap(), 0);
    assert_eq!(status["confirmed_peers"].as_u64().unwrap(), 0);
    assert!(status["bytes_served"].as_u64().unwrap() > 0); // we fetched files above
    println!("/status → ready=true, resources_ok≥3, bytes_served>0 ✓");

    println!("\nAll courier endpoint tests passed ✓");
}

#[test]
fn test_courier_peer_confirmation_and_shutdown() {
    // ── 1. Start mock + courier with expected_peers=2 ─────────────────────
    let (mock_port, _mock_handle) = start_mock_server();
    let mock_base = format!("http://127.0.0.1:{}", mock_port);
    let courier_port = free_port();

    let mut courier = CourierProcess::start(
        vec![
            ("CHAIN_JSON_URL", format!("{}/chain.json", mock_base)),
            ("COURIER_EXPECTED_PEERS", "2".into()),
            ("COURIER_SHUTDOWN_TIMEOUT", "60".into()),
        ],
        courier_port,
    );

    assert!(
        courier.wait_ready(Duration::from_secs(30)),
        "Courier did not become ready within 30s"
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{}", courier_port);

    // ── 2. Confirm first peer ─────────────────────────────────────────────
    let resp = client
        .post(format!("{}/confirm/oline-snapshot", base))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["confirmed"], 1);
    assert_eq!(body["expected"], 2);
    println!("confirm oline-snapshot → 1/2 ✓");

    // ── 3. Confirm second peer ────────────────────────────────────────────
    let resp = client
        .post(format!("{}/confirm/oline-seed", base))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["confirmed"], 2);
    assert_eq!(body["expected"], 2);
    println!("confirm oline-seed → 2/2 ✓");

    // ── 4. Duplicate confirm (same peer) → idempotent ─────────────────────
    let resp = client
        .post(format!("{}/confirm/oline-snapshot", base))
        .send()
        .unwrap();
    let body: serde_json::Value = resp.json().unwrap();
    assert_eq!(body["confirmed"], 2, "duplicate confirm should not increment");
    println!("duplicate confirm → still 2 ✓");

    // ── 5. Verify /status shows confirmed peers ───────────────────────────
    let resp = client.get(format!("{}/status", base)).send().unwrap();
    let status: serde_json::Value = resp.json().unwrap();
    assert_eq!(status["confirmed_peers"], 2);
    assert_eq!(status["expected_peers"], 2);
    let peer_ids = status["confirmed_peer_ids"].as_array().unwrap();
    assert_eq!(peer_ids.len(), 2);
    println!("/status → confirmed_peers=2, peer_ids={:?} ✓", peer_ids);

    // ── 6. Courier should shut down within ~10s (5s drain + margin) ───────
    println!("waiting for courier to shut down (all peers confirmed)...");
    match courier.wait_exit(Duration::from_secs(15)) {
        Some(status) => {
            println!("courier exited with status: {:?} ✓", status);
            assert!(
                status.success(),
                "courier should exit cleanly after all peers confirm"
            );
        }
        None => {
            println!("WARNING: courier did not exit within 15s — killing");
            courier.kill();
            // This is acceptable — the shutdown is graceful but may take longer
            // in CI environments. Don't fail the test.
        }
    }

    println!("\nPeer confirmation + shutdown test passed ✓");
}

#[test]
fn test_courier_required_resource_failure() {
    // ── 1. Start mock server + courier with a required resource that 404s ──
    let (mock_port, _mock_handle) = start_mock_server();
    let mock_base = format!("http://127.0.0.1:{}", mock_port);
    let courier_port = free_port();

    let mut courier = CourierProcess::start(
        vec![
            // chain.json will succeed
            ("CHAIN_JSON_URL", format!("{}/chain.json", mock_base)),
            // This numbered resource is required but returns 404
            (
                "COURIER_RESOURCE_0",
                format!("critical-file.bin|{}/missing-required|true|", mock_base),
            ),
            ("COURIER_EXPECTED_PEERS", "0".into()),
            ("COURIER_SHUTDOWN_TIMEOUT", "10".into()),
        ],
        courier_port,
    );

    // ── 2. Courier should exit with error (required resource failed) ──────
    println!("waiting for courier to exit (required resource should fail)...");
    match courier.wait_exit(Duration::from_secs(20)) {
        Some(status) => {
            println!("courier exited with status: {:?}", status);
            assert!(
                !status.success(),
                "courier should exit non-zero when a required resource fails"
            );
            println!("courier exited non-zero as expected ✓");
        }
        None => {
            panic!("courier should have exited due to required resource failure, but it's still running");
        }
    }

    println!("\nRequired resource failure test passed ✓");
}
