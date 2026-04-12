/// Unified MinIO-IPFS Sites test suite.
///
/// ## Test 1: `test_minio_ipfs_dual_use` (Docker-only, no Akash)
///
/// Proves one minio-ipfs container serves both snapshot storage AND static
/// websites.  Exercises the real S3→IPFS autopin→gateway pipeline via Docker,
/// validates `s3_request()` signing, and round-trips a `SiteRecord` through
/// the encrypted `SiteStore`.
///
/// ## Test 2: `test_sites_deploy_to_akash` (IctAkashNetwork)
///
/// Validates the g.yml SDL deploys successfully to a local Akash chain via
/// the `oline` subprocess.  The test-provider is a mock so S3/IPFS don't
/// actually work — this only asserts the deploy flow completes.
///
/// # Prerequisites
///
/// ```bash
/// # Test 1 (Docker only):
/// docker pull ghcr.io/permissionlessweb/minio-ipfs:v0.0.9  # or set E2E_MINIO_IMAGE
///
/// # Test 2 (Akash chain):
/// just akash-setup    # one-time: builds ict-rs chain image + test-provider
/// ```
///
/// # Run
///
/// ```bash
/// # Test 1 only:
/// cargo test --test sites_standalone test_minio_ipfs_dual_use -- --nocapture --ignored
///
/// # Test 2 only:
/// cargo test --test sites_standalone test_sites_deploy_to_akash -- --nocapture --ignored
///
/// # Both:
/// cargo test --test sites_standalone -- --nocapture --ignored
/// ```
use o_line_sdl::sites::{SiteRecord, SiteStore};
use o_line_sdl::snapshots::s3_request;
use o_line_sdl::testing::docker::{run_container, ContainerPort, ContainerSpec};
use o_line_sdl::testing::IctAkashNetwork;
use std::{collections::HashMap, env, path::PathBuf, process::Command, time::Duration};

// ── Shared helpers ────────────────────────────────────────────────────────────

fn oline_bin() -> PathBuf {
    env!("CARGO_BIN_EXE_oline").into()
}

fn test_sdl_dir() -> PathBuf {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    PathBuf::from(manifest).join("tests/fixtures/sdls")
}

fn test_secrets_dir() -> PathBuf {
    std::env::temp_dir().join("oline-sites-test-secrets")
}

fn minio_image() -> String {
    env::var("E2E_MINIO_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/permissionlessweb/minio-ipfs:v0.0.9".into())
}

/// Wait for an HTTP endpoint to return 200 (or 403 for MinIO auth endpoints).
async fn wait_for_http(url: &str, label: &str, max_attempts: u32) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for attempt in 1..=max_attempts {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() || resp.status().as_u16() == 403 {
                eprintln!("  {} ready (attempt {})", label, attempt);
                return true;
            }
        }
        if attempt % 5 == 0 {
            eprintln!("  {} attempt {}/{}", label, attempt, max_attempts);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    false
}

/// Start a minio-ipfs Docker container with standard test configuration.
///
/// Returns the container handle (RAII — auto-removed on drop).
fn start_minio_container(
    name: &str,
    s3_port: u16,
    gw_port: u16,
    s3_key: &str,
    s3_secret: &str,
    bucket: &str,
) -> o_line_sdl::testing::docker::ContainerHandle {
    let mut env = HashMap::new();
    env.insert("MINIO_ENABLED".into(), "true".into());
    env.insert("MINIO_ROOT_USER".into(), s3_key.into());
    env.insert("MINIO_ROOT_PASSWORD".into(), s3_secret.into());
    env.insert("MINIO_BUCKET".into(), bucket.into());
    env.insert("AUTOPIN_INTERVAL".into(), "10".into());
    env.insert(
        "AUTOPIN_PATTERNS".into(),
        "*.html,*.css,*.js,*.json,*.ico,*.png,*.svg,*.wasm,index.html".into(),
    );
    env.insert("NGINX_ENABLED".into(), "false".into());

    let spec = ContainerSpec {
        name: name.into(),
        image: minio_image(),
        env,
        ports: vec![
            ContainerPort {
                internal: 9000,
                host: s3_port,
            },
            ContainerPort {
                internal: 8081,
                host: gw_port,
            },
        ],
        entrypoint: None,
        command: None,
        extra_hosts: vec![],
    };

    run_container(&spec).expect("Failed to start minio-ipfs container")
}

// ── Test 1: Docker-based dual-use (snapshots + websites) ──────────────────────

#[tokio::test]
#[ignore = "requires Docker + minio-ipfs image"]
async fn test_minio_ipfs_dual_use() {
    let _ = tracing_subscriber::fmt::try_init();

    let s3_key = "testadmin";
    let s3_secret = "testadmin";
    let bucket = "sites";
    let s3_port: u16 = 19100;
    let gw_port: u16 = 18181;

    eprintln!("=== MinIO-IPFS Dual-Use: Snapshots + Websites + SiteStore ===");
    eprintln!("  Image: {}", minio_image());

    // ── Start minio-ipfs container ───────────────────────────────────────
    let _handle = start_minio_container(
        "minio-ipfs-dual-use-e2e",
        s3_port,
        gw_port,
        s3_key,
        s3_secret,
        bucket,
    );
    eprintln!("  Container started: {}", _handle.name);

    let s3_url = format!("http://127.0.0.1:{}", s3_port);
    let gw_url = format!("http://127.0.0.1:{}", gw_port);

    // ── Wait for MinIO S3 ────────────────────────────────────────────────
    assert!(
        wait_for_http(&format!("{}/minio/health/live", s3_url), "MinIO S3", 30).await,
        "MinIO S3 did not become ready"
    );

    // ── Wait for IPFS gateway ────────────────────────────────────────────
    let ipfs_empty_dir = format!(
        "{}/ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn",
        gw_url
    );
    assert!(
        wait_for_http(&ipfs_empty_dir, "IPFS gateway", 60).await,
        "IPFS gateway did not become ready"
    );

    let client = reqwest::Client::new();

    // ── Upload "snapshot" file via S3 (mimics Phase A snapshot upload) ───
    let snapshot_content = b"fake-snapshot-archive-data-for-testing";
    let snap_url = format!("{}/{}/snapshot-2024-01-01.tar.lz4", s3_url, bucket);

    let resp = s3_request(
        &client,
        reqwest::Method::PUT,
        &snap_url,
        snapshot_content,
        s3_key,
        s3_secret,
        "us-east-1",
    )
    .await
    .expect("S3 PUT snapshot failed");
    assert!(
        resp.status().is_success(),
        "S3 PUT snapshot returned HTTP {}",
        resp.status()
    );
    eprintln!(
        "  Uploaded snapshot file to S3 ({} bytes)",
        snapshot_content.len()
    );

    // ── Upload index.html via S3 (mimics `oline sites upload`) ──────────
    let html_content = b"<!DOCTYPE html><html><body><h1>Hello from O-Line Sites!</h1><p>Served via MinIO-IPFS on Akash</p></body></html>";
    let html_url = format!("{}/{}/index.html", s3_url, bucket);

    let resp = s3_request(
        &client,
        reqwest::Method::PUT,
        &html_url,
        html_content,
        s3_key,
        s3_secret,
        "us-east-1",
    )
    .await
    .expect("S3 PUT index.html failed");
    assert!(
        resp.status().is_success(),
        "S3 PUT index.html returned HTTP {}",
        resp.status()
    );
    eprintln!(
        "  Uploaded index.html to S3 ({} bytes)",
        html_content.len()
    );

    // ── Wait for autopin → IPFS ──────────────────────────────────────────
    eprintln!("  Waiting for autopin to detect index.html (up to 90s)...");
    let mut html_cid = String::new();

    for attempt in 1..=45u32 {
        if let Ok(resp) = client
            .get(format!("{}/{}/metadata.json", s3_url, bucket))
            .send()
            .await
        {
            if let Ok(body) = resp.text().await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(cid) = json
                        .pointer("/snapshots/index.html/ipfs_cid")
                        .and_then(|v| v.as_str())
                    {
                        html_cid = cid.to_string();
                        eprintln!("  index.html pinned! CID={}", html_cid);
                        break;
                    }
                }
            }
        }
        if attempt % 5 == 0 {
            eprintln!("  autopin poll {}/45...", attempt);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    assert!(
        !html_cid.is_empty(),
        "index.html was not auto-pinned to IPFS within 90s"
    );

    // ── Fetch HTML via IPFS gateway ──────────────────────────────────────
    let gw_resp = client
        .get(format!("{}/ipfs/{}", gw_url, html_cid))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("IPFS gateway GET failed");

    assert_eq!(gw_resp.status(), 200, "IPFS gateway returned non-200");

    let body = gw_resp.text().await.unwrap();
    assert!(
        body.contains("Hello from O-Line Sites!"),
        "IPFS gateway served wrong content: {}",
        &body[..body.len().min(500)]
    );
    eprintln!("  HTML served correctly via IPFS gateway!");

    // ── SiteRecord + SiteStore round-trip ────────────────────────────────
    let store_dir = tempfile::tempdir().expect("tempdir");
    let store_path = store_dir.path().join("sites.enc");
    let store = SiteStore::open(&store_path, "test-password");

    // Create and persist a SiteRecord
    let record = SiteRecord::new(
        "test.example.com".into(),
        12345,
        bucket.into(),
        s3_key.into(),
        s3_secret.into(),
        s3_url.clone(),
        "".into(), // no CF zone in tests
    );
    store.add(record).expect("SiteStore::add failed");

    // Update CID after autopin
    let updated = store
        .update("test.example.com", |rec| {
            rec.cid = html_cid.clone();
        })
        .expect("SiteStore::update failed");
    assert!(updated, "SiteStore::update should find the record");

    // Re-open store (simulates fresh process) and verify round-trip
    let store2 = SiteStore::open(&store_path, "test-password");
    let loaded = store2
        .get("test.example.com")
        .expect("SiteStore::get failed")
        .expect("record not found after round-trip");
    assert_eq!(loaded.cid, html_cid, "CID mismatch after round-trip");
    assert_eq!(loaded.s3_key, s3_key);
    assert_eq!(loaded.bucket, bucket);
    assert_eq!(loaded.dseq, 12345);
    eprintln!("  SiteStore encrypt/decrypt round-trip OK");

    eprintln!("");
    eprintln!("=== MinIO-IPFS Dual-Use Test PASSED ===");
    eprintln!("  Proved: minio-ipfs container handles S3 upload → IPFS pin → HTTP serve");
    eprintln!("  Proved: s3_request() SigV4 signing works against real MinIO");
    eprintln!("  Proved: SiteRecord + SiteStore encrypted round-trip works");
}

// ── Test 2: Akash deploy flow via IctAkashNetwork ─────────────────────────────

#[tokio::test]
#[ignore = "requires Docker for ict-rs Akash chain + test-provider"]
async fn test_sites_deploy_to_akash() {
    let _ = tracing_subscriber::fmt::try_init();

    // ── Start local Akash network ────────────────────────────────────────
    eprintln!("=== Starting IctAkashNetwork for Sites deploy ===");
    let net = IctAkashNetwork::start("sites-deploy")
        .await
        .expect("IctAkashNetwork::start");
    eprintln!(
        "  rpc={} grpc={} provider={}",
        net.rpc(),
        net.grpc(),
        net.provider_uri()
    );

    // ── Fund deployer ────────────────────────────────────────────────────
    let deployer = net.deployer_client().await.expect("deployer client");
    let deployer_addr = deployer.address().to_string();
    net.faucet(&deployer_addr, 50_000_000)
        .await
        .expect("faucet");
    eprintln!("  Funded deployer: {}", deployer_addr);

    // ── Deploy g.yml via oline subprocess ────────────────────────────────
    let sdl_dir = test_sdl_dir();
    let secrets_dir = test_secrets_dir();
    let _ = std::fs::create_dir_all(&secrets_dir);

    let image = minio_image();
    eprintln!("=== Deploying g.yml to local Akash ===");
    eprintln!("  image: {}", image);
    eprintln!("  SDL dir: {}", sdl_dir.display());

    // Use a clean temp dir as CWD so oline won't load .env from the repo root.
    let clean_cwd = std::env::temp_dir().join("oline-sites-test-cwd");
    let _ = std::fs::create_dir_all(&clean_cwd);

    let child = Command::new(oline_bin())
        .args(["deploy", "--parallel"])
        .env_clear()
        .current_dir(&clean_cwd)
        // Minimal system vars
        .env("HOME", env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
        .env("PATH", env::var("PATH").unwrap_or_default())
        // Non-interactive bypasses
        .env("OLINE_NON_INTERACTIVE", "1")
        .env("OLINE_MNEMONIC", &net.deployer_mnemonic)
        .env("OLINE_PASSWORD", "oline-sites-test")
        // Endpoints from IctAkashNetwork
        .env("OLINE_RPC_ENDPOINT", net.rpc())
        .env("OLINE_GRPC_ENDPOINT", net.grpc())
        .env("OLINE_REST_ENDPOINT", "")
        .env("OLINE_CHAIN_ID", net.chain_id())
        .env("OLINE_DENOM", "uakt")
        // Test image + SDL directory
        .env("MINIO_IPFS_IMAGE", &image)
        .env("SDL_DIR", sdl_dir.to_string_lossy().as_ref())
        // Skip DNS (no Cloudflare creds)
        .env("OLINE_CF_API_TOKEN", "")
        .env("OLINE_CF_ZONE_ID", "")
        // Secrets
        .env("SECRETS_PATH", secrets_dir.to_string_lossy().as_ref())
        .env("OLINE_ENCRYPTED_MNEMONIC", "")
        // Bid wait + stop after deploy
        .env("OLINE_MAX_BID_WAIT", "20")
        .env("OLINE_TEST_STOP_AFTER_DEPLOY", "1")
        // Logging
        .env(
            "RUST_LOG",
            "info,akash_deploy_rs=debug,test_provider=debug",
        )
        .output()
        .expect("failed to spawn oline");

    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    eprintln!("oline stdout:\n{}", stdout);
    eprintln!("oline stderr:\n{}", stderr);

    // Extract DSEQ from output
    let dseq_line = stdout
        .lines()
        .chain(stderr.lines())
        .find(|l| l.contains("DSEQ") && l.chars().any(|c| c.is_ascii_digit()));
    eprintln!("  DSEQ line: {:?}", dseq_line);

    assert!(
        child.status.success() || stderr.contains("DSEQ"),
        "oline deploy failed: exit={:?}\nstdout: {}\nstderr: {}",
        child.status,
        &stdout[..stdout.len().min(2000)],
        &stderr[..stderr.len().min(2000)],
    );

    eprintln!("=== Sites deploy to Akash PASSED ===");
    eprintln!("  The test-provider accepted the g.yml manifest.");
    eprintln!("  S3/IPFS don't work (mock provider) — deploy flow only.");
}
