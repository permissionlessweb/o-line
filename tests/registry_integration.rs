//! Registry integration tests — require a running Docker daemon.
//!
//! Run via:
//! ```bash
//! just test registry integration
//! # or directly:
//! cargo test --features testing --test registry_integration -- --nocapture --ignored --test-threads=1
//! ```

use o_line_sdl::registry::{import::import_image_direct, server, storage::list_registry_images};
use std::net::TcpListener;
use tempfile::TempDir;

/// Ensure `nginx:alpine` is available locally; panics if Docker is broken.
fn ensure_nginx_alpine() {
    let output = std::process::Command::new("docker")
        .args(["pull", "nginx:alpine"])
        .output()
        .expect("docker command not found");
    assert!(
        output.status.success(),
        "docker pull nginx:alpine failed — is Docker healthy?\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Bind to port 0, read the OS-assigned port, and close the socket.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind port 0");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Start the registry server on a random port in a background task.
///
/// Uses `serve_with_dir` to pass the storage path directly, avoiding env var
/// races when multiple tests run in the same process.
fn spawn_registry(
    storage_dir: &std::path::Path,
    port: u16,
    username: &str,
    password: &str,
) -> tokio::task::JoinHandle<()> {
    let storage = storage_dir.to_path_buf();
    let username = username.to_string();
    let password = password.to_string();

    tokio::spawn(async move {
        if let Err(e) = server::serve_with_dir(port, &username, &password, &storage).await {
            eprintln!("[registry] server error: {e}");
        }
    })
}

/// Wait for the registry HTTP endpoint to become available.
async fn wait_for_registry(port: u16) {
    let url = format!("http://127.0.0.1:{port}/v2/");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();

    for _ in 0..30 {
        if client.get(&url).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    panic!("registry did not start on port {port} within 6 seconds");
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Start the registry with auth and verify:
///   - Anonymous read GET `/v2/` → 200
///   - Authenticated read GET `/v2/` → 200
///   - Unauthenticated write POST (blob upload) → rejected (401/403)
#[tokio::test]
#[ignore]
async fn test_registry_serve_and_v2_check() {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port();
    let handle = spawn_registry(tmp.path(), port, "oline", "testpass");

    wait_for_registry(port).await;

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    // Anonymous read → 200 (Anonymous auth provider grants ReadOnly to unauthed)
    let resp = client.get(format!("{base}/v2/")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "expected 200 for anonymous read");

    // Authenticated read → 200
    let resp = client
        .get(format!("{base}/v2/"))
        .basic_auth("oline", Some("testpass"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "expected 200 for authenticated read");

    // Unauthenticated write → rejected
    let resp = client
        .post(format!("{base}/v2/test/repo/blobs/uploads/"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "expected 401/403 for unauthenticated write, got {status}"
    );

    handle.abort();
}

/// `import_image_direct("nginx:alpine", dir)` writes blobs + tags,
/// then `list_registry_images` discovers it.
#[tokio::test]
#[ignore]
async fn test_registry_direct_import_and_list() {
    let tmp = TempDir::new().unwrap();

    ensure_nginx_alpine();

    import_image_direct("nginx:alpine", tmp.path())
        .await
        .expect("import_image_direct failed");

    let images = list_registry_images(tmp.path()).unwrap();
    assert!(
        images.iter().any(|i| i.contains("nginx") && i.contains("alpine")),
        "expected nginx:alpine in listing, got: {images:?}"
    );
}

/// Upload a blob to the registry via the OCI Distribution API (PATCH + PUT).
///
/// The `container-registry` crate requires chunked upload: PATCH data first,
/// then PUT with `?digest=` to finalize.
async fn upload_blob(
    client: &reqwest::Client,
    base: &str,
    repo: &str,
    data: &[u8],
    digest: &str,
) {
    // POST to start upload
    let resp = client
        .post(format!("{base}/v2/{repo}/blobs/uploads/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202, "expected 202 for upload start");

    let location = resp
        .headers()
        .get("location")
        .expect("missing Location header")
        .to_str()
        .unwrap()
        .to_string();

    let abs_url = if location.starts_with("http") {
        location.clone()
    } else {
        format!("{base}{location}")
    };

    // PATCH data
    let resp = client
        .patch(&abs_url)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", data.len().to_string())
        .header("Content-Range", format!("0-{}", data.len() - 1))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "PATCH blob failed: {}",
        resp.status()
    );

    // PUT to finalize with digest
    let separator = if abs_url.contains('?') { '&' } else { '?' };
    let finalize_url = format!("{abs_url}{separator}digest={digest}");

    let resp = client
        .put(&finalize_url)
        .header("Content-Length", "0")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "expected 201 for blob finalize, got {}",
        resp.status()
    );
}

/// Push a blob + manifest to an open registry via the OCI Distribution API,
/// then pull the manifest back and verify its content.
///
/// Uses reqwest directly (no Docker daemon push) to avoid HTTPS/insecure-registry
/// issues with Docker Desktop.
#[tokio::test]
#[ignore]
async fn test_registry_oci_api_roundtrip() {
    use sha2::{Digest, Sha256};

    let tmp = TempDir::new().unwrap();
    let port = pick_free_port();
    // Open registry — no auth
    let handle = spawn_registry(tmp.path(), port, "", "");

    wait_for_registry(port).await;

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let repo = "test/hello";

    // ── 1. Upload config blob ────────────────────────────────────────────────
    let config_json = br#"{"architecture":"amd64","os":"linux"}"#;
    let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(config_json)));
    let config_size = config_json.len();

    upload_blob(&client, &base, repo, config_json, &config_digest).await;

    // ── 2. Upload layer blob ─────────────────────────────────────────────────
    let layer_data = b"fake layer content for testing";
    let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(layer_data)));
    let layer_size = layer_data.len();

    upload_blob(&client, &base, repo, layer_data, &layer_digest).await;

    // ── 3. Push manifest ─────────────────────────────────────────────────────
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest
        },
        "layers": [{
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar",
            "size": layer_size,
            "digest": layer_digest
        }]
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

    let resp = client
        .put(format!("{base}/v2/{repo}/manifests/latest"))
        .header("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
        .body(manifest_bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "expected 201 for manifest push, got {}",
        resp.status()
    );

    // ── 4. Pull manifest back ────────────────────────────────────────────────
    let resp = client
        .get(format!("{base}/v2/{repo}/manifests/latest"))
        .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "expected 200 for manifest pull");

    let pulled: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(pulled["schemaVersion"], 2);
    assert_eq!(pulled["config"]["digest"], config_digest);
    assert_eq!(
        pulled["layers"][0]["digest"],
        layer_digest,
    );

    eprintln!("[test] OCI API roundtrip passed");

    handle.abort();
}

/// With auth enabled, verify that unauthenticated reads succeed (anonymous ReadOnly)
/// but unauthenticated writes are blocked.
#[tokio::test]
#[ignore]
async fn test_registry_auth_enforced() {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port();
    let handle = spawn_registry(tmp.path(), port, "oline", "secret123");

    wait_for_registry(port).await;

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    // Anonymous read (GET /v2/) → allowed
    let resp = client.get(format!("{base}/v2/")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "anonymous read should succeed");

    // Anonymous write (POST blob upload) → rejected
    let resp = client
        .post(format!("{base}/v2/test/image/blobs/uploads/"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "expected 401/403 for anonymous write, got {status}"
    );

    // Anonymous manifest push → rejected
    let resp = client
        .put(format!("{base}/v2/test/image/manifests/v1"))
        .header("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
        .body(r#"{"schemaVersion":2}"#)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "expected 401/403 for anonymous manifest push, got {status}"
    );

    handle.abort();
}
