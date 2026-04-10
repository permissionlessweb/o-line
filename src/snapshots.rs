use crate::{
    cli::{prompt_s3_creds, redact_if_secret, urlencoded},
    config::days_to_date,
    crypto::{hmac_sha256, sha256_hex, ssh_dest_path},
};
use akash_deploy_rs::ServiceEndpoint;
use std::{
    env::var,
    error::Error,
    fs,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

/// Sign an S3 request using AWS Signature V4 (path-style).
/// Returns the Authorization header value and headers to add.
pub fn s3_signed_headers(
    method: &str,
    url: &reqwest::Url,
    payload: &[u8],
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> Vec<(String, String)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Format timestamps (manual — no chrono dependency)
    let (year, month, day) = days_to_date(now / 86400);
    let rem = now % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;
    let secs = rem % 60;

    let date_stamp = format!("{:04}{:02}{:02}", year, month, day);
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hours, mins, secs
    );

    let host = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or(""), port),
        None => url.host_str().unwrap_or("").to_string(),
    };
    let path = url.path();
    let query = url.query().unwrap_or("");
    let payload_hash = sha256_hex(payload);

    // Canonical headers (sorted by key, lowercase)
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, payload_hash, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    // Canonical request
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, query, canonical_headers, signed_headers, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );

    // Signing key
    let k_date = hmac_sha256(
        format!("AWS4{}", secret_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, scope, signed_headers, signature
    );

    vec![
        ("Authorization".into(), auth),
        ("x-amz-date".into(), amz_date),
        ("x-amz-content-sha256".into(), payload_hash),
    ]
}

pub async fn s3_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    payload: &[u8],
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> Result<reqwest::Response, Box<dyn Error>> {
    let parsed_url = reqwest::Url::parse(url)?;
    let headers = s3_signed_headers(
        method.as_str(),
        &parsed_url,
        payload,
        access_key,
        secret_key,
        region,
    );

    let mut req = client.request(method, parsed_url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if !payload.is_empty() {
        req = req.body(payload.to_vec());
    }
    Ok(req.send().await?)
}

pub async fn fetch_latest_snapshot_url(
    state_url: &str,
    base_url: &str,
) -> Result<String, Box<dyn Error>> {
    tracing::info!("Fetching latest snapshot info from {}...", state_url);
    let resp = reqwest::get(state_url).await?.text().await?;
    let trimmed = resp.trim();
    let state: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("Failed to parse snapshot state JSON: {}", e))?;

    // Try `latest` field first (cosmos-omnibus format: {"chain_id":…, "latest":…, "snapshots":[…]})
    // Fall back to legacy format: {"snapshot_name":…} with base_url prefix.
    let url = if let Some(u) = state["latest"].as_str() {
        u.to_string()
    } else if let Some(name) = state["snapshot_name"].as_str() {
        format!("{}{}", base_url, name)
    } else {
        return Err("missing 'latest' or 'snapshot_name' in snapshot state JSON".into());
    };

    tracing::info!("  Latest snapshot: {}", url);
    Ok(url)
}

/// Fetch the snapshot metadata JSON and return the latest snapshot download URL.
/// Tries the `latest` field (cosmos-omnibus format) then the `url` field (legacy).
/// Falls back to `fallback_url` if the metadata is unavailable or malformed.
pub async fn fetch_snapshot_url_from_metadata(metadata_url: &str, fallback_url: &str) -> String {
    tracing::info!("  Fetching snapshot metadata from {}", metadata_url);
    match reqwest::get(metadata_url).await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => {
                // Try `latest` field first (cosmos-omnibus: {"chain_id":…, "latest":…})
                // then fall back to legacy `url` field.
                let url = json
                    .get("latest")
                    .or_else(|| json.get("url"))
                    .and_then(|u| u.as_str());
                if let Some(url) = url {
                    tracing::info!("  Snapshot URL from metadata: {}", url);
                    return url.to_string();
                }
                tracing::info!(
                    "  Warning: snapshot metadata JSON has no 'latest' or 'url' field — using fallback"
                );
            }
            Err(e) => tracing::info!(
                "  Warning: failed to parse snapshot metadata JSON: {} — using fallback",
                e
            ),
        },
        Err(e) => tracing::info!(
            "  Warning: failed to fetch snapshot metadata from {}: {} — using fallback",
            metadata_url,
            e
        ),
    }
    tracing::info!("  Using fallback snapshot URL: {}", fallback_url);
    fallback_url.to_string()
}

/// Download the current public snapshot to a local cache directory, if not already present.
///
/// Workflow:
///   1. Fetch `state_url` → parse JSON → extract latest snapshot filename + URL.
///   2. Derive `local_path = cache_dir/<filename>` (the filename from the URL, e.g.
///      `terp_2024-01-01.tar.lz4`).
///   3. If `local_path` already exists and is non-empty → return it immediately (cache hit).
///   4. Otherwise download via `wget -c` and return the path.
///
/// Pass this path as `E2E_SNAPSHOT_PATH` so the e2e harness distributes it via SSH
/// instead of each node downloading independently.
///
/// # Example
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use o_line_sdl::snapshots::ensure_snapshot_cached;
/// use std::path::PathBuf;
///
/// let path = ensure_snapshot_cached(
///     "https://server-4.itrocket.net/mainnet/terp/.current_state.json",
///     "https://server-4.itrocket.net/mainnet/terp/",
///     &PathBuf::from("/tmp/oline-snapshot-cache"),
/// ).await.unwrap();
/// println!("Snapshot ready at: {:?}", path);
/// # }
/// ```
pub async fn ensure_snapshot_cached(
    state_url: &str,
    base_url: &str,
    cache_dir: &Path,
) -> Result<PathBuf, Box<dyn Error>> {
    let download_url = fetch_latest_snapshot_url(state_url, base_url).await?;

    // Derive filename from the URL (last path segment)
    let filename = download_url
        .split('/')
        .filter(|s| !s.is_empty())
        .last()
        .ok_or_else(|| format!("Cannot extract filename from URL: {}", download_url))?
        .to_string();

    let local_path = cache_dir.join(&filename);

    if local_path.exists() && fs::metadata(&local_path)?.len() > 0 {
        println!(
            "  [snapshot] Cache hit: {:?} ({} bytes) — skipping download.",
            local_path,
            fs::metadata(&local_path)?.len()
        );
        return Ok(local_path);
    }

    println!(
        "  [snapshot] Cache miss for '{}' — downloading...",
        filename
    );
    fetch_snapshot_to_local(&download_url, &local_path).await?;
    Ok(local_path)
}

// ── Local snapshot transfer ───────────────────────────────────────────────────
//
// These functions implement the download-once, distribute-locally pattern:
//
//   1. `fetch_snapshot_to_local`  — download from public URL to local cache (skip if cached)
//   2. `fetch_snapshot_from_node` — SSH into running node, stream data dir to local file
//   3. `push_snapshot_to_node`    — pipe local archive to waiting node via SSH
//
// Nodes waiting for SFTP delivery must be started with SNAPSHOT_MODE=sftp
// (see plays/audible/oline-entrypoint.sh).  The deployer sets this env var in
// the SDL before deploying subsequent phases.

/// Download a snapshot from `url` to `local_path`.
///
/// If `local_path` already exists and is non-empty, returns immediately
/// (cached — use this to download once and reuse across deployments).
/// Uses `wget` which follows redirects and supports resume with `-c`.
pub async fn fetch_snapshot_to_local(
    url: &str,
    local_path: &Path,
) -> Result<(), Box<dyn Error>> {
    if local_path.exists() && fs::metadata(local_path)?.len() > 0 {
        tracing::info!(
            "  [snapshot] Cached: {:?} — skipping download.",
            local_path
        );
        return Ok(());
    }
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)?;
    }
    tracing::info!("  [snapshot] Downloading {} → {:?}", url, local_path);
    let status = std::process::Command::new("wget")
        .args([
            "-c",
            "--progress=dot:giga",
            "--max-redirect=5",
            "-O",
            local_path.to_str().unwrap(),
            url,
        ])
        .status()
        .map_err(|e| format!("wget not found: {}", e))?;
    if !status.success() {
        return Err(format!("wget failed (exit {:?})", status.code()).into());
    }
    tracing::info!(
        "  [snapshot] Downloaded: {:?} ({} bytes)",
        local_path,
        fs::metadata(local_path)?.len()
    );
    Ok(())
}

/// SSH into a running cosmos node and stream its data directory as a compressed
/// tar archive to `local_path`.
///
/// Uses the system `ssh` binary for streaming — handles multi-GB files without
/// buffering in memory.  WAL files are excluded (they are live and change-prone).
///
/// `format`: `"tar.lz4"` (default, fast), `"tar.zst"`, or `"tar.gz"`.
/// `remote_data_dir`: e.g. `"/root/.terpd/data"`.
///
/// If `local_path` already exists and is non-empty, skips the fetch.
pub async fn fetch_snapshot_from_node(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    remote_data_dir: &str,
    local_path: &Path,
    format: &str,
) -> Result<(), Box<dyn Error>> {
    if local_path.exists() && fs::metadata(local_path)?.len() > 0 {
        tracing::info!(
            "  [{}] Snapshot cached at {:?} — skipping fetch.",
            label,
            local_path
        );
        return Ok(());
    }
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let (user_host, port) = ssh_user_host_port(endpoints, ssh_key_path, label)?;

    let compress = match format {
        "tar.lz4" => "lz4 -c",
        "tar.zst" => "zstd -c --fast",
        _ => "gzip -c",
    };
    let remote_cmd = format!(
        "tar c --exclude='*.wal' -C '{}' . | {}",
        remote_data_dir, compress
    );

    tracing::info!(
        "  [{}] Streaming data dir {} → {:?}",
        label,
        remote_data_dir,
        local_path
    );

    let mut out_file = fs::File::create(local_path)
        .map_err(|e| format!("[{}] Cannot create {:?}: {}", label, local_path, e))?;

    let mut ssh_args = vec!["-i", ssh_key_path.to_str().unwrap(), "-p", &port];
    ssh_args.extend_from_slice(crate::crypto::SSH_FAST_ARGS);
    ssh_args.extend_from_slice(&[&user_host as &str, &remote_cmd as &str]);

    let mut child = std::process::Command::new("ssh")
        .args(&ssh_args)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("[{}] ssh not found: {}", label, e))?;
    // Total size unknown for streaming tar — pass 0 for bytes-only progress
    let status = crate::crypto::pipe_process_to_file(&mut child, &mut out_file, 0, label)
        .map_err(|e| format!("[{}] pipe error: {}", label, e))?;

    if !status.success() {
        let _ = fs::remove_file(local_path); // remove partial file
        return Err(
            format!("[{}] ssh stream failed (exit {:?})", label, status.code()).into(),
        );
    }

    tracing::info!(
        "  [{}] Snapshot saved: {:?} ({} bytes)",
        label,
        local_path,
        fs::metadata(local_path)?.len()
    );
    Ok(())
}

/// Pipe a local snapshot archive to a waiting remote node via SSH.
///
/// The node must be started with `SNAPSHOT_MODE=sftp` so `oline-entrypoint.sh`
/// waits for the file at `remote_path` (default `/tmp/snapshot.tar.lz4`).
///
/// Uses the system `ssh` binary with stdin piping — handles multi-GB files
/// without buffering in memory.
pub async fn push_snapshot_to_node(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    local_path: &Path,
    remote_path: &str,
) -> Result<(), Box<dyn Error>> {
    let size = fs::metadata(local_path)
        .map_err(|e| format!("[{}] Cannot read {:?}: {}", label, local_path, e))?
        .len();

    let (user_host, port) = ssh_user_host_port(endpoints, ssh_key_path, label)?;

    tracing::info!(
        "  [{}] Pushing snapshot ({} bytes) → {}:{}",
        label,
        size,
        user_host,
        remote_path
    );

    let max_attempts: u16 = 30;
    let mut attempt: u16 = 0;

    loop {
        attempt += 1;

        // Ensure parent directory exists on the remote node
        let mkdir_cmd = format!("mkdir -p '{}'", remote_path.rsplit('/').skip(1).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("/"));
        let mut mkdir_args = vec!["-i", ssh_key_path.to_str().unwrap(), "-p", &port];
        mkdir_args.extend_from_slice(crate::crypto::SSH_FAST_ARGS);
        mkdir_args.extend_from_slice(&[&user_host as &str, &mkdir_cmd]);
        let _ = std::process::Command::new("ssh").args(&mkdir_args).status();

        let mut src_file = fs::File::open(local_path)
            .map_err(|e| format!("[{}] Cannot open {:?}: {}", label, local_path, e))?;

        let write_cmd = format!("cat > '{}'", remote_path);
        let mut ssh_args = vec!["-i", ssh_key_path.to_str().unwrap(), "-p", &port];
        ssh_args.extend_from_slice(crate::crypto::SSH_FAST_ARGS);
        ssh_args.extend_from_slice(&[&user_host as &str, &write_cmd as &str]);

        let mut child = std::process::Command::new("ssh")
            .args(&ssh_args)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("[{}] ssh not found: {}", label, e))?;
        let status = crate::crypto::pipe_file_to_process(&mut src_file, &mut child, size, label)
            .map_err(|e| format!("[{}] pipe error: {}", label, e))?;

        if status.success() {
            break;
        }

        if attempt >= max_attempts {
            return Err(
                format!("[{}] ssh push failed after {} attempts (exit {:?})", label, max_attempts, status.code()).into(),
            );
        }

        tracing::info!(
            "  [{}] SSH push attempt {}/{} failed (exit {:?}) — retrying in 10s",
            label, attempt, max_attempts, status.code()
        );
        std::thread::sleep(std::time::Duration::from_secs(10));
    }

    tracing::info!("  [{}] Snapshot pushed to {}", label, remote_path);
    Ok(())
}

/// SSH into a running cosmos node and read its genesis.json file to `local_path`.
///
/// Genesis is small (KB-MB) so a simple `cat` is sufficient.
/// If `local_path` already exists and is non-empty, skips the fetch.
pub async fn fetch_genesis_from_node(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    remote_genesis_path: &str,
    local_path: &Path,
) -> Result<(), Box<dyn Error>> {
    if local_path.exists() && fs::metadata(local_path)?.len() > 0 {
        tracing::info!(
            "  [{}] Genesis cached at {:?} — skipping fetch.",
            label,
            local_path
        );
        return Ok(());
    }
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let (user_host, port) = ssh_user_host_port(endpoints, ssh_key_path, label)?;

    tracing::info!(
        "  [{}] Fetching genesis {} → {:?}",
        label,
        remote_genesis_path,
        local_path
    );

    let out_file = fs::File::create(local_path)
        .map_err(|e| format!("[{}] Cannot create {:?}: {}", label, local_path, e))?;

    let cat_cmd = format!("cat '{}'", remote_genesis_path);
    let mut ssh_args = vec!["-i", ssh_key_path.to_str().unwrap(), "-p", &port];
    ssh_args.extend_from_slice(crate::crypto::SSH_FAST_ARGS);
    ssh_args.extend_from_slice(&[&user_host as &str, &cat_cmd as &str]);

    let status = std::process::Command::new("ssh")
        .args(&ssh_args)
        .stdout(out_file)
        .status()
        .map_err(|e| format!("[{}] ssh not found: {}", label, e))?;

    if !status.success() {
        let _ = fs::remove_file(local_path);
        return Err(
            format!("[{}] genesis fetch failed (exit {:?})", label, status.code()).into(),
        );
    }

    tracing::info!(
        "  [{}] Genesis saved: {:?} ({} bytes)",
        label,
        local_path,
        fs::metadata(local_path)?.len()
    );
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract `(user@host, port)` strings from `endpoints` suitable for passing
/// to the system `ssh` binary.
fn ssh_user_host_port(
    endpoints: &[ServiceEndpoint],
    _ssh_key_path: &PathBuf,
    label: &str,
) -> Result<(String, String), Box<dyn Error>> {
    let ssh_port_env: u16 = var("SSH_PORT")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);

    let ep = endpoints
        .iter()
        .find(|e| e.internal_port == ssh_port_env)
        .ok_or_else(|| format!("[{}] No SSH endpoint for internal port {}", label, ssh_port_env))?;

    // ssh_dest_path → "ssh://root@host:port"
    let dest = ssh_dest_path(&ep.port.to_string(), &ep.uri);
    let stripped = dest.strip_prefix("ssh://").unwrap_or(&dest);

    // Split "root@host:port" → ("root@host", "port")
    let port = stripped
        .rfind(':')
        .map(|i| stripped[i + 1..].to_string())
        .unwrap_or_else(|| "22".to_string());
    let user_host = stripped
        .rfind(':')
        .map(|i| stripped[..i].to_string())
        .unwrap_or_else(|| stripped.to_string());

    Ok((user_host, port))
}
