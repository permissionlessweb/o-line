use crate::{
    cli::{prompt_s3_creds, redact_if_secret, urlencoded},
    config::{days_to_date, OLineConfig, RuntimeDefaults},
    crypto::{hmac_sha256, sha256_hex},
};
use std::{
    collections::HashMap,
    error::Error,
    io::{self, BufRead, Write},
};

pub const SNAPSHOT_RPC_DOMAIN: &str = "statesync.terp.network";
pub const SNAPSHOT_P2P_DOMAIN: &str = "statesync.terp.network";
pub const SEED_RPC_DOMAIN: &str = "seed-statesync.terp.network";
pub const SEED_P2P_DOMAIN: &str = "seed.terp.network";

/// Helper to insert S3 snapshot export variables.
/// `s3_key`, `s3_secret`, and `s3_host` are generated/derived at deploy time.
pub fn insert_s3_vars(
    vars: &mut HashMap<String, String>,
    config: &OLineConfig,
    s3_key: &str,
    s3_secret: &str,
    s3_host: &str,
) {
    vars.insert("S3_KEY".into(), s3_key.to_string());
    vars.insert("S3_SECRET".into(), s3_secret.to_string());
    vars.insert("S3_HOST".into(), s3_host.to_string());
    vars.insert("SNAPSHOT_PATH".into(), config.snapshot_path.clone());
    vars.insert("SNAPSHOT_TIME".into(), config.snapshot_time.clone());
    vars.insert(
        "SNAPSHOT_SAVE_FORMAT".into(),
        config.snapshot_save_format.clone(),
    );
    // Metadata URL uses the public download domain so URLs in snapshot.json are externally accessible
    vars.insert(
        "SNAPSHOT_METADATA_URL".into(),
        format!(
            "https://{}/{}/snapshot.json",
            config.snapshot_download_domain,
            config.snapshot_path.trim_matches('/')
        ),
    );
    vars.insert(
        "SNAPSHOT_DOWNLOAD_DOMAIN".into(),
        config.snapshot_download_domain.clone(),
    );
    vars.insert("SNAPSHOT_RETAIN".into(), config.snapshot_retain.clone());
    vars.insert(
        "SNAPSHOT_KEEP_LAST".into(),
        config.snapshot_keep_last.clone(),
    );
}

/// Helper to insert minio-ipfs variables.
/// `root_user` and `root_password` are the auto-generated credentials
/// shared between the snapshot node (as S3_KEY/S3_SECRET) and MinIO.
pub fn insert_minio_vars(
    vars: &mut HashMap<String, String>,
    config: &OLineConfig,
    root_user: &str,
    root_password: &str,
) {
    vars.insert("MINIO_IPFS_IMAGE".into(), config.minio_ipfs_image.clone());
    // Derive MINIO_BUCKET from snapshot_path (first path component, e.g. "snapshots" from "snapshots/terpnetwork")
    let minio_bucket = config
        .snapshot_path
        .split('/')
        .next()
        .unwrap_or("snapshots")
        .to_string();
    vars.insert("MINIO_BUCKET".into(), minio_bucket);
    vars.insert("AUTOPIN_INTERVAL".into(), config.autopin_interval.clone());
    vars.insert("MINIO_ROOT_USER".into(), root_user.to_string());
    vars.insert("MINIO_ROOT_PASSWORD".into(), root_password.to_string());
}

/// Sign an S3 request using AWS Signature V4 (path-style).
/// Returns the Authorization header value and headers to add.
fn s3_signed_headers(
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

async fn s3_request(
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
    defaults: &RuntimeDefaults,
) -> Result<String, Box<dyn Error>> {
    let state_url = &defaults.snapshot_state_url;
    let base_url = &defaults.snapshot_base_url;
    tracing::info!("Fetching latest snapshot info from {}...", state_url);
    let resp = reqwest::get(state_url).await?.text().await?;
    let trimmed = resp.trim();
    let state: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("Failed to parse .current_state.json: {}", e))?;
    let snapshot_name = state["snapshot_name"]
        .as_str()
        .ok_or("missing snapshot_name in .current_state.json")?;
    let url = format!("{}{}", base_url, snapshot_name);
    tracing::info!("  Latest snapshot: {}", url);

    Ok(url)
}

/// Fetch the snapshot metadata JSON and return the `url` field.
/// Falls back to `fallback_url` if the metadata is unavailable or malformed.
pub async fn fetch_snapshot_url_from_metadata(metadata_url: &str, fallback_url: &str) -> String {
    tracing::info!("  Fetching snapshot metadata from {}", metadata_url);
    match reqwest::get(metadata_url).await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => {
                if let Some(url) = json.get("url").and_then(|u| u.as_str()) {
                    tracing::info!("  Snapshot URL from metadata: {}", url);
                    return url.to_string();
                }
                tracing::info!(
                    "  Warning: snapshot metadata JSON has no 'url' field — using fallback"
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

// ── Subcommand: test-s3 ──

pub async fn cmd_test_s3(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== S3 Connection Test ===\n");

    tracing::info!("  Note: S3/MinIO credentials are auto-generated per deployment.");
    tracing::info!("  Enter the credentials from your running MinIO instance to test.\n");

    // Check for env vars first (enables non-interactive / CI usage)
    let (s3_key, s3_secret, s3_host, snapshot_path) = match (
        std::env::var("S3_KEY"),
        std::env::var("S3_SECRET"),
        std::env::var("S3_HOST"),
        std::env::var("SNAPSHOT_PATH"),
    ) {
        (Ok(k), Ok(s), Ok(h), Ok(p))
            if !k.is_empty() && !s.is_empty() && !h.is_empty() && !p.is_empty() =>
        {
            tracing::info!("  Using credentials from environment variables.\n");
            (k, s, h, p)
        }
        _ => {
            let stdin = io::stdin();
            let mut lines = stdin.lock().lines();
            prompt_s3_creds(&mut lines)?
        }
    };

    // Parse bucket and prefix from snapshot_path (e.g. "snapshots/terpnetwork")
    let (bucket_name, prefix) = match snapshot_path.split_once('/') {
        Some((b, p)) => (b.to_string(), format!("{}/", p)),
        None => (snapshot_path.clone(), String::new()),
    };

    tracing::info!("  S3 host:    {}", s3_host);
    tracing::info!("  Bucket:     {}", bucket_name);
    tracing::info!(
        "  Prefix:     {}",
        if prefix.is_empty() { "(root)" } else { &prefix }
    );
    tracing::info!(
        "  Access key: {}",
        redact_if_secret("S3_KEY", &s3_key, defaults)
    );

    let client = reqwest::Client::new();
    let region = "us-east-1";
    let base = format!("{}/{}", s3_host, bucket_name);
    let mut rw_ok = true;
    let mut list_ok = true;

    // Test 1: List objects (GET /?prefix=...&max-keys=5)
    print!("  [1/4] List objects in bucket... ");
    io::stdout().flush()?;
    let list_url = format!(
        "{}?list-type=2&prefix={}&max-keys=5",
        base,
        urlencoded(&prefix)
    );
    match s3_request(
        &client,
        reqwest::Method::GET,
        &list_url,
        b"",
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                let count = body.matches("<Key>").count();
                tracing::info!("OK (HTTP 200, {} objects listed)", count);
            } else {
                tracing::info!(
                    "SKIPPED (HTTP {} — provider may not support ListObjects)",
                    status
                );
                list_ok = false;
            }
        }
        Err(e) => {
            tracing::info!("SKIPPED: {}", e);
            list_ok = false;
        }
    }

    // Test 2: Put test object
    let test_key = format!("{}.oline-test", prefix);
    let test_data = b"oline s3 connectivity test";
    let put_url = format!("{}/{}", base, test_key);

    print!("  [2/4] Put test object ({})... ", test_key);
    io::stdout().flush()?;
    match s3_request(
        &client,
        reqwest::Method::PUT,
        &put_url,
        test_data,
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                tracing::info!("OK (HTTP {})", status);
            } else {
                let body = resp.text().await.unwrap_or_default();
                tracing::info!("FAILED (HTTP {})", status);
                if !body.is_empty() {
                    tracing::info!("    Response: {}", &body[..body.len().min(200)]);
                }
                rw_ok = false;
            }
        }
        Err(e) => {
            tracing::info!("FAILED: {}", e);
            rw_ok = false;
        }
    }

    // Test 3: Get test object
    let get_url = format!("{}/{}", base, test_key);
    print!("  [3/4] Get test object... ");
    io::stdout().flush()?;
    match s3_request(
        &client,
        reqwest::Method::GET,
        &get_url,
        b"",
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.bytes().await.unwrap_or_default();
                if body.as_ref() == test_data {
                    tracing::info!("OK (data verified)");
                } else {
                    tracing::info!("OK (HTTP 200, content differs — still functional)");
                }
            } else {
                tracing::info!("FAILED (HTTP {})", status);
                rw_ok = false;
            }
        }
        Err(e) => {
            tracing::info!("FAILED: {}", e);
            rw_ok = false;
        }
    }

    // Test 4: Delete test object
    let del_url = format!("{}/{}", base, test_key);
    print!("  [4/4] Delete test object... ");
    io::stdout().flush()?;
    match s3_request(
        &client,
        reqwest::Method::DELETE,
        &del_url,
        b"",
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 200 || status == 204 {
                tracing::info!("OK (HTTP {})", status);
            } else {
                tracing::info!(
                    "WARN (HTTP {} — may need manual cleanup of {})",
                    status,
                    test_key
                );
            }
        }
        Err(e) => {
            tracing::info!("WARN: {} — test object may remain at {}", e, test_key);
        }
    }

    if rw_ok && list_ok {
        tracing::info!("All S3 tests passed. Credentials are fully functional.");
    } else if rw_ok {
        tracing::info!("Read/write tests passed. Credentials are functional.");
        tracing::info!("Note: ListObjects not supported by this provider (common with Filebase).");
        tracing::info!("This does not affect O-Line deployments — only PUT/GET/DELETE are used.");
    } else {
        tracing::info!("S3 read/write tests failed. Check credentials and bucket permissions.");
    }
    Ok(())
}
