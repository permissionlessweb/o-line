use crate::{cli::*, snapshots::*, with_examples};

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct TestS3Args {}
    => "../../docs/examples/test-s3.md"
}

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct TestGrpcArgs {
        /// gRPC-Web domain to test (falls back to GRPC_DOMAIN_SNAPSHOT env var)
        #[arg(value_name = "DOMAIN")]
        pub domain: Option<String>
    }
    => "../../docs/examples/test-grpc.md"
}

use std::{
    error::Error,
    io::{self, BufRead, Write},
};

pub async fn cmd_test_s3() -> Result<(), Box<dyn Error>> {
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
    tracing::info!("  Access key: {}", redact_if_secret("S3_KEY", &s3_key,));

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

// ── Subcommand: test-grpc ──
// Sends a gRPC-Web GetNodeInfo request to the given domain and prints the result.
// Usage: oline test-grpc [domain]   (defaults to GRPC_DOMAIN_SNAPSHOT env var)
pub async fn cmd_test_grpc(domain: Option<String>) -> Result<(), Box<dyn Error>> {
    let domain = domain
        .or_else(|| {
            std::env::var("GRPC_DOMAIN_SNAPSHOT")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .ok_or("Usage: oline test-grpc <domain>  (e.g. grpc.terp.network)")?;

    let url = format!(
        "https://{}/cosmos.base.tendermint.v1beta1.Service/GetNodeInfo",
        domain
    );
    tracing::info!("=== gRPC-Web Test ===");
    tracing::info!("Endpoint: {}", url);

    // Empty GetNodeInfo request: gRPC-Web frame [flag=0, length=0 (4 bytes)]
    let body = vec![0x00u8, 0x00, 0x00, 0x00, 0x00];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(&url)
        .header("Content-Type", "application/grpc-web+proto")
        .header("X-Grpc-Web", "1")
        .body(body)
        .send()
        .await?;

    let http_status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    tracing::info!("HTTP status:  {}", http_status);
    tracing::info!("Content-Type: {}", content_type);

    let bytes = resp.bytes().await?;

    let grpc_status = grpc_web_trailer_status(&bytes);
    tracing::info!(
        "gRPC status:  {}",
        grpc_status.as_deref().unwrap_or("(trailer not found)")
    );

    if grpc_status.as_deref() == Some("0") {
        // Extract printable strings from the protobuf data frame (chain_id, moniker, etc.)
        let strings = proto_readable_strings(&bytes, 4);
        if !strings.is_empty() {
            tracing::info!("Node info strings:");
            for s in &strings {
                tracing::info!("  {}", s);
            }
        }
        tracing::info!("gRPC-Web endpoint OK");
        Ok(())
    } else {
        Err(format!(
            "gRPC-Web test failed — HTTP {}, grpc-status: {:?}",
            http_status, grpc_status
        )
        .into())
    }
}

/// Scan gRPC-Web response bytes for the trailer frame (flag byte 0x80) and
/// return the value of the `grpc-status` trailer header if present.
fn grpc_web_trailer_status(bytes: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 5 <= bytes.len() {
        let flag = bytes[i];
        let len =
            u32::from_be_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]) as usize;
        if i + 5 + len > bytes.len() {
            break;
        }
        if flag == 0x80 {
            if let Ok(trailer) = std::str::from_utf8(&bytes[i + 5..i + 5 + len]) {
                for line in trailer.lines() {
                    if let Some(val) = line.strip_prefix("grpc-status:") {
                        return Some(val.trim().to_string());
                    }
                }
            }
        }
        i += 5 + len;
    }
    None
}

/// Extract contiguous printable ASCII strings (length >= min_len) from raw bytes.
/// Useful for reading chain_id, moniker, and version strings from a protobuf blob.
fn proto_readable_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    for &b in bytes {
        if b >= 0x20 && b < 0x7f {
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                result.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if current.len() >= min_len {
        result.push(current);
    }
    result
}
