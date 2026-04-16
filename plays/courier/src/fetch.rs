//! Resource fetcher — downloads all manifest resources to disk.
//!
//! Streams large files (snapshots can be 10-50GB) to disk without
//! buffering the entire body in memory. Verifies SHA-256 if provided.

use crate::manifest::{Manifest, Resource};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// Result of fetching a single resource.
#[derive(Clone, Debug)]
pub struct FetchResult {
    pub name: String,
    pub success: bool,
    pub required: bool,
    pub bytes: u64,
    pub sha256: String,
    pub error: String,
}

/// Fetch all resources in the manifest concurrently (limited parallelism).
/// Large files (snapshot) are fetched sequentially to avoid OOM; small files
/// are fetched in parallel.
pub async fn fetch_all(manifest: &Manifest, data_dir: &str) -> Vec<FetchResult> {
    let mut results = Vec::with_capacity(manifest.resources.len());

    // Split into small (<100MB expected) and large resources.
    // Heuristic: snapshot files are large, everything else is small.
    let (small, large): (Vec<_>, Vec<_>) = manifest
        .resources
        .iter()
        .partition(|r| !is_likely_large(&r.name));

    // Fetch small files concurrently
    let small_futs: Vec<_> = small
        .iter()
        .map(|r| fetch_one(r, data_dir))
        .collect();
    let small_results = futures_util::future::join_all(small_futs).await;
    results.extend(small_results);

    // Fetch large files sequentially (streaming)
    for r in &large {
        results.push(fetch_one(r, data_dir).await);
    }

    results
}

/// Fetch a single resource, streaming to disk.
async fn fetch_one(resource: &Resource, data_dir: &str) -> FetchResult {
    let dest = Path::new(data_dir).join(&resource.name);

    // Create parent dirs for nested filenames (e.g. "cosmovisor/terpd")
    if let Some(parent) = dest.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return FetchResult {
                name: resource.name.clone(),
                success: false,
                required: resource.required,
                bytes: 0,
                sha256: String::new(),
                error: format!("mkdir failed: {}", e),
            };
        }
    }

    info!("fetching {} from {}", resource.name, resource.url);

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let resp = match client.get(&resource.url).send().await {
        Ok(r) => r,
        Err(e) => {
            return FetchResult {
                name: resource.name.clone(),
                success: false,
                required: resource.required,
                bytes: 0,
                sha256: String::new(),
                error: format!("request failed: {}", e),
            };
        }
    };

    if !resp.status().is_success() {
        return FetchResult {
            name: resource.name.clone(),
            success: false,
            required: resource.required,
            bytes: 0,
            sha256: String::new(),
            error: format!("HTTP {}", resp.status()),
        };
    }

    let content_length = resp.content_length();
    if let Some(len) = content_length {
        info!("  {} content-length: {} bytes ({:.1} MB)", resource.name, len, len as f64 / 1_048_576.0);
    }

    // Stream to file + compute SHA-256
    let mut file = match tokio::fs::File::create(&dest).await {
        Ok(f) => f,
        Err(e) => {
            return FetchResult {
                name: resource.name.clone(),
                success: false,
                required: resource.required,
                bytes: 0,
                sha256: String::new(),
                error: format!("create file failed: {}", e),
            };
        }
    };

    let mut hasher = Sha256::new();
    let mut total_bytes: u64 = 0;
    let mut stream = resp.bytes_stream();
    let mut last_progress = std::time::Instant::now();

    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if let Err(e) = file.write_all(&bytes).await {
                    return FetchResult {
                        name: resource.name.clone(),
                        success: false,
                        required: resource.required,
                        bytes: total_bytes,
                        sha256: String::new(),
                        error: format!("write failed at {} bytes: {}", total_bytes, e),
                    };
                }
                hasher.update(&bytes);
                total_bytes += bytes.len() as u64;

                // Progress logging every 30s for large files
                if last_progress.elapsed().as_secs() >= 30 {
                    let pct = content_length
                        .map(|cl| format!(" ({:.1}%)", (total_bytes as f64 / cl as f64) * 100.0))
                        .unwrap_or_default();
                    info!("  {} progress: {:.1} MB{}", resource.name, total_bytes as f64 / 1_048_576.0, pct);
                    last_progress = std::time::Instant::now();
                }
            }
            Err(e) => {
                return FetchResult {
                    name: resource.name.clone(),
                    success: false,
                    required: resource.required,
                    bytes: total_bytes,
                    sha256: String::new(),
                    error: format!("stream error at {} bytes: {}", total_bytes, e),
                };
            }
        }
    }

    if let Err(e) = file.flush().await {
        warn!("flush warning for {}: {}", resource.name, e);
    }

    let digest = hex::encode(hasher.finalize());

    // Verify SHA-256 if provided
    if !resource.sha256.is_empty() && digest != resource.sha256 {
        // Clean up the bad file
        let _ = tokio::fs::remove_file(&dest).await;
        return FetchResult {
            name: resource.name.clone(),
            success: false,
            required: resource.required,
            bytes: total_bytes,
            sha256: digest.clone(),
            error: format!(
                "SHA-256 mismatch: expected {} got {}",
                resource.sha256, digest
            ),
        };
    }

    info!(
        "  {} complete: {} bytes, sha256={}",
        resource.name, total_bytes, &digest[..12]
    );

    FetchResult {
        name: resource.name.clone(),
        success: true,
        required: resource.required,
        bytes: total_bytes,
        sha256: digest,
        error: String::new(),
    }
}

/// Heuristic: is this filename likely a large download (>100MB)?
fn is_likely_large(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("snapshot")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tar.lz4")
        || lower.ends_with(".tar.zst")
        || lower.ends_with(".tar.xz")
        || lower.ends_with(".tar")
        || lower.contains("genesis")
}
