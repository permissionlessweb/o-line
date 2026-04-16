//! HTTP file server + health endpoint + peer confirmation.
//!
//! Routes:
//!   GET  /ready            — 200 if all required resources fetched, 503 otherwise
//!   GET  /manifest         — JSON manifest with fetch results + SHA-256 digests
//!   GET  /files/<name>     — Stream a fetched file
//!   POST /confirm/<peer>   — Peer confirms it received all data
//!   GET  /status           — JSON status: confirmed peers, uptime, bytes served

use crate::fetch::FetchResult;
use axum::{
    Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Json},
    routing::{get, post},
};
use serde::Serialize;
use std::{
    collections::HashSet,
    sync::Arc,
    time::Instant,
};
use tokio::sync::RwLock;
use tracing::info;

/// Shared server state.
pub struct CourierState {
    pub fetch_results: Vec<FetchResult>,
    pub expected_peers: u32,
    pub confirmed: HashSet<String>,
    pub data_dir: String,
    pub started_at: Instant,
    pub bytes_served: u64,
}

impl CourierState {
    pub fn new(results: Vec<FetchResult>, expected_peers: u32, data_dir: String) -> Self {
        Self {
            fetch_results: results,
            expected_peers,
            confirmed: HashSet::new(),
            data_dir,
            started_at: Instant::now(),
            bytes_served: 0,
        }
    }

    pub fn confirmed_peers(&self) -> u32 {
        self.confirmed.len() as u32
    }

    pub fn all_required_ok(&self) -> bool {
        self.fetch_results
            .iter()
            .filter(|r| r.required)
            .all(|r| r.success)
    }
}

type SharedState = Arc<RwLock<CourierState>>;

/// Start the HTTP server.
pub async fn run(state: SharedState, addr: &str) {
    let app = Router::new()
        .route("/ready", get(handle_ready))
        .route("/manifest", get(handle_manifest))
        .route("/files/{*path}", get(handle_file))
        .route("/confirm/{peer}", post(handle_confirm))
        .route("/status", get(handle_status))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    info!("courier http server listening on {}", addr);
    axum::serve(listener, app).await.expect("server error");
}

// ── /ready ──
async fn handle_ready(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;
    if s.all_required_ok() {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

// ── /manifest ──
#[derive(Serialize)]
struct ManifestEntry {
    name: String,
    success: bool,
    required: bool,
    bytes: u64,
    sha256: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

async fn handle_manifest(State(state): State<SharedState>) -> Json<Vec<ManifestEntry>> {
    let s = state.read().await;
    let entries: Vec<_> = s
        .fetch_results
        .iter()
        .map(|r| ManifestEntry {
            name: r.name.clone(),
            success: r.success,
            required: r.required,
            bytes: r.bytes,
            sha256: r.sha256.clone(),
            error: r.error.clone(),
        })
        .collect();
    Json(entries)
}

// ── /files/<path> ──
async fn handle_file(
    State(state): State<SharedState>,
    Path(file_path): Path<String>,
) -> impl IntoResponse {
    let data_dir = {
        let s = state.read().await;
        s.data_dir.clone()
    };

    let full_path = std::path::Path::new(&data_dir).join(&file_path);

    // Security: prevent path traversal
    let canonical = match full_path.canonicalize() {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "not found\n").into_response(),
    };
    let data_canonical = match std::path::Path::new(&data_dir).canonicalize() {
        Ok(p) => p,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "server error\n").into_response(),
    };
    if !canonical.starts_with(&data_canonical) {
        return (StatusCode::FORBIDDEN, "forbidden\n").into_response();
    }

    // Read file and stream it
    let metadata = match tokio::fs::metadata(&canonical).await {
        Ok(m) => m,
        Err(_) => return (StatusCode::NOT_FOUND, "not found\n").into_response(),
    };

    if !metadata.is_file() {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }

    let file_size = metadata.len();

    // Determine content type from extension
    let content_type = match file_path.rsplit('.').next() {
        Some("json") => "application/json",
        Some("tar") => "application/x-tar",
        Some("gz") | Some("tgz") => "application/gzip",
        Some("lz4") => "application/x-lz4",
        Some("zst") | Some("zstd") => "application/zstd",
        Some("xz") => "application/x-xz",
        Some("so") => "application/x-sharedlib",
        Some("sh") => "text/x-shellscript",
        _ => "application/octet-stream",
    };

    // Stream the file using tokio_util::io::ReaderStream
    let file = match tokio::fs::File::open(&canonical).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "read error\n").into_response(),
    };

    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    // Track bytes served
    {
        let mut s = state.write().await;
        s.bytes_served += file_size;
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::CONTENT_LENGTH, file_size.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", file_path.rsplit('/').next().unwrap_or(&file_path)),
            ),
        ],
        body,
    )
        .into_response()
}

// ── /confirm/<peer> ──
async fn handle_confirm(
    State(state): State<SharedState>,
    Path(peer): Path<String>,
) -> impl IntoResponse {
    let mut s = state.write().await;
    let was_new = s.confirmed.insert(peer.clone());
    let count = s.confirmed.len() as u32;
    let expected = s.expected_peers;
    drop(s);

    if was_new {
        info!(
            "peer '{}' confirmed ({}/{})",
            peer, count, expected
        );
    }

    Json(serde_json::json!({
        "peer": peer,
        "confirmed": count,
        "expected": expected,
    }))
}

// ── /status ──
#[derive(Serialize)]
struct CourierStatus {
    ready: bool,
    uptime_secs: u64,
    resources_total: usize,
    resources_ok: usize,
    resources_failed: usize,
    bytes_served: u64,
    confirmed_peers: u32,
    expected_peers: u32,
    confirmed_peer_ids: Vec<String>,
}

async fn handle_status(State(state): State<SharedState>) -> Json<CourierStatus> {
    let s = state.read().await;
    Json(CourierStatus {
        ready: s.all_required_ok(),
        uptime_secs: s.started_at.elapsed().as_secs(),
        resources_total: s.fetch_results.len(),
        resources_ok: s.fetch_results.iter().filter(|r| r.success).count(),
        resources_failed: s.fetch_results.iter().filter(|r| !r.success).count(),
        bytes_served: s.bytes_served,
        confirmed_peers: s.confirmed.len() as u32,
        expected_peers: s.expected_peers,
        confirmed_peer_ids: s.confirmed.iter().cloned().collect(),
    })
}
