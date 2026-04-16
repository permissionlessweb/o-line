//! oline-courier: ephemeral bootstrap fetcher for o-line node deployments.
//!
//! Fetches all required public resources once, serves them over HTTP to
//! internal Akash nodes, then shuts down once all peers confirm receipt.
//! The oline nodes never touch the public internet.

mod fetch;
mod manifest;
mod server;

use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::info;

use manifest::Manifest;
use server::CourierState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("oline-courier starting");

    // ── Build manifest from environment ──
    let manifest = Manifest::from_env();
    info!("manifest: {} resource(s) to fetch", manifest.resources.len());
    for r in &manifest.resources {
        info!("  {} → {} (required={})", r.name, r.url, r.required);
    }

    // ── Fetch phase ──
    let data_dir = std::env::var("COURIER_DATA_DIR").unwrap_or_else(|_| "/srv/bootstrap".into());
    tokio::fs::create_dir_all(&data_dir).await?;

    let results = fetch::fetch_all(&manifest, &data_dir).await;
    let (ok, failed): (Vec<_>, Vec<_>) = results.iter().partition(|r| r.success);
    info!(
        "fetch complete: {} succeeded, {} failed",
        ok.len(),
        failed.len()
    );

    // Abort if any required resource failed
    let required_failures: Vec<_> = failed
        .iter()
        .filter(|r| r.required)
        .collect();
    if !required_failures.is_empty() {
        for f in &required_failures {
            tracing::error!("required resource failed: {} — {}", f.name, f.error);
        }
        return Err(format!(
            "{} required resource(s) failed to fetch",
            required_failures.len()
        )
        .into());
    }

    // ── Build state for HTTP server ──
    let expected_peers: u32 = std::env::var("COURIER_EXPECTED_PEERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let shutdown_timeout_secs: u64 = std::env::var("COURIER_SHUTDOWN_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600); // default 1 hour

    let state = Arc::new(RwLock::new(CourierState::new(
        results,
        expected_peers,
        data_dir.clone(),
    )));

    // ── Serve phase ──
    let port: u16 = std::env::var("COURIER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    let addr = format!("0.0.0.0:{}", port);
    info!("serving files from {} on {}", data_dir, addr);
    if expected_peers > 0 {
        info!(
            "will shut down after {} peer(s) confirm receipt (timeout: {}s)",
            expected_peers, shutdown_timeout_secs
        );
    } else {
        info!("no expected peers set — serving until timeout ({}s)", shutdown_timeout_secs);
    }

    let server_state = state.clone();
    let server_handle = tokio::spawn(async move {
        server::run(server_state, &addr).await
    });

    // ── Shutdown logic ──
    // Wait for: all peers confirmed OR timeout OR SIGTERM
    let shutdown_state = state.clone();
    tokio::select! {
        _ = wait_for_peers(shutdown_state, expected_peers) => {
            info!("all peers confirmed — initiating graceful shutdown");
        }
        _ = tokio::time::sleep(Duration::from_secs(shutdown_timeout_secs)) => {
            info!("shutdown timeout reached ({}s) — shutting down", shutdown_timeout_secs);
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT — shutting down");
        }
    }

    // Give in-flight downloads a moment to complete
    info!("draining connections (5s grace period)...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    server_handle.abort();
    info!("courier shut down");
    Ok(())
}

/// Poll until confirmed_peers >= expected_peers.
/// Returns immediately if expected_peers == 0.
async fn wait_for_peers(state: Arc<RwLock<CourierState>>, expected: u32) {
    if expected == 0 {
        // No peer tracking — run until timeout
        std::future::pending::<()>().await;
    }
    loop {
        {
            let s = state.read().await;
            if s.confirmed_peers() >= expected {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
