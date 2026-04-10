//! `oline endpoints` — probe Akash RPC/gRPC endpoints and save the fastest to `.env`.
//!
//! Endpoints are discovered from the Cosmos Chain Registry (`akash/chain.json`) with
//! a hardcoded fallback list when the network is unavailable.  All probes run
//! concurrently so the full check completes in ~5 seconds regardless of list size.

use crate::{config::upsert_env_key, with_examples};
use std::{error::Error, time::Duration};
use tokio::time::Instant;

// ── Chain registry ────────────────────────────────────────────────────────────

const AKASH_CHAIN_REGISTRY: &str =
    "https://raw.githubusercontent.com/cosmos/chain-registry/master/akash/chain.json";

// ── Hardcoded fallback endpoints ──────────────────────────────────────────────

fn fallback_rpc() -> Vec<(&'static str, &'static str)> {
    vec![
        ("https://rpc.akashnet.net:443",                "Akash Network"),
        ("https://akash-rpc.polkachu.com:18252",         "Polkachu"),
        ("https://rpc-akash.ecostake.com:443",           "Ecostake"),
        ("https://akash-rpc.lavenderfive.com:443",       "Lavender.Five"),
        ("https://akash-mainnet-rpc.autostake.com:443",  "AutoStake"),
        ("https://rpc.akash.quokkastake.io:443",         "Quokka Stake"),
        ("https://akash.rpc.interblockchain.io:443",     "Interblockchain.io"),
    ]
}

fn fallback_grpc() -> Vec<(&'static str, &'static str)> {
    vec![
        ("grpc.akashnet.net:9090",              "Akash Network"),
        ("akash-grpc.lavenderfive.com:443",     "Lavender.Five"),
        ("akash-grpc.polkachu.com:18262",       "Polkachu"),
        ("grpc-akash.ecostake.com:9090",        "Ecostake"),
        ("akash.grpc.interblockchain.io:9443",  "Interblockchain.io"),
    ]
}

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct EndpointsArgs {
        #[command(subcommand)]
        pub cmd: Option<EndpointsSubcmd>,
    }
    => "../../docs/examples/endpoints.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum EndpointsSubcmd {
    /// Probe all endpoints and print the latency table (no .env changes)
    Check,
    /// Probe and write the fastest healthy endpoints to .env
    Save {
        /// Pin a specific RPC URL instead of selecting the fastest
        #[arg(long)]
        rpc: Option<String>,
        /// Pin a specific gRPC address instead of selecting the fastest
        #[arg(long)]
        grpc: Option<String>,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn cmd_endpoints(args: &EndpointsArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        None => run_check_and_prompt_save().await,
        Some(EndpointsSubcmd::Check) => {
            run_check().await;
            Ok(())
        }
        Some(EndpointsSubcmd::Save { rpc, grpc }) => {
            run_save(rpc.as_deref(), grpc.as_deref()).await
        }
    }
}

// ── Probe types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Endpoint {
    address: String,
    provider: String,
}

#[derive(Debug, Clone)]
struct ProbeResult {
    endpoint: Endpoint,
    latency_ms: Option<u64>,
}

impl ProbeResult {
    fn is_alive(&self) -> bool {
        self.latency_ms.is_some()
    }
}

// ── Endpoint discovery ────────────────────────────────────────────────────────

async fn fetch_registry_endpoints() -> (Vec<Endpoint>, Vec<Endpoint>) {
    let fetch = async {
        let body = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?
            .get(AKASH_CHAIN_REGISTRY)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let parse = |kind: &str| -> Vec<Endpoint> {
            body.pointer(&format!("/apis/{}", kind))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| {
                            let address = e.get("address")?.as_str()?.to_string();
                            let provider = e
                                .get("provider")
                                .and_then(|p| p.as_str())
                                .unwrap_or("Unknown")
                                .to_string();
                            Some(Endpoint { address, provider })
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        Ok::<_, Box<dyn Error>>(( parse("rpc"), parse("grpc") ))
    };

    match fetch.await {
        Ok((rpcs, grpcs)) if !rpcs.is_empty() => {
            tracing::info!(
                "  [registry] Fetched {} RPC + {} gRPC endpoints",
                rpcs.len(),
                grpcs.len()
            );
            (rpcs, grpcs)
        }
        Err(e) => {
            tracing::info!("  [registry] Fetch failed ({}), using fallback list.", e);
            (fallback_endpoints(fallback_rpc()), fallback_endpoints(fallback_grpc()))
        }
        Ok(_) => {
            tracing::info!("  [registry] Empty response, using fallback list.");
            (fallback_endpoints(fallback_rpc()), fallback_endpoints(fallback_grpc()))
        }
    }
}

fn fallback_endpoints(pairs: Vec<(&'static str, &'static str)>) -> Vec<Endpoint> {
    pairs
        .into_iter()
        .map(|(a, p)| Endpoint {
            address: a.to_string(),
            provider: p.to_string(),
        })
        .collect()
}

// ── Probing ───────────────────────────────────────────────────────────────────

/// Probe an RPC endpoint: GET `<url>/health` (Tendermint standard).
/// Falls back to `/status` if `/health` returns 5xx.
async fn probe_rpc(url: &str) -> Option<u64> {
    let clean = url.trim_end_matches('/');
    let start = Instant::now();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    // Try /health first (fast, 200 = alive)
    if let Ok(r) = client.get(format!("{}/health", clean)).send().await {
        if r.status().as_u16() < 500 {
            return Some(start.elapsed().as_millis() as u64);
        }
    }

    // Fallback: /status (always returns JSON on live nodes)
    let start2 = Instant::now();
    if let Ok(r) = client.get(format!("{}/status", clean)).send().await {
        if r.status().as_u16() < 500 {
            return Some(start2.elapsed().as_millis() as u64);
        }
    }

    None
}

/// Probe a gRPC endpoint via TCP connect.
/// Accepts `"https://host:port"`, `"host:port"`, or `"host:port"` formats.
async fn probe_grpc(addr: &str) -> Option<u64> {
    let start = Instant::now();
    let connect_target = grpc_tcp_addr(addr)?;

    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&connect_target),
    )
    .await
    {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}

/// Extract a `"host:port"` string from gRPC address variants.
fn grpc_tcp_addr(addr: &str) -> Option<String> {
    let stripped = addr
        .strip_prefix("https://")
        .or_else(|| addr.strip_prefix("http://"))
        .unwrap_or(addr)
        .trim_end_matches('/');

    if stripped.contains(':') {
        // Already "host:port"
        Some(stripped.to_string())
    } else {
        // bare hostname — default 9090
        Some(format!("{}:9090", stripped))
    }
}

// ── Probe runner ──────────────────────────────────────────────────────────────

async fn probe_all_rpc(endpoints: Vec<Endpoint>) -> Vec<ProbeResult> {
    let mut set = tokio::task::JoinSet::new();
    for ep in endpoints {
        let addr = ep.address.clone();
        set.spawn(async move {
            let latency_ms = probe_rpc(&addr).await;
            ProbeResult { endpoint: ep, latency_ms }
        });
    }
    let mut results: Vec<ProbeResult> = Vec::new();
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
    }
    results.sort_by_key(|r| r.latency_ms.unwrap_or(u64::MAX));
    results
}

async fn probe_all_grpc(endpoints: Vec<Endpoint>) -> Vec<ProbeResult> {
    let mut set = tokio::task::JoinSet::new();
    for ep in endpoints {
        let addr = ep.address.clone();
        set.spawn(async move {
            let latency_ms = probe_grpc(&addr).await;
            ProbeResult { endpoint: ep, latency_ms }
        });
    }
    let mut results: Vec<ProbeResult> = Vec::new();
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
    }
    results.sort_by_key(|r| r.latency_ms.unwrap_or(u64::MAX));
    results
}

// ── Display ───────────────────────────────────────────────────────────────────

fn print_results(label: &str, results: &[ProbeResult], current: Option<&str>) {
    tracing::info!("\n  {} Endpoints:", label);
    tracing::info!("  {:<3}  {:<6}  {:<50}  {}", "#", "ms", "Address", "Provider");
    tracing::info!("  {:-<80}", "");

    for (i, r) in results.iter().enumerate() {
        let current_marker = if current
            .map(|c| c.trim_end_matches('/') == r.endpoint.address.trim_end_matches('/'))
            .unwrap_or(false)
        {
            " ← current"
        } else {
            ""
        };

        match r.latency_ms {
            Some(ms) => tracing::info!(
                "  {:<3}  {:<6}  {:<50}  {}{}",
                i + 1,
                ms,
                r.endpoint.address,
                r.endpoint.provider,
                current_marker
            ),
            None => tracing::info!(
                "  {:<3}  {:<6}  {:<50}  {}{}",
                i + 1,
                "DEAD",
                r.endpoint.address,
                r.endpoint.provider,
                current_marker
            ),
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Run probes and return results.  Also prints the table.
async fn run_check() -> (Vec<ProbeResult>, Vec<ProbeResult>) {
    tracing::info!("\n=== Akash Endpoint Health Check ===\n");
    tracing::info!("  Fetching Akash chain registry...");
    let (rpc_eps, grpc_eps) = fetch_registry_endpoints().await;
    tracing::info!(
        "  Probing {} RPC + {} gRPC endpoints concurrently...",
        rpc_eps.len(),
        grpc_eps.len()
    );

    let current_rpc = std::env::var("OLINE_RPC_ENDPOINT").ok();
    let current_grpc = std::env::var("OLINE_GRPC_ENDPOINT").ok();

    let (rpc_results, grpc_results) =
        tokio::join!(probe_all_rpc(rpc_eps), probe_all_grpc(grpc_eps));

    print_results("RPC", &rpc_results, current_rpc.as_deref());
    print_results("gRPC", &grpc_results, current_grpc.as_deref());

    let alive_rpc = rpc_results.iter().filter(|r| r.is_alive()).count();
    let alive_grpc = grpc_results.iter().filter(|r| r.is_alive()).count();
    tracing::info!(
        "\n  {}/{} RPC alive,  {}/{} gRPC alive",
        alive_rpc,
        rpc_results.len(),
        alive_grpc,
        grpc_results.len()
    );

    (rpc_results, grpc_results)
}

async fn run_check_and_prompt_save() -> Result<(), Box<dyn Error>> {
    let (rpc_results, grpc_results) = run_check().await;

    let best_rpc = rpc_results.iter().find(|r| r.is_alive());
    let best_grpc = grpc_results.iter().find(|r| r.is_alive());

    if best_rpc.is_none() && best_grpc.is_none() {
        tracing::info!("\n  No alive endpoints found — check your internet connection.");
        return Ok(());
    }

    tracing::info!("\n  Fastest alive:");
    if let Some(r) = &best_rpc {
        tracing::info!(
            "    RPC:  {} ({}ms)",
            r.endpoint.address,
            r.latency_ms.unwrap_or(0)
        );
    }
    if let Some(r) = &best_grpc {
        tracing::info!(
            "    gRPC: {} ({}ms)",
            r.endpoint.address,
            r.latency_ms.unwrap_or(0)
        );
    }

    // Interactive prompt
    tracing::info!("\n  Save fastest endpoints to .env? [Y/n] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("n") {
        tracing::info!("  Not saved.");
        return Ok(());
    }

    save_to_env(
        best_rpc.map(|r| r.endpoint.address.as_str()),
        best_grpc.map(|r| r.endpoint.address.as_str()),
    )
}

async fn run_save(rpc: Option<&str>, grpc: Option<&str>) -> Result<(), Box<dyn Error>> {
    if rpc.is_some() || grpc.is_some() {
        // Explicit values: skip probe, write directly
        return save_to_env(rpc, grpc);
    }

    // No explicit values — probe and take fastest
    let (rpc_results, grpc_results) = run_check().await;

    let best_rpc = rpc_results.iter().find(|r| r.is_alive());
    let best_grpc = grpc_results.iter().find(|r| r.is_alive());

    if best_rpc.is_none() && best_grpc.is_none() {
        return Err("No alive endpoints found — cannot save to .env".into());
    }

    save_to_env(
        best_rpc.map(|r| r.endpoint.address.as_str()),
        best_grpc.map(|r| r.endpoint.address.as_str()),
    )
}

fn save_to_env(rpc: Option<&str>, grpc: Option<&str>) -> Result<(), Box<dyn Error>> {
    if let Some(url) = rpc {
        upsert_env_key("OLINE_RPC_ENDPOINT", url)?;
        tracing::info!("  Saved: OLINE_RPC_ENDPOINT={}", url);
    }
    if let Some(addr) = grpc {
        upsert_env_key("OLINE_GRPC_ENDPOINT", addr)?;
        tracing::info!("  Saved: OLINE_GRPC_ENDPOINT={}", addr);
    }
    tracing::info!("  .env updated — `oline deploy` will use these endpoints.");
    Ok(())
}
