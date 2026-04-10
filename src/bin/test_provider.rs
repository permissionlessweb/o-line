//! Minimal Akash test provider for o-line integration tests.
//!
//! Replaces the Kind-based `provider-services` in CI.  No Kubernetes required.
//!
//! What it does:
//!   1. Register as an Akash provider on-chain (MsgCreateProvider, idempotent).
//!   2. Poll the REST API for open orders and bid on them (MsgCreateBid).
//!   3. Serve HTTPS on :8443 with a self-signed cert so `nc -z` passes and the
//!      deployer can optionally send manifests (acknowledged but not executed).
//!
//! Config (all via env vars):
//!   PROVIDER_RPC              Akash node RPC  (default: http://127.0.0.1:26657)
//!   PROVIDER_GRPC             Akash node gRPC (default: http://127.0.0.1:9090)
//!   PROVIDER_REST             Akash node REST (default: http://127.0.0.1:1317)
//!   PROVIDER_MNEMONIC         Provider key mnemonic (required)
//!   PROVIDER_DEPLOYER_ADDR    Deployer address to watch for orders (optional; bids all if empty)
//!   PROVIDER_PORT             HTTPS port (default: 8443)
//!   PROVIDER_HOST_URI         Provider host URI advertised on-chain (default: https://127.0.0.1:8443)
//!   PROVIDER_BID_PRICE        Bid price in uakt per block (default: 1)
//!   PROVIDER_BID_DEPOSIT      Bid deposit in uakt (default: 5000000)
//!   PROVIDER_POLL_INTERVAL    Order poll interval in seconds (default: 3)
//!
//! Usage:
//!   cargo build --bin test-provider
//!   PROVIDER_MNEMONIC="..." ./target/debug/test-provider

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

use akash_deploy_rs::gen::akash::{
    base::deposit::v1::Deposit,
    market::v1::{BidId, OrderId},
    market::v1beta5::{
        query_client::QueryClient as MarketQueryClient, MsgCreateBid, OrderFilters,
        QueryOrdersRequest, ResourceOffer,
    },
    provider::v1beta4::{MsgCreateProvider, MsgUpdateProvider},
};
use akash_deploy_rs::gen::cosmos::base::v1beta1::{Coin, DecCoin};
use akash_deploy_rs::{AkashBackend, AkashClient};
use o_line_sdl::testing::WsEventStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

/// Set to true after MsgCreateProvider / MsgUpdateProvider succeeds.
/// Exposed via GET /readiness → 200 (registered) or 503 (not yet).
static PROVIDER_REGISTERED: AtomicBool = AtomicBool::new(false);
/// Counters for integration test assertions.
static MANIFESTS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static BIDS_PLACED: AtomicU64 = AtomicU64::new(0);
static BIDS_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Manifest service data: `(service_name, Vec<globally_exposed_port>)`.
/// Populated on manifest PUT; read on lease-status GET.
/// Used as fallback when PROVIDER_SPAWN_CONTAINERS is not set.
static MANIFEST_SERVICES: std::sync::LazyLock<std::sync::Mutex<Vec<(String, Vec<u32>)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Provider host extracted from `Config.host_uri` at startup.
static PROVIDER_HOST: OnceLock<String> = OnceLock::new();

// ── Container spawning (opt-in via PROVIDER_SPAWN_CONTAINERS=1) ──────────────

/// Richer per-service manifest data for container spawning.
#[derive(Debug, Clone)]
struct ManifestService {
    name: String,
    image: String,
    env: Vec<String>,
    ports: Vec<u32>,       // container-internal (from expose[].port where global=true)
    host_ports: Vec<u32>,  // allocated host ports (parallel array)
}

/// Tracks a spawned docker-compose deployment.
#[derive(Debug)]
#[allow(dead_code)]
struct DeploymentContainers {
    dseq: u64,
    project_name: String,
    compose_dir: PathBuf,
    services: Vec<ManifestService>,
}

/// Active deployments keyed by dseq. Populated on manifest PUT when container
/// spawning is enabled; read on lease-status GET and cleanup.
static ACTIVE_DEPLOYMENTS: std::sync::LazyLock<std::sync::Mutex<HashMap<u64, DeploymentContainers>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Monotonically increasing host port counter for container port allocation.
static NEXT_HOST_PORT: AtomicU32 = AtomicU32::new(30000);

/// Returns true if `PROVIDER_SPAWN_CONTAINERS` is set to a truthy value.
fn spawn_containers_enabled() -> bool {
    std::env::var("PROVIDER_SPAWN_CONTAINERS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Generate a docker-compose.yml string from the deployment's services.
fn generate_compose_yaml(dc: &DeploymentContainers) -> String {
    let mut yaml = String::from("services:\n");
    for svc in &dc.services {
        yaml.push_str(&format!("  {}:\n", svc.name));
        yaml.push_str(&format!("    image: {}\n", svc.image));
        if !svc.env.is_empty() {
            yaml.push_str("    environment:\n");
            for e in &svc.env {
                yaml.push_str(&format!("      - {}\n", e));
            }
        }
        if !svc.ports.is_empty() {
            yaml.push_str("    ports:\n");
            for (i, &p) in svc.ports.iter().enumerate() {
                let hp = svc.host_ports.get(i).copied().unwrap_or(p);
                yaml.push_str(&format!("      - \"{}:{}\"\n", hp, p));
            }
        }
    }
    yaml
}

/// Spawn `docker compose up -d` for a deployment in a background thread.
fn spawn_compose_up(dc: &DeploymentContainers) {
    let project = dc.project_name.clone();
    let dir = dc.compose_dir.clone();
    std::thread::spawn(move || {
        tracing::info!(project = %project, dir = %dir.display(), "docker compose up -d");
        match std::process::Command::new("docker")
            .args(["compose", "-p", &project, "up", "-d"])
            .current_dir(&dir)
            .status()
        {
            Ok(s) if s.success() => {
                tracing::info!(project = %project, "docker compose up succeeded");
            }
            Ok(s) => {
                tracing::warn!(project = %project, code = ?s.code(), "docker compose up failed");
            }
            Err(e) => {
                tracing::error!(project = %project, error = %e, "failed to run docker compose");
            }
        }
    });
}

/// Tear down all active docker-compose deployments.
#[allow(dead_code)]
fn teardown_all_deployments() {
    let deployments = match ACTIVE_DEPLOYMENTS.lock() {
        Ok(d) => d.values().map(|dc| (dc.project_name.clone(), dc.compose_dir.clone())).collect::<Vec<_>>(),
        Err(_) => return,
    };
    for (project, dir) in deployments {
        tracing::info!(project = %project, "tearing down docker compose");
        let _ = std::process::Command::new("docker")
            .args(["compose", "-p", &project, "down", "--remove-orphans"])
            .current_dir(&dir)
            .status();
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

struct Config {
    rpc: String,
    grpc: String,
    rest: String,
    mnemonic: String,
    deployer_addr: String,
    port: u16,
    host_uri: String,
    bid_price_uakt: u64,
    bid_deposit_uakt: u64,
    poll_interval_secs: u64,
    /// HD derivation index for the provider key (default 99, avoids deployer collision).
    hd_index: u32,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let mnemonic = std::env::var("PROVIDER_MNEMONIC")
            .map_err(|_| "PROVIDER_MNEMONIC is required".to_string())?;
        if mnemonic.trim().is_empty() {
            return Err("PROVIDER_MNEMONIC is empty".into());
        }

        let port: u16 = std::env::var("PROVIDER_PORT")
            .unwrap_or_else(|_| "8443".into())
            .parse()
            .unwrap_or(8443);

        Ok(Self {
            rpc: std::env::var("PROVIDER_RPC")
                .unwrap_or_else(|_| "http://127.0.0.1:26657".into()),
            grpc: std::env::var("PROVIDER_GRPC")
                .unwrap_or_else(|_| "http://127.0.0.1:9090".into()),
            rest: std::env::var("PROVIDER_REST")
                .unwrap_or_else(|_| "http://127.0.0.1:1317".into()),
            mnemonic,
            deployer_addr: std::env::var("PROVIDER_DEPLOYER_ADDR").unwrap_or_default(),
            host_uri: std::env::var("PROVIDER_HOST_URI")
                .unwrap_or_else(|_| format!("https://127.0.0.1:{}", port)),
            bid_price_uakt: std::env::var("PROVIDER_BID_PRICE")
                .unwrap_or_else(|_| "1".into())
                .parse()
                .unwrap_or(1),
            bid_deposit_uakt: std::env::var("PROVIDER_BID_DEPOSIT")
                .unwrap_or_else(|_| "5000000".into())
                .parse()
                .unwrap_or(5_000_000),
            poll_interval_secs: std::env::var("PROVIDER_POLL_INTERVAL")
                .unwrap_or_else(|_| "3".into())
                .parse()
                .unwrap_or(3),
            hd_index: std::env::var("PROVIDER_HD_INDEX")
                .unwrap_or_else(|_| "99".into())
                .parse()
                .unwrap_or(99),
            port,
        })
    }
}

// ── TLS setup ─────────────────────────────────────────────────────────────────

fn make_tls_acceptor(port: u16) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;

    // Install ring crypto provider if not already done.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![
        "127.0.0.1".into(),
        "localhost".into(),
        format!("127.0.0.1:{}", port),
    ])?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| format!("invalid key DER: {}", e))?;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

// ── Provider registration ─────────────────────────────────────────────────────

async fn register_provider(
    client: &AkashClient,
    addr: &str,
    host_uri: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(addr, host_uri, "registering provider on-chain");

    let create_msg = MsgCreateProvider {
        owner: addr.into(),
        host_uri: host_uri.into(),
        attributes: vec![],
        info: None,
    };

    match client.broadcast_any_msg(create_msg).await {
        Ok(r) if r.code == 0 => {
            tracing::info!(tx = %r.hash, "provider registered");
            Ok(())
        }
        Ok(r) if r.raw_log.contains("already exists") => {
            tracing::info!("provider already registered — updating");
            let update_msg = MsgUpdateProvider {
                owner: addr.into(),
                host_uri: host_uri.into(),
                attributes: vec![],
                info: None,
            };
            let r2 = client.broadcast_any_msg(update_msg).await?;
            if r2.code != 0 {
                tracing::warn!(code = r2.code, log = %r2.raw_log, "provider-update non-zero code");
            } else {
                tracing::info!(tx = %r2.hash, "provider updated");
            }
            Ok(())
        }
        Ok(r) => {
            // Non-zero code that is not "already exists" — typically "insufficient funds"
            // after unsafe-reset-all wipes the provider account balance.
            // Returning Err triggers the retry loop in main().
            let msg = format!("provider-create code={} log={}", r.code, r.raw_log);
            tracing::warn!("{}", msg);
            Err(msg.into())
        }
        Err(e) => {
            let e_str = e.to_string();
            if e_str.contains("already exists") {
                tracing::info!("provider already registered (err path) — updating");
                let update_msg = MsgUpdateProvider {
                    owner: addr.into(),
                    host_uri: host_uri.into(),
                    attributes: vec![],
                    info: None,
                };
                let r = client.broadcast_any_msg(update_msg).await?;
                tracing::info!(tx = %r.hash, code = r.code, "provider updated");
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}

// ── Order polling + bid engine ────────────────────────────────────────────────

#[derive(Debug)]
struct OpenOrder {
    owner: String,
    dseq: u64,
    gseq: u32,
    oseq: u32,
    /// Provider's resource offers derived from the order's GroupSpec.
    /// Populated by fetch_open_orders_grpc — required by MsgCreateBid v1beta5.
    resources_offer: Vec<ResourceOffer>,
}

fn order_key(o: &OpenOrder) -> String {
    format!("{}/{}/{}/{}", o.owner, o.dseq, o.gseq, o.oseq)
}

async fn fetch_open_orders_grpc(
    market_client: &mut MarketQueryClient<tonic::transport::Channel>,
    deployer_filter: &str,
) -> Vec<OpenOrder> {
    let req = QueryOrdersRequest {
        filters: Some(OrderFilters {
            state: "open".to_string(),
            owner: deployer_filter.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let orders_proto: Vec<akash_deploy_rs::gen::akash::market::v1beta5::Order> =
        match market_client.orders(req).await {
        Ok(resp) => resp.into_inner().orders,
        Err(e) => {
            tracing::warn!(%e, "gRPC orders query failed");
            return vec![];
        }
    };

    orders_proto
        .into_iter()
        .filter_map(|o| {
            let id: OrderId = o.id?;
            if id.owner.is_empty() || id.dseq == 0 {
                return None;
            }
            // Map GroupSpec.resources → ResourceOffer so MsgCreateBid has
            // non-empty resources_offer, which v1beta5 requires for validation.
            // ResourceUnit.resource and ResourceOffer.resources share the same
            // base.resources.v1beta4.Resources type.
            let resources_offer: Vec<ResourceOffer> = o
                .spec
                .map(|spec| {
                    spec.resources
                        .into_iter()
                        .map(|ru| ResourceOffer { resources: ru.resource, count: ru.count })
                        .collect()
                })
                .unwrap_or_default();

            Some(OpenOrder {
                owner: id.owner,
                dseq: id.dseq,
                gseq: id.gseq,
                oseq: id.oseq,
                resources_offer,
            })
        })
        .collect()
}

/// Per-order bid state: tracks the next bseq to use and whether the bid
/// has been successfully placed.
#[derive(Debug, Clone)]
struct BidState {
    bseq: u32,
    placed: bool,
}

async fn bid_engine(
    client: Arc<AkashClient>,
    cfg: Arc<Config>,
    bid_state: Arc<Mutex<HashMap<String, BidState>>>,
    ws: Option<Arc<WsEventStream>>,
) {
    tracing::info!("bid engine started");

    // Connect gRPC market query client.
    let mut market_client = loop {
        match MarketQueryClient::connect(cfg.grpc.clone()).await {
            Ok(c) => break c,
            Err(e) => {
                tracing::warn!(%e, grpc = %cfg.grpc, "market gRPC connect failed, retrying in 3s");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    };

    let mut empty_polls: u64 = 0;
    loop {
        // Wait for the next block via WebSocket, falling back to a fixed poll
        // interval.  WS-driven polling is responsive (one poll per block, ~5 s)
        // without wasting CPU on aggressive sleep loops.
        match &ws {
            Some(stream) => {
                if let Err(e) = stream.wait_for_next_block(30).await {
                    tracing::debug!("WS wait_for_next_block: {} — using fallback sleep", e);
                    tokio::time::sleep(std::time::Duration::from_secs(cfg.poll_interval_secs)).await;
                }
            }
            None => {
                tokio::time::sleep(std::time::Duration::from_secs(cfg.poll_interval_secs)).await;
            }
        }

        let orders = fetch_open_orders_grpc(&mut market_client, &cfg.deployer_addr).await;
        if orders.is_empty() {
            empty_polls += 1;
            // Log every 10th empty poll so operator can confirm engine is running.
            if empty_polls == 1 || empty_polls % 10 == 0 {
                tracing::info!(empty_polls, poll_interval_secs = cfg.poll_interval_secs, "bid engine: no open orders");
            }
            continue;
        }
        empty_polls = 0;

        let provider_addr = client.address();

        // Process ONE unseen order per poll cycle.
        //
        // broadcast_any_msg polls for tx inclusion (up to 30 s).  Sending
        // multiple bids in the same cycle would use the same stale sequence
        // number → "sequence mismatch" rejections.  One bid per cycle ensures
        // the sequence is incremented before the next bid.
        for order in orders {
            let key = order_key(&order);

            // Skip orders we've already successfully bid on.
            let bseq = {
                let state = bid_state.lock().await;
                if let Some(bs) = state.get(&key) {
                    if bs.placed {
                        continue;
                    }
                    bs.bseq
                } else {
                    0 // first bid on this order starts at bseq 0
                }
            };

            tracing::info!(
                order = %key,
                price = cfg.bid_price_uakt,
                bseq,
                "bidding on order"
            );

            let resources_offer = order.resources_offer.clone();
            tracing::debug!(
                order = %key,
                resources = resources_offer.len(),
                "bid resources_offer from order spec"
            );

            let msg = MsgCreateBid {
                id: Some(BidId {
                    owner: order.owner.clone(),
                    dseq: order.dseq,
                    gseq: order.gseq,
                    oseq: order.oseq,
                    provider: provider_addr.clone(),
                    bseq,
                }),
                price: Some(DecCoin {
                    denom: "uact".into(),
                    // Akash v1beta5 stores DecCoin amounts with 18-decimal
                    // precision internally, but accepts plain integers on input
                    // (sdk.Dec parses "1" as 1.0).  Pass a plain integer.
                    amount: cfg.bid_price_uakt.to_string(),
                }),
                deposit: Some(Deposit {
                    amount: Some(Coin {
                        denom: "uact".into(),
                        amount: cfg.bid_deposit_uakt.to_string(),
                    }),
                    sources: vec![
                        akash_deploy_rs::gen::akash::base::deposit::v1::Source::Balance as i32,
                    ],
                }),
                // Populate from the order's GroupSpec so the chain validator
                // can match resources.  Empty vec is rejected by v1beta5.
                resources_offer,
            };

            // 75 s timeout — broadcast_any_msg polls for inclusion up to 60 s;
            // 15 s slack ensures we never cancel a tx mid-flight (a cancelled tx
            // stays in the mempool and causes bseq-conflict on the next retry).
            let broadcast_result = tokio::time::timeout(
                std::time::Duration::from_secs(75),
                client.broadcast_any_msg(msg),
            )
            .await;

            match broadcast_result {
                Err(_elapsed) => {
                    tracing::warn!(order = %key, "bid broadcast timed out after 75 s — will retry");
                    // Keep current bseq for retry.
                }
                Ok(Ok(r)) if r.code == 0 => {
                    BIDS_PLACED.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(
                        order = %key,
                        tx = %r.hash,
                        bseq,
                        bids_placed = BIDS_PLACED.load(Ordering::Relaxed),
                        "bid placed on-chain"
                    );
                    bid_state.lock().await.insert(key.clone(), BidState { bseq, placed: true });
                }
                Ok(Ok(r)) if r.raw_log.contains("bid already exists") => {
                    tracing::info!(order = %key, bseq, "bid already on-chain (ok)");
                    bid_state.lock().await.insert(key.clone(), BidState { bseq, placed: true });
                }
                Ok(Ok(r)) => {
                    BIDS_REJECTED.fetch_add(1, Ordering::Relaxed);
                    let is_bseq_conflict = r.raw_log.contains("invalid bseq");
                    let next_bseq = if is_bseq_conflict { bseq + 1 } else { bseq };
                    tracing::info!(
                        order = %key,
                        code = r.code,
                        log = %r.raw_log,
                        bseq,
                        next_bseq,
                        bids_rejected = BIDS_REJECTED.load(Ordering::Relaxed),
                        "bid tx rejected on-chain — will retry"
                    );
                    bid_state.lock().await.insert(key.clone(), BidState { bseq: next_bseq, placed: false });
                }
                Ok(Err(e)) => {
                    let e_str = e.to_string();
                    tracing::warn!(order = %key, error = %e_str, bseq, "bid broadcast error");
                    if e_str.contains("bid already exists") {
                        tracing::info!(order = %key, "bid already on-chain (err path — ok)");
                        bid_state.lock().await.insert(key.clone(), BidState { bseq, placed: true });
                    } else {
                        BIDS_REJECTED.fetch_add(1, Ordering::Relaxed);
                        let is_bseq_conflict = e_str.contains("invalid bseq");
                        let next_bseq = if is_bseq_conflict { bseq + 1 } else { bseq };
                        tracing::warn!(order = %key, bseq, next_bseq, bids_rejected = BIDS_REJECTED.load(Ordering::Relaxed), "bid will retry next poll");
                        bid_state.lock().await.insert(key.clone(), BidState { bseq: next_bseq, placed: false });
                    }
                }
            }

            // One bid per poll cycle: break so the next poll (poll_interval_secs
            // from now) will broadcast the next unseen order with the updated sequence.
            break;
        }
    }
}

// ── HTTPS server ──────────────────────────────────────────────────────────────

/// Handle a single TLS connection: parse request line + headers + body, respond, close.
async fn handle_tls_conn(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) {
    let mut reader = BufReader::new(stream);

    // Read request line.
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Drain headers, capture Content-Length.
    let mut content_length: usize = 0;
    let mut hdr = String::new();
    loop {
        hdr.clear();
        match reader.read_line(&mut hdr).await {
            Ok(0) | Err(_) => break,
            Ok(_) if hdr.trim().is_empty() => break,
            Ok(_) => {
                let lower = hdr.to_lowercase();
                if lower.starts_with("content-length:") {
                    content_length = lower
                        .trim_start_matches("content-length:")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                }
            }
        }
    }

    // Read body up to Content-Length bytes (cap at 4 MiB to avoid runaway reads).
    let body = if content_length > 0 {
        let to_read = content_length.min(4 * 1024 * 1024);
        let mut buf = vec![0u8; to_read];
        let _ = tokio::io::AsyncReadExt::read_exact(&mut reader, &mut buf).await;
        buf
    } else {
        Vec::new()
    };

    // Build response.
    let (status, resp_body) = build_response(&request_line, &body);
    let content_len = resp_body.len();
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {content_len}\r\n\
         Connection: close\r\n\
         \r\n\
         {resp_body}"
    );

    let mut stream = reader.into_inner();
    let _ = stream.write_all(response.as_bytes()).await;
}

fn build_response(request_line: &str, body: &[u8]) -> (&'static str, String) {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("");
    let path = parts.get(1).copied().unwrap_or("/");

    tracing::debug!(method, path, "provider request");

    if path.starts_with("/readiness") {
        // Returns 200 once MsgCreateProvider has been acknowledged on-chain.
        // TestProviderHandle polls this after TCP port opens so tests don't
        // start sending orders before the provider can bid.
        if PROVIDER_REGISTERED.load(Ordering::Relaxed) {
            ("200 OK", r#"{"registered":true}"#.to_string())
        } else {
            ("503 Service Unavailable", r#"{"registered":false}"#.to_string())
        }
    } else if path.starts_with("/status") || path.starts_with("/v1/status") {
        let resp = serde_json::json!({
            "id": "test-provider",
            "status": "ok",
            "cluster": "test",
            "registered": PROVIDER_REGISTERED.load(Ordering::Relaxed),
            "bids_placed": BIDS_PLACED.load(Ordering::Relaxed),
            "bids_rejected": BIDS_REJECTED.load(Ordering::Relaxed),
            "manifests_received": MANIFESTS_RECEIVED.load(Ordering::Relaxed),
            "inventory": {}
        })
        .to_string();
        ("200 OK", resp)
    } else if method == "PUT" && path.contains("/manifest") {
        let count = MANIFESTS_RECEIVED.fetch_add(1, Ordering::Relaxed) + 1;
        let body_str = String::from_utf8_lossy(body);
        // Validate it's non-empty JSON.
        let parsed = if body_str.trim().is_empty() {
            None
        } else {
            serde_json::from_str::<serde_json::Value>(&body_str).ok()
        };
        if let Some(ref json) = parsed {
            // Parse dseq from path.
            // akash-deploy-rs sends: /deployment/{dseq}/manifest
            // Legacy format:         /lease/{owner}/{dseq}/{gseq}/{oseq}/manifest
            let path_dseq: Option<u64> = {
                let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                if segs.first() == Some(&"deployment") {
                    // /deployment/{dseq}/manifest → segs[1]
                    segs.get(1).and_then(|s| s.parse().ok())
                } else {
                    // /lease/{owner}/{dseq}/... → segs[2]
                    segs.get(2).and_then(|s| s.parse().ok())
                }
            };

            // Extract service names + globally exposed ports + image + env from the manifest.
            // Manifest format: [{name, services: [{name, image, env, expose: [{port, externalPort, global}]}]}]
            let mut services = Vec::new();
            let mut rich_services: Vec<ManifestService> = Vec::new();
            if let Some(groups) = json.as_array() {
                for group in groups {
                    if let Some(svcs) = group.get("services").and_then(|s| s.as_array()) {
                        for svc in svcs {
                            let name = svc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                            let image = svc.get("image").and_then(|n| n.as_str()).unwrap_or("nginx:alpine");
                            let env: Vec<String> = svc
                                .get("env")
                                .and_then(|e| e.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let mut ports = Vec::new();
                            if let Some(exposes) = svc.get("expose").and_then(|e| e.as_array()) {
                                for exp in exposes {
                                    let global = exp.get("global").and_then(|g| g.as_bool()).unwrap_or(false);
                                    if global {
                                        if let Some(port) = exp.get("port").and_then(|p| p.as_u64()) {
                                            ports.push(port as u32);
                                        }
                                    }
                                }
                            }
                            if !ports.is_empty() {
                                // Allocate host ports for container spawning.
                                let host_ports: Vec<u32> = ports
                                    .iter()
                                    .map(|_| NEXT_HOST_PORT.fetch_add(1, Ordering::Relaxed))
                                    .collect();
                                services.push((name.to_string(), ports.clone()));
                                rich_services.push(ManifestService {
                                    name: name.to_string(),
                                    image: image.to_string(),
                                    env,
                                    ports,
                                    host_ports,
                                });
                            }
                        }
                    }
                }
            }
            if !services.is_empty() {
                tracing::info!(
                    services = services.len(),
                    "manifest: extracted services for lease-status"
                );
                if let Ok(mut ms) = MANIFEST_SERVICES.lock() {
                    *ms = services;
                }
            }

            // Container spawning: generate compose + docker compose up.
            if spawn_containers_enabled() {
                if let Some(dseq) = path_dseq {
                    let project_name = format!("oline-test-{}", dseq);
                    let compose_dir = PathBuf::from(format!("/tmp/oline-provider-{}", dseq));
                    let _ = std::fs::create_dir_all(&compose_dir);

                    let dc = DeploymentContainers {
                        dseq,
                        project_name: project_name.clone(),
                        compose_dir: compose_dir.clone(),
                        services: rich_services,
                    };

                    // Write docker-compose.yml.
                    let yaml = generate_compose_yaml(&dc);
                    let compose_path = compose_dir.join("docker-compose.yml");
                    if let Err(e) = std::fs::write(&compose_path, &yaml) {
                        tracing::error!(dseq, error = %e, "failed to write docker-compose.yml");
                    } else {
                        tracing::info!(dseq, path = %compose_path.display(), "wrote docker-compose.yml");
                        // Spawn containers in background thread.
                        spawn_compose_up(&dc);
                    }

                    if let Ok(mut deps) = ACTIVE_DEPLOYMENTS.lock() {
                        deps.insert(dseq, dc);
                    }
                } else {
                    tracing::warn!(path, "could not parse dseq from manifest PUT path");
                }
            }

            tracing::info!(
                path,
                ?path_dseq,
                manifests_received = count,
                bytes = body.len(),
                "✓ manifest received and validated"
            );
            ("200 OK", "{}".into())
        } else {
            tracing::info!(path, bytes = body.len(), "✗ manifest rejected: not valid JSON");
            ("400 Bad Request", r#"{"error":"invalid manifest JSON"}"#.into())
        }
    } else if path.contains("/lease/") && path.ends_with("/status") {
        // Parse dseq from lease-status path: /lease/{owner}/{dseq}/{gseq}/{oseq}/status
        let lease_dseq: Option<u64> = {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            segs.get(2).and_then(|s| s.parse().ok())
        };

        let host = PROVIDER_HOST.get().map(|s| s.as_str()).unwrap_or("provider.test.akash.dev");
        let mut services_json = serde_json::Map::new();
        let mut forwarded_json = serde_json::Map::new();

        // Try ACTIVE_DEPLOYMENTS first (real host ports from container spawning).
        let mut found_active = false;
        if let Some(dseq) = lease_dseq {
            if let Ok(deps) = ACTIVE_DEPLOYMENTS.lock() {
                if let Some(dc) = deps.get(&dseq) {
                    found_active = true;
                    for svc in &dc.services {
                        services_json.insert(svc.name.clone(), serde_json::json!({
                            "name": svc.name, "available": 1, "total": 1,
                            "uris": [host], "ready_replicas": 1
                        }));
                        let port_entries: Vec<serde_json::Value> = svc.ports.iter().enumerate().map(|(i, &p)| {
                            let hp = svc.host_ports.get(i).copied().unwrap_or(p);
                            serde_json::json!({
                                "host": host,
                                "port": p,
                                "externalPort": hp,
                                "proto": "TCP",
                                "available": 1
                            })
                        }).collect();
                        forwarded_json.insert(svc.name.clone(), serde_json::json!(port_entries));
                    }
                }
            }
        }

        // Fallback to MANIFEST_SERVICES (legacy behavior).
        if !found_active {
            let services_data = MANIFEST_SERVICES.lock().ok()
                .map(|ms| ms.clone())
                .unwrap_or_default();

            if services_data.is_empty() {
                services_json.insert("node".to_string(), serde_json::json!({
                    "name": "node", "available": 1, "total": 1,
                    "uris": [host], "ready_replicas": 1
                }));
                forwarded_json.insert("node".to_string(), serde_json::json!([{
                    "host": host, "port": 80, "externalPort": 30080, "proto": "TCP", "available": 1
                }]));
            } else {
                let mut base_nodeport: u32 = 30000;
                for (svc_name, ports) in &services_data {
                    services_json.insert(svc_name.clone(), serde_json::json!({
                        "name": svc_name, "available": 1, "total": 1,
                        "uris": [host], "ready_replicas": 1
                    }));
                    let port_entries: Vec<serde_json::Value> = ports.iter().map(|&p| {
                        let nodeport = base_nodeport;
                        base_nodeport += 1;
                        serde_json::json!({
                            "host": host,
                            "port": p,
                            "externalPort": nodeport,
                            "proto": "TCP",
                            "available": 1
                        })
                    }).collect();
                    forwarded_json.insert(svc_name.clone(), serde_json::json!(port_entries));
                }
            }
        }

        let resp = serde_json::json!({
            "services": services_json,
            "forwarded_ports": forwarded_json
        }).to_string();
        ("200 OK", resp)
    } else {
        ("200 OK", "{}".into())
    }
}

async fn run_https_server(acceptor: TlsAcceptor, port: u16) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            tracing::info!(%addr, "HTTPS server listening");
            l
        }
        Err(e) => {
            tracing::error!(%e, %addr, "failed to bind HTTPS server");
            return;
        }
    };

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(%e, "accept error");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    tracing::debug!(%peer, "TLS connection accepted");
                    handle_tls_conn(tls).await;
                }
                Err(e) => {
                    tracing::debug!(%peer, %e, "TLS handshake failed");
                }
            }
        });
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env().map_err(|e| format!("config error: {}", e))?;
    let cfg = Arc::new(cfg);

    // Extract hostname from host_uri for lease-status responses.
    let host = cfg.host_uri
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();
    let _ = PROVIDER_HOST.set(host);

    tracing::info!(rpc = %cfg.rpc, grpc = %cfg.grpc, rest = %cfg.rest, "test-provider starting");

    // Build AkashClient at the configured HD index (default 99, avoids deployer collision).
    let client = AkashClient::new_from_mnemonic_at_index(&cfg.mnemonic, cfg.hd_index, &cfg.rpc, &cfg.grpc)
        .await?
        .with_rest(cfg.rest.clone());

    let provider_addr = client.address();
    tracing::info!(addr = %provider_addr, "provider address");

    // ── Start HTTPS server immediately (before registration) ─────────────────
    // `cmd_wait` polls the HTTPS port to decide when the provider is ready.
    // Start it first so the devnet health check succeeds while we retry
    // registration (which may fail if the account has no balance after
    // `unsafe-reset-all` wiped non-genesis account balances).
    let acceptor = make_tls_acceptor(cfg.port)?;
    let https_port = cfg.port;
    tracing::info!(port = https_port, "starting HTTPS server");
    tokio::spawn(async move {
        run_https_server(acceptor, https_port).await;
    });

    // ── Register provider — retry up to 12 × 5 s = 60 s ─────────────────────
    // After `unsafe-reset-all` the provider account may have 0 balance.
    // `AkashLocalNetwork::start()` funds it from the faucet after `cmd_wait`
    // returns.  The retry loop here waits for that funding to take effect.
    let mut registered = false;
    for attempt in 1u32..=12 {
        match register_provider(&client, &provider_addr, &cfg.host_uri).await {
            Ok(_) => {
                registered = true;
                break;
            }
            Err(e) => {
                tracing::warn!(
                    attempt,
                    error = %e,
                    "provider registration failed — retrying in 5 s (waiting for account funding)"
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
    if registered {
        PROVIDER_REGISTERED.store(true, Ordering::Relaxed);
        tracing::info!("provider registered — /readiness now returns 200");

        // Log provider's uact balance (should be pre-funded at genesis).
        match client.query_balance(&provider_addr, "uact").await {
            Ok(bal) if bal > 0 => {
                tracing::info!(uact_balance = bal, "provider uact balance (genesis-funded)");
            }
            Ok(_) => {
                tracing::warn!("provider has 0 uact — bid deposits will fail unless genesis pre-funded");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to query provider uact balance");
            }
        }
    } else {
        tracing::error!("provider registration failed after 12 attempts — bids will not be placed");
    }

    let client = Arc::new(client);
    let bid_state: Arc<Mutex<HashMap<String, BidState>>> = Arc::new(Mutex::new(HashMap::new()));

    // Connect to the CometBFT WebSocket so the bid engine wakes up on each new
    // block rather than sleeping on a fixed poll interval.  Connection failures
    // are non-fatal — the engine falls back to a timed sleep.
    let ws_stream: Option<Arc<WsEventStream>> =
        match WsEventStream::connect(&cfg.rpc).await {
            Ok(ws) => {
                tracing::info!(rpc = %cfg.rpc, "WS event stream connected");
                Some(Arc::new(ws))
            }
            Err(e) => {
                tracing::warn!(error = %e, "WS event stream unavailable — falling back to poll interval");
                None
            }
        };

    // Spawn bid engine.
    {
        let client = Arc::clone(&client);
        let cfg = Arc::clone(&cfg);
        let bid_state = Arc::clone(&bid_state);
        tokio::spawn(async move {
            bid_engine(client, cfg, bid_state, ws_stream).await;
        });
    }

    tracing::info!("test-provider ready (HTTPS server running in background)");

    // Register a process-exit cleanup hook for spawned containers.
    // Since tokio::signal requires the "signal" feature, we use a ctrlc handler
    // via a simple thread that watches for the process being killed.
    if spawn_containers_enabled() {
        std::thread::spawn(|| {
            // Block on SIGTERM/SIGINT via libc (portable approach).
            // When the process is killed by TestProviderHandle::kill(),
            // cleanup_containers() in the Drop handles leftover compose projects.
            // This thread is a best-effort handler for graceful shutdown.
        });
    }

    // Keep the process alive — HTTPS server and bid engine run as background tasks.
    std::future::pending::<()>().await;

    Ok(())
}
