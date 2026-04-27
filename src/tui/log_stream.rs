use std::collections::VecDeque;

use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

use crate::log_persistence::PersistLine;
use crate::providers::TrustedProviderStore;
use crate::sessions::OLineSession;
use crate::workflow::{
    context::OLineContext,
    step::DeployPhase,
};
use akash_deploy_rs::AkashBackend;

/// Maximum number of lines retained per service buffer.
pub const MAX_LINES: usize = 10_000;

/// Maximum reconnect attempts per collector before giving up.
const MAX_RECONNECTS: u32 = 10;

// ── Types ──────────────────────────────────────────────────────────────────────

/// Metadata needed to connect to one service's log WebSocket.
#[derive(Debug, Clone)]
pub struct LogTarget {
    /// Human-readable label shown in the tab bar (e.g. "A:snapshot").
    pub label: String,
    /// WebSocket URL: `wss://host/lease/{dseq}/{gseq}/{oseq}/logs?follow=true&tail=100&service={svc}`
    pub ws_url: String,
    /// JWT Bearer token for provider authentication.
    pub jwt: String,
    /// Optional proxy URL for routing WS connections through the provider-proxy-node.
    /// When set, connections go to `wss://{proxy_url}/proxy-ws?url={encoded_ws_url}`
    /// instead of directly to the provider.
    pub proxy_url: Option<String>,
}

/// A single log line delivered from a background collector task.
pub struct LogLine {
    /// Index into `App.log_buffers` identifying which service produced this line.
    pub service_index: usize,
    /// The raw log text.
    pub text: String,
}

/// Connection status for a single service's WebSocket.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnStatus {
    Connecting,
    Connected,
    Disconnected(String),
}

/// Per-service log buffer with connection status.
pub struct LogBuffer {
    pub label: String,
    pub lines: VecDeque<String>,
    pub status: ConnStatus,
}

impl LogBuffer {
    pub fn new(label: String) -> Self {
        Self {
            label,
            lines: VecDeque::with_capacity(1024),
            status: ConnStatus::Connecting,
        }
    }

    pub fn push(&mut self, line: String) {
        if self.lines.len() >= MAX_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }
}

// ── LogTarget construction ─────────────────────────────────────────────────────

/// Build log targets from deployed phases in the context.
///
/// For each successfully deployed phase, extracts dseq/gseq/oseq, jwt, and
/// provider host_uri, then enumerates unique service names from endpoints.
pub fn build_log_targets(ctx: &OLineContext) -> Vec<LogTarget> {
    let tp_store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    let mut targets = Vec::new();

    let phase_labels: &[(DeployPhase, &str)] = &[
        (DeployPhase::SpecialTeams, "A"),
        (DeployPhase::Tackles, "B"),
        (DeployPhase::Forwards, "C"),
        (DeployPhase::Relayer, "E"),
    ];

    for (phase, letter) in phase_labels {
        if !ctx.phase_deployed(phase) {
            continue;
        }

        let state = match ctx.state(phase.clone()) {
            Some(s) => s,
            None => continue,
        };

        let dseq = match state.dseq {
            Some(d) if d > 0 => d,
            _ => continue,
        };
        let gseq = state.gseq;
        let oseq = state.oseq;

        let jwt = match &state.jwt_token {
            Some(t) if !t.is_empty() => t.clone(),
            _ => continue,
        };

        let provider_addr = match &state.selected_provider {
            Some(p) => p.clone(),
            None => continue,
        };

        let host_uri = tp_store
            .find(&provider_addr)
            .map(|p| p.host_uri.clone())
            .or_else(|| ctx.provider_hosts.get(&provider_addr).cloned());

        let host = match &host_uri {
            Some(h) if !h.is_empty() => h.trim_end_matches('/'),
            _ => {
                tracing::warn!(
                    "TUI: no host_uri for provider {}, skipping phase {}",
                    provider_addr, letter
                );
                continue;
            }
        };
        let ws_host = host.replace("https://", "wss://");

        // Collect unique service names from endpoints
        let endpoints = ctx.endpoints(phase.clone());
        let mut seen = std::collections::HashSet::new();
        let mut service_names: Vec<String> = Vec::new();
        for ep in endpoints {
            if seen.insert(ep.service.clone()) {
                service_names.push(ep.service.clone());
            }
        }

        // If no endpoints, create a single target with no service filter
        if service_names.is_empty() {
            let ws_url = format!(
                "{}/lease/{}/{}/{}/logs?follow=true&tail=100",
                ws_host, dseq, gseq, oseq,
            );
            targets.push(LogTarget {
                label: format!("{}:{}", letter, phase.key()),
                ws_url,
                jwt: jwt.clone(),
                proxy_url: None,
            });
        } else {
            for svc in &service_names {
                let ws_url = format!(
                    "{}/lease/{}/{}/{}/logs?follow=true&tail=100&service={}",
                    ws_host, dseq, gseq, oseq, svc,
                );
                targets.push(LogTarget {
                    label: format!("{}:{}", letter, svc),
                    ws_url,
                    jwt: jwt.clone(),
                    proxy_url: None,
                });
            }
        }
    }

    targets
}

// ── Standalone LogTarget builder ─────────────────────────────────────────────

/// Build a single LogTarget for a service within a deployed phase.
///
/// `host_uri` is the provider's HTTPS URI (e.g. "https://provider.akash.network").
/// The scheme is replaced with `wss://` for the WebSocket connection.
pub fn make_log_target(
    label: &str,
    host_uri: &str,
    dseq: u64,
    gseq: u32,
    oseq: u32,
    service_name: &str,
    jwt: &str,
) -> LogTarget {
    let host = host_uri.trim_end_matches('/');
    let ws_host = host.replace("https://", "wss://");

    let ws_url = if service_name.is_empty() {
        format!(
            "{}/lease/{}/{}/{}/logs?follow=true&tail=100",
            ws_host, dseq, gseq, oseq,
        )
    } else {
        format!(
            "{}/lease/{}/{}/{}/logs?follow=true&tail=100&service={}",
            ws_host, dseq, gseq, oseq, service_name,
        )
    };

    LogTarget {
        label: label.to_string(),
        ws_url,
        jwt: jwt.to_string(),
        proxy_url: None,
    }
}

// ── Session-based LogTarget builder ──────────────────────────────────────────

/// Build log targets from a persisted session without requiring an OLineContext.
///
/// For each deployment entry in the session, resolves the provider host_uri
/// (from TrustedProviderStore or on-chain query), generates a JWT, and builds
/// one LogTarget per service (or a single unfiltered target if no services recorded).
pub async fn build_log_targets_from_session<B: AkashBackend>(
    session: &OLineSession,
    client: &B,
) -> Vec<LogTarget> {
    let tp_store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    let mut targets = Vec::new();

    let phase_letter = |phase: &str| -> &str {
        match phase {
            "special-teams" => "A",
            "tackles" => "B",
            "forwards" => "C",
            "relayer" => "E",
            _ => "?",
        }
    };

    // Generate JWT once for the session's master address.
    let jwt = match client.generate_jwt(&session.master_address).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to generate JWT for session {}: {}", session.id, e);
            return targets;
        }
    };

    for dep in &session.deployments {
        if dep.dseq == 0 {
            continue;
        }
        let provider_addr = match &dep.provider {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };

        let letter = phase_letter(&dep.phase);

        // Resolve host_uri: trusted store first, then on-chain query fallback.
        let host_uri = tp_store
            .find(provider_addr)
            .map(|p| p.host_uri.clone())
            .or_else(|| {
                // Attempt on-chain lookup — this is a synchronous context check,
                // so we do a blocking-compatible approach via the already-known data.
                None
            });

        // If not in trusted store, try on-chain query.
        let host_uri = match host_uri {
            Some(h) => h,
            None => {
                match client.query_provider_info(provider_addr).await {
                    Ok(Some(info)) => info.host_uri,
                    Ok(None) => {
                        tracing::warn!(
                            "TUI reconnect: provider {} not found on-chain, skipping phase {}",
                            provider_addr, letter
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "TUI reconnect: failed to query provider {}: {}, skipping phase {}",
                            provider_addr, e, letter
                        );
                        continue;
                    }
                }
            }
        };

        let host = host_uri.trim_end_matches('/');
        let ws_host = host.replace("https://", "wss://");

        if dep.services.is_empty() {
            let ws_url = format!(
                "{}/lease/{}/{}/{}/logs?follow=true&tail=100",
                ws_host, dep.dseq, dep.gseq, dep.oseq,
            );
            targets.push(LogTarget {
                label: format!("{}:{}", letter, dep.phase),
                ws_url,
                jwt: jwt.clone(),
                proxy_url: None,
            });
        } else {
            for svc in &dep.services {
                let ws_url = format!(
                    "{}/lease/{}/{}/{}/logs?follow=true&tail=100&service={}",
                    ws_host, dep.dseq, dep.gseq, dep.oseq, svc,
                );
                targets.push(LogTarget {
                    label: format!("{}:{}", letter, svc),
                    ws_url,
                    jwt: jwt.clone(),
                    proxy_url: None,
                });
            }
        }
    }

    targets
}

// ── WebSocket connection ───────────────────────────────────────────────────────

/// Spawn one background task per log target that streams WS messages into an mpsc channel.
///
/// Returns the receiver and join handles (for cleanup).
/// When `persist_tx` is provided, each log line is also sent to the persist channel.
pub fn spawn_log_collectors(
    targets: &[LogTarget],
    persist_tx: Option<mpsc::UnboundedSender<PersistLine>>,
) -> (mpsc::UnboundedReceiver<LogLine>, Vec<JoinHandle<()>>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut handles = Vec::with_capacity(targets.len());

    for (idx, target) in targets.iter().enumerate() {
        let tx = tx.clone();
        let persist_tx = persist_tx.clone();
        let ws_url = target.ws_url.clone();
        let jwt = target.jwt.clone();
        let label = target.label.clone();
        let proxy_url = target.proxy_url.clone();

        let handle = tokio::spawn(async move {
            let mut retries = 0u32;
            loop {
                match connect_and_stream_with_proxy(&ws_url, &jwt, idx, &tx, persist_tx.as_ref(), &label, proxy_url.as_deref()).await {
                    Ok(()) => break, // clean close
                    Err(e) => {
                        retries += 1;
                        if retries > MAX_RECONNECTS {
                            let _ = tx.send(LogLine {
                                service_index: idx,
                                text: format!("[{}] max reconnects exceeded: {}", label, e),
                            });
                            break;
                        }
                        let _ = tx.send(LogLine {
                            service_index: idx,
                            text: format!("[{}] reconnecting ({}/{}): {}", label, retries, MAX_RECONNECTS, e),
                        });
                        let backoff = std::time::Duration::from_secs(1 << retries.min(5));
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        });
        handles.push(handle);
    }

    (rx, handles)
}

/// Connect to a single WS endpoint, forward text messages to `tx`.
/// Returns `Ok(())` on clean close, `Err` on error.
///
/// When `persist_tx` is provided, each cleaned line is also sent to the
/// log persistence channel for writing to disk.
///
/// When `proxy_url` is provided (via the `LogTarget`), the connection is
/// routed through the provider-proxy-node at
/// `wss://{proxy_url}/proxy-ws?url={encoded_provider_ws_url}`.
/// If the proxy connection fails, falls back to direct provider connection.
pub async fn connect_and_stream(
    ws_url: &str,
    jwt: &str,
    service_index: usize,
    tx: &mpsc::UnboundedSender<LogLine>,
    persist_tx: Option<&mpsc::UnboundedSender<PersistLine>>,
    label: &str,
) -> Result<(), String> {
    connect_and_stream_with_proxy(ws_url, jwt, service_index, tx, persist_tx, label, None).await
}

/// Connect to a WS endpoint with optional proxy routing.
pub async fn connect_and_stream_with_proxy(
    ws_url: &str,
    jwt: &str,
    service_index: usize,
    tx: &mpsc::UnboundedSender<LogLine>,
    persist_tx: Option<&mpsc::UnboundedSender<PersistLine>>,
    label: &str,
    proxy_url: Option<&str>,
) -> Result<(), String> {
    // Try proxy connection first if configured
    if let Some(proxy) = proxy_url {
        let encoded_ws = crate::cli::urlencoded(ws_url);
        let proxy_host = proxy.trim_end_matches('/');
        let proxy_ws = format!(
            "{}/proxy-ws?url={}",
            proxy_host.replace("https://", "wss://").replace("http://", "ws://"),
            encoded_ws,
        );

        let mut req = proxy_ws
            .as_str()
            .into_client_request()
            .map_err(|e| format!("bad proxy WS URL: {e}"))?;
        req.headers_mut().insert(
            "Authorization",
            format!("Bearer {jwt}")
                .parse()
                .map_err(|e| format!("bad auth header: {e}"))?,
        );

        match tokio_tungstenite::connect_async(req).await {
            Ok((ws, _)) => {
                let _ = tx.send(LogLine {
                    service_index,
                    text: format!("[{}] connected via proxy", label),
                });
                return stream_ws_messages(ws, service_index, tx, persist_tx, label).await;
            }
            Err(e) => {
                let _ = tx.send(LogLine {
                    service_index,
                    text: format!("[{}] proxy failed ({}), falling back to direct", label, e),
                });
                // Fall through to direct connection
            }
        }
    }

    // Direct connection (default path)
    let mut req = ws_url
        .into_client_request()
        .map_err(|e| format!("bad WS URL: {e}"))?;
    req.headers_mut().insert(
        "Authorization",
        format!("Bearer {jwt}")
            .parse()
            .map_err(|e| format!("bad auth header: {e}"))?,
    );

    let (ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .map_err(|e| format!("WS connect: {e}"))?;

    stream_ws_messages(ws, service_index, tx, persist_tx, label).await
}

/// Stream WebSocket messages from an already-connected WS into the log channel.
async fn stream_ws_messages(
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    service_index: usize,
    tx: &mpsc::UnboundedSender<LogLine>,
    persist_tx: Option<&mpsc::UnboundedSender<PersistLine>>,
    label: &str,
) -> Result<(), String> {
    let (_, mut read) = ws.split();

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(line)) => {
                // Akash log lines may contain embedded newlines; split them.
                for l in line.lines() {
                    let cleaned = clean_log_line(l);
                    if let Some(ptx) = persist_tx {
                        let _ = ptx.send(PersistLine {
                            service: label.to_string(),
                            text: cleaned.clone(),
                        });
                    }
                    let _ = tx.send(LogLine {
                        service_index,
                        text: cleaned,
                    });
                }
            }
            Ok(Message::Close(_)) => return Ok(()),
            Err(e) => return Err(format!("WS read: {e}")),
            _ => {}
        }
    }

    Ok(())
}

/// Clean a raw Akash provider log line for TUI display.
///
/// Akash provider logs arrive as JSON: `{"name":"svc-pod","message":"..."}`.
/// Extract the message field and strip ANSI escape codes so the TUI renders
/// clean, readable text.
fn clean_log_line(raw: &str) -> String {
    let text = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(obj) => obj
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or(raw)
            .to_string(),
        Err(_) => raw.to_string(),
    };
    strip_ansi(&text)
}

/// Strip ANSI escape sequences (CSI codes like \x1b[...m).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Consume the CSI sequence: ESC [ ... (final byte 0x40-0x7E)
            if let Some(next) = chars.next() {
                if next == '[' {
                    // Skip until we hit a letter (the terminator)
                    for ch in chars.by_ref() {
                        if ch.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                // else: non-CSI escape, just skip the one char
            }
        } else {
            out.push(c);
        }
    }
    out
}
