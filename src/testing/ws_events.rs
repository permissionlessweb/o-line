//! CometBFT WebSocket event stream for proactive test assertions.
//!
//! [`WsEventStream`] connects to a CometBFT node's `/websocket` endpoint and
//! fans out parsed events to multiple subscribers via a `broadcast` channel.
//! The background reader task auto-reconnects on disconnect.
//!
//! # Event key format
//!
//! Akash market events appear in the CometBFT flat events map as:
//!   `"akash.market.v1beta5.EventOrderCreated.id.owner"` → `["akash1…"]`
//!   `"akash.market.v1beta5.EventBidCreated.id.dseq"`    → `["42"]`
//!
//! The exact package prefix varies across Akash versions.  All
//! [`CometEvent`] helpers use **suffix matching** (e.g. `EventOrderCreated.id.owner`)
//! to remain version-agnostic.

use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ── Public types ──────────────────────────────────────────────────────────────

/// Discriminates CometBFT subscription event types we care about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CometEventKind {
    /// `tm.event='NewBlock'`
    NewBlock,
    /// `tm.event='Tx'` — carries Akash market events as flat attributes.
    Tx,
}

/// A single event received from the CometBFT WebSocket.
#[derive(Debug, Clone)]
pub struct CometEvent {
    pub kind: CometEventKind,
    /// Block height at which the event occurred (0 if unknown).
    pub height: u64,
    /// Flat attributes map.  Multi-valued attributes have their first value stored here.
    ///
    /// Keys use the CometBFT format `"<proto.package.EventType.field.path>"`.
    /// The exact proto package prefix varies by Akash version — always use
    /// [`CometEvent::attr_suffix`] rather than exact key lookups.
    pub attrs: HashMap<String, String>,
}

impl CometEvent {
    /// Return the value for an exact key (seldom needed; prefer [`attr_suffix`]).
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(|s| s.as_str())
    }

    /// Return the first value whose key **ends with** `suffix`.
    ///
    /// Use this for Akash event attributes because the proto package prefix
    /// differs between chain versions:
    ///
    /// ```text
    /// akash.v1.EventOrderCreated.id.owner          // older
    /// akash.market.v1beta5.EventOrderCreated.id.owner  // newer
    /// ```
    ///
    /// Both are matched by `attr_suffix("EventOrderCreated.id.owner")`.
    pub fn attr_suffix(&self, suffix: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.ends_with(suffix))
            .map(|(_, v)| v.as_str())
    }

    /// True if this is a `tm.event='Tx'` event that carries Akash market data.
    pub fn is_akash_market_event(&self) -> bool {
        matches!(self.kind, CometEventKind::Tx)
            && self.attrs.keys().any(|k| k.contains("Event") && k.contains("akash"))
    }
}

/// A running CometBFT WebSocket subscription stream.
///
/// Connects to `ws://<host>:<port>/websocket` and subscribes to both
/// `NewBlock` and `Tx` events.  A background tokio task reads messages and
/// broadcasts parsed [`CometEvent`]s to all active receivers.
///
/// The background task is **aborted on Drop** so it does not outlive the
/// test or keep the tokio runtime alive.
pub struct WsEventStream {
    tx: broadcast::Sender<CometEvent>,
    _task: tokio::task::AbortHandle,
}

impl Drop for WsEventStream {
    fn drop(&mut self) {
        self._task.abort();
    }
}

impl WsEventStream {
    /// Connect to a CometBFT node and start the background event reader.
    ///
    /// `rpc_url` may be `"http://127.0.0.1:26657"`, `"https://…"`, or just
    /// `"127.0.0.1:26657"` — the scheme is replaced with `ws://`.
    pub async fn connect(rpc_url: &str) -> Result<Self, String> {
        let ws_url = rpc_to_ws_url(rpc_url);

        // Verify the endpoint is reachable — just the WebSocket handshake.
        // We do NOT subscribe here; subscribe_all() is called inside the
        // background task so reconnections also subscribe exactly once.
        let (ws, _) = connect_async(&ws_url)
            .await
            .map_err(|e| format!("WsEventStream: connect to {} failed: {}", ws_url, e))?;

        let (tx, _) = broadcast::channel::<CometEvent>(512);
        let tx2 = tx.clone();
        let handle = tokio::spawn(ws_reader_loop(ws_url, ws, tx2));

        tracing::debug!("WsEventStream connected");
        Ok(Self {
            tx,
            _task: handle.abort_handle(),
        })
    }

    /// Create a new receiver that captures all future events.
    ///
    /// **Create the receiver _before_ the activity you want to observe.**
    /// Events produced before `subscribe()` is called are not buffered for
    /// the new receiver (broadcast channel semantics).
    pub fn subscribe(&self) -> broadcast::Receiver<CometEvent> {
        self.tx.subscribe()
    }

    // ── Convenience waiters ───────────────────────────────────────────────────

    /// Block until the next `NewBlock` event arrives.
    ///
    /// Returns the block height.  Used in bid engines to poll the chain only
    /// when there is genuinely new state.
    pub async fn wait_for_next_block(&self, timeout_secs: u64) -> Result<u64, String> {
        let mut rx = self.tx.subscribe();
        tokio::time::timeout(Duration::from_secs(timeout_secs), async move {
            loop {
                match rx.recv().await {
                    Ok(ev) if ev.kind == CometEventKind::NewBlock => return Ok(ev.height),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "WS receiver lagged");
                    }
                    Err(e) => return Err(format!("WS channel: {}", e)),
                }
            }
        })
        .await
        .map_err(|_| "timeout waiting for NewBlock".to_string())?
    }

    /// Wait for `EventOrderCreated` where owner matches `deployer_addr`.
    ///
    /// Returns the `dseq` of the created order.  Uses suffix matching so it
    /// works across all Akash chain versions.
    pub async fn wait_for_order_created(
        &self,
        deployer_addr: &str,
        timeout_secs: u64,
    ) -> Result<u64, String> {
        self.wait_for_suffix_dseq(
            "EventOrderCreated.id.owner",
            deployer_addr,
            "EventOrderCreated.id.dseq",
            timeout_secs,
        )
        .await
    }

    /// Wait for `EventBidCreated` for the given `(owner, dseq)` pair.
    pub async fn wait_for_bid_created(
        &self,
        deployer_addr: &str,
        dseq: u64,
        timeout_secs: u64,
    ) -> Result<(), String> {
        self.wait_for_suffix_pair(
            "EventBidCreated.id.owner",
            deployer_addr,
            "EventBidCreated.id.dseq",
            dseq,
            timeout_secs,
        )
        .await
    }

    /// Wait for `EventLeaseCreated` for the given `(owner, dseq)` pair.
    pub async fn wait_for_lease_created(
        &self,
        deployer_addr: &str,
        dseq: u64,
        timeout_secs: u64,
    ) -> Result<(), String> {
        self.wait_for_suffix_pair(
            "EventLeaseCreated.id.owner",
            deployer_addr,
            "EventLeaseCreated.id.dseq",
            dseq,
            timeout_secs,
        )
        .await
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    async fn wait_for_suffix_dseq(
        &self,
        owner_suffix: &str,
        owner_val: &str,
        dseq_suffix: &str,
        timeout_secs: u64,
    ) -> Result<u64, String> {
        let owner_suffix = owner_suffix.to_owned();
        let owner_val = owner_val.to_owned();
        let dseq_suffix = dseq_suffix.to_owned();
        let err_suffix = owner_suffix.clone();
        let err_val = owner_val.clone();
        let mut rx = self.tx.subscribe();
        tokio::time::timeout(Duration::from_secs(timeout_secs), async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if ev.attr_suffix(&owner_suffix) == Some(&owner_val) {
                            if let Some(dseq) = ev
                                .attr_suffix(&dseq_suffix)
                                .and_then(|s| s.parse::<u64>().ok())
                            {
                                return Ok(dseq);
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "WS receiver lagged");
                    }
                    Err(e) => return Err(format!("WS channel: {}", e)),
                }
            }
        })
        .await
        .map_err(|_| format!("timeout waiting for *{}={}", err_suffix, err_val))?
    }

    async fn wait_for_suffix_pair(
        &self,
        owner_suffix: &str,
        owner_val: &str,
        dseq_suffix: &str,
        dseq: u64,
        timeout_secs: u64,
    ) -> Result<(), String> {
        let owner_suffix = owner_suffix.to_owned();
        let owner_val = owner_val.to_owned();
        let dseq_suffix = dseq_suffix.to_owned();
        let err_suffix = owner_suffix.clone();
        let err_val = owner_val.clone();
        let mut rx = self.tx.subscribe();
        tokio::time::timeout(Duration::from_secs(timeout_secs), async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        let owner_match = ev.attr_suffix(&owner_suffix) == Some(&owner_val);
                        let dseq_match = ev
                            .attr_suffix(&dseq_suffix)
                            .and_then(|s| s.parse::<u64>().ok())
                            == Some(dseq);
                        if owner_match && dseq_match {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "WS receiver lagged");
                    }
                    Err(e) => return Err(format!("WS channel: {}", e)),
                }
            }
        })
        .await
        .map_err(|_| {
            format!(
                "timeout waiting for *{}={} dseq={}",
                err_suffix, err_val, dseq
            )
        })?
    }
}

// ── Internal: URL conversion ──────────────────────────────────────────────────

fn rpc_to_ws_url(rpc: &str) -> String {
    let without_scheme = rpc
        .strip_prefix("https://")
        .or_else(|| rpc.strip_prefix("http://"))
        .unwrap_or(rpc);
    format!("ws://{}/websocket", without_scheme)
}

// ── Internal: WebSocket background task ──────────────────────────────────────

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

async fn subscribe_all(ws: &mut WsStream) -> Result<(), String> {
    ws.send(Message::Text(
        r#"{"jsonrpc":"2.0","id":1,"method":"subscribe","params":{"query":"tm.event='NewBlock'"}}"#
            .to_owned(),
    ))
    .await
    .map_err(|e| e.to_string())?;

    ws.send(Message::Text(
        r#"{"jsonrpc":"2.0","id":2,"method":"subscribe","params":{"query":"tm.event='Tx'"}}"#
            .to_owned(),
    ))
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

async fn ws_reader_loop(
    ws_url: String,
    initial_ws: WsStream,
    tx: broadcast::Sender<CometEvent>,
) {
    let mut current_ws = Some(initial_ws);

    loop {
        let ws = match current_ws.take() {
            Some(ws) => ws,
            None => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                match connect_async(&ws_url).await {
                    Ok((ws, _)) => ws,
                    Err(e) => {
                        tracing::warn!(url = %ws_url, error = %e, "WS reconnect failed");
                        continue;
                    }
                }
            }
        };

        if let Err(e) = read_until_closed(ws, &tx, &ws_url).await {
            tracing::warn!(url = %ws_url, error = %e, "WS reader exited — reconnecting");
        }
    }
}

async fn read_until_closed(
    mut ws: WsStream,
    tx: &broadcast::Sender<CometEvent>,
    ws_url: &str,
) -> Result<(), String> {
    subscribe_all(&mut ws)
        .await
        .map_err(|e| format!("subscribe failed on reconnect: {}", e))?;

    tracing::debug!(url = %ws_url, "WS reader active");

    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| format!("WS recv: {}", e))?;
        match msg {
            Message::Text(text) => {
                if let Some(ev) = parse_comet_event(&text) {
                    // Log every Tx event so the caller can see what Akash emits.
                    if ev.kind == CometEventKind::Tx && !ev.attrs.is_empty() {
                        let akash_keys: Vec<&str> = ev
                            .attrs
                            .keys()
                            .filter(|k| k.contains("akash") || k.contains("Event"))
                            .map(|k| k.as_str())
                            .collect();
                        if !akash_keys.is_empty() {
                            tracing::debug!(
                                height = ev.height,
                                keys = ?akash_keys,
                                "WS Tx event with Akash attributes"
                            );
                        }
                    }
                    let _ = tx.send(ev);
                }
            }
            Message::Close(_) => {
                tracing::debug!(url = %ws_url, "WS close frame received");
                return Ok(());
            }
            Message::Ping(payload) => {
                let _ = ws.send(Message::Pong(payload)).await;
            }
            _ => {}
        }
    }

    Ok(())
}

// ── Internal: JSON parsing ────────────────────────────────────────────────────

fn parse_comet_event(text: &str) -> Option<CometEvent> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    let result = json.get("result")?;

    // Subscription confirmations have no `data` field — skip them.
    let data = result.get("data")?;
    let events_obj = result.get("events")?.as_object()?;

    let event_type = events_obj
        .get("tm.event")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())?;

    let kind = match event_type {
        "NewBlock" => CometEventKind::NewBlock,
        "Tx" => CometEventKind::Tx,
        _ => return None,
    };

    let height: u64 = data
        .pointer("/value/block/header/height") // NewBlock
        .or_else(|| data.pointer("/value/TxResult/height")) // Tx
        .and_then(|h| h.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Flatten: first element of each array value.
    // Then expand any JSON-object values into dot-notation sub-keys so that
    // suffix matching on field paths works transparently.
    //
    // Akash events emit protobuf message fields as JSON objects, e.g.:
    //   "akash.market.v1.EventOrderCreated.id"
    //      → '{"owner":"akash1...","dseq":"9","gseq":1,"oseq":1}'
    // After expansion:
    //   "akash.market.v1.EventOrderCreated.id.owner" → "akash1..."
    //   "akash.market.v1.EventOrderCreated.id.dseq"  → "9"
    //   "akash.market.v1.EventOrderCreated.id.gseq"  → "1"
    let mut attrs: HashMap<String, String> = HashMap::new();

    for (k, v) in events_obj.iter() {
        let Some(val) = v.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()) else {
            continue;
        };
        // Store the raw value under the original key.
        attrs.insert(k.clone(), val.to_owned());

        // If the value is a JSON object, expand each field into a sub-key.
        if val.starts_with('{') {
            if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str(val) {
                for (field, field_val) in &obj {
                    let sub_key = format!("{}.{}", k, field);
                    let sub_val = match field_val {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        other => other.to_string(),
                    };
                    attrs.insert(sub_key, sub_val);
                }
            }
        }
    }

    Some(CometEvent { kind, height, attrs })
}
