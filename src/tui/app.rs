use std::collections::VecDeque;
use std::io::{self, stdout};
use std::path::PathBuf;
use std::sync::Arc;

use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::prelude::CrosstermBackend;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use super::log_stream::{build_log_targets, ConnStatus, LogBuffer, LogLine, LogTarget};
use super::ui;
use crate::nodes::NodeStore;
use crate::workflow::context::OLineContext;

/// Page-scroll jump size.
const PAGE_SCROLL_LINES: usize = 20;

// ── SSH target ─────────────────────────────────────────────────────────────────

/// SSH connection metadata for the `s` hotkey.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub label: String,
    pub host: String,
    pub port: String,
    pub ssh_key_path: PathBuf,
}

// ── TuiController ──────────────────────────────────────────────────────────────

/// Shared handle between the deploy flow (producer) and TUI (consumer).
///
/// The deploy flow pushes `LogTarget`s and `SshTarget`s as phases complete.
/// The TUI drains pending targets and spawns WebSocket collectors.
#[derive(Clone)]
pub struct TuiController {
    inner: Arc<Mutex<TuiControllerInner>>,
}

struct TuiControllerInner {
    pending_targets: Vec<LogTarget>,
    ssh_targets: Vec<SshTarget>,
    /// Active collectors: (receiver, join handles).
    collector: Option<(mpsc::UnboundedReceiver<LogLine>, Vec<JoinHandle<()>>)>,
    /// All log buffers (shared between collector and TUI).
    log_buffers: Vec<LogBuffer>,
}

impl TuiController {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TuiControllerInner {
                pending_targets: Vec::new(),
                ssh_targets: Vec::new(),
                collector: None,
                log_buffers: Vec::new(),
            })),
        }
    }

    /// Build a TuiController pre-populated from an OLineContext (for backward compat).
    pub fn from_context(ctx: &OLineContext) -> Self {
        let targets = build_log_targets(ctx);
        let ctrl = Self::new();

        // Synchronous population — no tokio runtime needed since we own the lock.
        let mut inner = ctrl.inner.try_lock().unwrap();

        // Load SSH targets from encrypted node store (best-effort, sync).
        load_ssh_targets_into(&mut inner.ssh_targets, &ctx.deployer.password, &[]);
        if !targets.is_empty() {
            let base_idx = inner.log_buffers.len();
            for t in &targets {
                inner.log_buffers.push(LogBuffer::new(t.label.clone()));
            }
            let (tx, rx) = mpsc::unbounded_channel();
            let mut handles = Vec::with_capacity(targets.len());
            for (i, target) in targets.iter().enumerate() {
                let idx = base_idx + i;
                let tx = tx.clone();
                let ws_url = target.ws_url.clone();
                let jwt = target.jwt.clone();
                let label = target.label.clone();
                let handle = tokio::spawn(async move {
                    let mut retries = 0u32;
                    loop {
                        match super::log_stream::connect_and_stream(&ws_url, &jwt, idx, &tx).await
                        {
                            Ok(()) => break,
                            Err(e) => {
                                retries += 1;
                                if retries > 10 {
                                    let _ = tx.send(LogLine {
                                        service_index: idx,
                                        text: format!(
                                            "[{}] max reconnects exceeded: {}",
                                            label, e
                                        ),
                                    });
                                    break;
                                }
                                let _ = tx.send(LogLine {
                                    service_index: idx,
                                    text: format!(
                                        "[{}] reconnecting ({}/10): {}",
                                        label, retries, e
                                    ),
                                });
                                let backoff =
                                    std::time::Duration::from_secs(1 << retries.min(5));
                                tokio::time::sleep(backoff).await;
                            }
                        }
                    }
                });
                handles.push(handle);
            }
            inner.collector = Some((rx, handles));
            inner.pending_targets.extend(targets);
        }
        drop(inner);
        ctrl
    }

    /// Called by the deploy flow after each phase completes.
    /// Immediately spawns WebSocket collectors for the new targets.
    pub async fn add_targets(&self, targets: Vec<LogTarget>) {
        let mut inner = self.inner.lock().await;
        if targets.is_empty() {
            return;
        }

        let base_idx = inner.log_buffers.len();
        for t in &targets {
            inner.log_buffers.push(LogBuffer::new(t.label.clone()));
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let mut new_handles = Vec::with_capacity(targets.len());

        for (i, target) in targets.iter().enumerate() {
            let idx = base_idx + i;
            let tx = tx.clone();
            let ws_url = target.ws_url.clone();
            let jwt = target.jwt.clone();
            let label = target.label.clone();

            let handle = tokio::spawn(async move {
                let mut retries = 0u32;
                loop {
                    match super::log_stream::connect_and_stream(&ws_url, &jwt, idx, &tx).await {
                        Ok(()) => break,
                        Err(e) => {
                            retries += 1;
                            if retries > 10 {
                                let _ = tx.send(LogLine {
                                    service_index: idx,
                                    text: format!(
                                        "[{}] max reconnects exceeded: {}",
                                        label, e
                                    ),
                                });
                                break;
                            }
                            let _ = tx.send(LogLine {
                                service_index: idx,
                                text: format!(
                                    "[{}] reconnecting ({}/10): {}",
                                    label, retries, e
                                ),
                            });
                            let backoff = std::time::Duration::from_secs(1 << retries.min(5));
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            });
            new_handles.push(handle);
        }

        if let Some((_, ref mut handles)) = inner.collector {
            handles.extend(new_handles);
        } else {
            inner.collector = Some((rx, new_handles));
        }

        inner.pending_targets.extend(targets);
    }

    /// Register an SSH-able service for the `s` hotkey.
    pub async fn add_ssh_target(&self, target: SshTarget) {
        self.inner.lock().await.ssh_targets.push(target);
    }

    /// Number of services currently streaming.
    pub async fn target_count(&self) -> usize {
        self.inner.lock().await.log_buffers.len()
    }

    /// Get SSH targets for the service picker.
    pub async fn ssh_targets(&self) -> Vec<SshTarget> {
        self.inner.lock().await.ssh_targets.clone()
    }

    /// Load SSH targets from the encrypted node store into the controller.
    ///
    /// Called after deploy completes — reads `nodes.enc` and converts each
    /// `NodeRecord` into an `SshTarget` with label format `"PHASE:service"`
    /// matching the log tab labels.
    pub async fn load_ssh_targets_from_nodes(&self, password: &str, dseqs: &[u64]) {
        let mut inner = self.inner.lock().await;
        load_ssh_targets_into(&mut inner.ssh_targets, password, dseqs);
    }
}

// ── SSH target loading helper ────────────────────────────────────────────────

/// Populate `ssh_targets` from the encrypted node store (`nodes.enc`).
///
/// Shared by `from_context` (sync, lock already held) and `load_ssh_targets_from_nodes` (async).
fn load_ssh_targets_into(ssh_targets: &mut Vec<SshTarget>, password: &str, dseqs: &[u64]) {
    let path = NodeStore::default_path();
    if !path.exists() {
        tracing::info!("  SSH: no node store at {}", path.display());
        return;
    }
    let store = NodeStore::open(&path, password);
    let records = match store.load() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("  SSH: could not decrypt node store: {}", e);
            return;
        }
    };

    // Clear stale targets before repopulating.
    ssh_targets.clear();

    let total = records.len();
    for rec in records {
        if !dseqs.is_empty() && !dseqs.contains(&rec.dseq) {
            continue;
        }
        if rec.host.is_empty() || rec.ssh_port == 0 {
            continue;
        }
        let key = rec.key_path();
        tracing::debug!(
            "  SSH target: {}:{} -> {}:{} key={}",
            rec.phase, rec.service, rec.host, rec.ssh_port, key.display(),
        );
        ssh_targets.push(SshTarget {
            label: format!("{}:{}", rec.phase, rec.service),
            host: rec.host.clone(),
            port: rec.ssh_port.to_string(),
            ssh_key_path: key,
        });
    }
    if ssh_targets.is_empty() && total > 0 {
        tracing::info!("  SSH: {} node record(s) but none usable", total);
    } else if !ssh_targets.is_empty() {
        tracing::info!(
            "  SSH: {} target(s) ready: {}",
            ssh_targets.len(),
            ssh_targets.iter().map(|t| format!("{} [key={}]", t.label, t.ssh_key_path.display())).collect::<Vec<_>>().join(", "),
        );
    }
}

// ── TuiApp ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Summary,
    LogViewer,
}

pub struct TuiApp {
    screen: Screen,
    pub log_buffers: Vec<LogBuffer>,
    pub active_tab: usize,
    pub scroll_offsets: Vec<usize>,
    running: bool,
    /// Deploy progress lines (from TracingSwitch capture).
    pub deploy_lines: VecDeque<String>,
    /// Scroll offset for the deploy progress pane.
    pub deploy_scroll: usize,
    /// Whether the background deploy task has finished.
    pub deploy_done: bool,
}

/// Max lines retained in the deploy progress pane.
const MAX_DEPLOY_LINES: usize = 10_000;

impl TuiApp {
    fn new(buffers: Vec<LogBuffer>) -> Self {
        let count = buffers.len();
        Self {
            screen: Screen::Summary,
            log_buffers: buffers,
            active_tab: 0,
            scroll_offsets: vec![0; count],
            running: true,
            deploy_lines: VecDeque::new(),
            deploy_scroll: 0,
            deploy_done: false,
        }
    }

    /// Create a TuiApp for the split-pane deploy mode.
    pub fn new_deploy(buffers: Vec<LogBuffer>) -> Self {
        let count = buffers.len();
        Self {
            screen: Screen::LogViewer,
            log_buffers: buffers,
            active_tab: 0,
            scroll_offsets: vec![0; count],
            running: true,
            deploy_lines: VecDeque::new(),
            deploy_scroll: 0,
            deploy_done: false,
        }
    }

    /// Append a deploy progress line from the TracingSwitch capture.
    pub fn push_deploy_line(&mut self, line: String) {
        let was_at_bottom = self.deploy_at_bottom();
        self.deploy_lines.push_back(line);
        if self.deploy_lines.len() > MAX_DEPLOY_LINES {
            self.deploy_lines.pop_front();
            if self.deploy_scroll > 0 {
                self.deploy_scroll = self.deploy_scroll.saturating_sub(1);
            }
        }
        // Auto-scroll if pinned to bottom
        if was_at_bottom {
            self.deploy_scroll = self.deploy_lines.len().saturating_sub(1);
        }
    }

    /// Whether the deploy pane scroll is at the bottom.
    fn deploy_at_bottom(&self) -> bool {
        self.deploy_lines.len().saturating_sub(self.deploy_scroll) <= PAGE_SCROLL_LINES + 5
    }

    fn tab_count(&self) -> usize {
        self.log_buffers.len()
    }

    /// Returns true if the current tab's scroll is pinned to the bottom.
    fn is_at_bottom(&self) -> bool {
        if self.log_buffers.is_empty() {
            return true;
        }
        let buf = &self.log_buffers[self.active_tab];
        let offset = self.scroll_offsets[self.active_tab];
        buf.lines.len().saturating_sub(offset) <= PAGE_SCROLL_LINES + 5
    }

    /// Ingest a log line from the background collector.
    fn handle_log_line(&mut self, line: LogLine) {
        if line.service_index >= self.log_buffers.len() {
            return;
        }

        let was_at_bottom = line.service_index == self.active_tab && self.is_at_bottom();

        let buf = &mut self.log_buffers[line.service_index];
        if buf.status == ConnStatus::Connecting {
            buf.status = ConnStatus::Connected;
        }
        buf.push(line.text);

        // Auto-scroll if pinned to bottom
        if was_at_bottom && line.service_index == self.active_tab {
            let len = self.log_buffers[self.active_tab].lines.len();
            self.scroll_offsets[self.active_tab] = len.saturating_sub(1);
        }
    }

    /// Add buffers for newly registered targets (dynamic growth during deploy).
    pub fn extend_buffers(&mut self, new_buffers: Vec<LogBuffer>) {
        for buf in new_buffers {
            self.log_buffers.push(buf);
            self.scroll_offsets.push(0);
        }
    }
}

// ── Backward-compatible entry point ─────────────────────────────────────────

/// Post-deploy TUI: build log targets from context and launch viewer.
///
/// This is the backward-compatible wrapper — call after `workflow.run()` completes.
pub async fn run_post_deploy_tui(ctx: &OLineContext) -> Result<(), Box<dyn std::error::Error>> {
    let controller = TuiController::from_context(ctx);
    run_tui(controller).await
}

// ── Main entry points ───────────────────────────────────────────────────────

/// Full TUI: run after all phases complete (or when user enters via prompt).
/// Blocks until user exits with Ctrl+C or q.
pub async fn run_tui(controller: TuiController) -> Result<(), Box<dyn std::error::Error>> {
    let mut inner = controller.inner.lock().await;

    if inner.log_buffers.is_empty() {
        tracing::info!("No deployed services found for log streaming.");
        return Ok(());
    }

    let buffers = std::mem::take(&mut inner.log_buffers);
    let mut rx = inner.collector.take().map(|(rx, _)| rx);
    let ssh_targets = inner.ssh_targets.clone();
    drop(inner);

    tracing::info!(
        "Entering log viewer ({} service(s)). Press Ctrl+C to exit.",
        buffers.len()
    );

    let mut app = TuiApp::new(buffers);

    // Install panic hook that restores terminal state.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut event_stream = EventStream::new();
    // Start in LogViewer directly since this is the post-deploy entry point
    app.screen = Screen::LogViewer;
    execute!(stdout(), EnterAlternateScreen)?;
    let mut terminal: Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>> =
        Some(ratatui::Terminal::new(CrosstermBackend::new(stdout()))?);

    while app.running {
        match app.screen {
            Screen::Summary => {
                summary_loop(&mut app, &mut rx, &mut event_stream, &mut terminal).await?;
            }
            Screen::LogViewer => {
                log_viewer_loop(
                    &mut app,
                    &mut rx,
                    &mut event_stream,
                    &mut terminal,
                    &ssh_targets,
                )
                .await?;
            }
        }
    }

    // Cleanup
    if terminal.is_some() {
        execute!(stdout(), LeaveAlternateScreen)?;
    }
    disable_raw_mode()?;

    Ok(())
}

/// Brief TUI: called from a deploy prompt when user types 'l'.
/// Returns when user presses Esc (back to deploy flow).
pub async fn run_tui_briefly(controller: TuiController) -> Result<(), Box<dyn std::error::Error>> {
    let mut inner = controller.inner.lock().await;

    if inner.log_buffers.is_empty() {
        tracing::info!("No services streaming yet.");
        return Ok(());
    }

    // Take ownership temporarily — we'll put them back after
    let buffers = std::mem::take(&mut inner.log_buffers);
    let mut rx = inner.collector.take().map(|(rx, _)| rx);
    let ssh_targets = inner.ssh_targets.clone();
    drop(inner);

    let mut app = TuiApp::new(buffers);

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let mut terminal = Some(ratatui::Terminal::new(CrosstermBackend::new(stdout()))?);
    let mut event_stream = EventStream::new();

    app.screen = Screen::LogViewer;
    log_viewer_loop(
        &mut app,
        &mut rx,
        &mut event_stream,
        &mut terminal,
        &ssh_targets,
    )
    .await?;

    // Cleanup alternate screen
    execute!(stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;

    // Put buffers back into controller for next access
    let mut inner = controller.inner.lock().await;
    inner.log_buffers = app.log_buffers;
    if let Some(rx) = rx {
        inner.collector = Some((rx, Vec::new()));
    }

    Ok(())
}

// ── Split-pane deploy TUI ────────────────────────────────────────────────────

/// Split-pane TUI: container logs on top, deploy progress on bottom.
///
/// Drives the `workflow_fut` concurrently with the TUI event loop (no `tokio::spawn`,
/// so the workflow future does not need to be `Send`).
/// Blocks until the user exits with Ctrl+C or q.
pub async fn run_deploy_tui(
    controller: TuiController,
    mut deploy_rx: mpsc::UnboundedReceiver<String>,
    workflow_fut: impl std::future::Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::pin!(workflow_fut);
    let mut workflow_done = false;

    let mut inner = controller.inner.lock().await;

    let buffers = std::mem::take(&mut inner.log_buffers);
    let mut log_rx = inner.collector.take().map(|(rx, _)| rx);
    let mut ssh_targets = inner.ssh_targets.clone();
    drop(inner);

    let mut app = TuiApp::new_deploy(buffers);

    // Install panic hook that restores terminal state.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let mut terminal = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut event_stream = EventStream::new();

    // Initial draw
    terminal.draw(|f| ui::draw_deploy(f, &app))?;

    loop {
        let needs_redraw;

        tokio::select! {
            // Drive the workflow forward (no Send requirement since it's pinned locally)
            () = &mut workflow_fut, if !workflow_done => {
                workflow_done = true;
                app.deploy_done = true;
                // Refresh SSH targets — deploy just wrote NodeRecords to nodes.enc.
                ssh_targets = controller.inner.lock().await.ssh_targets.clone();
                tracing::info!(
                    "  Deploy done. SSH targets: {}",
                    if ssh_targets.is_empty() { "none".into() }
                    else { ssh_targets.iter().map(|t| t.label.as_str()).collect::<Vec<_>>().join(", ") },
                );
                needs_redraw = true;
            }
            // Container log lines
            Some(line) = async {
                match log_rx.as_mut() {
                    Some(r) => r.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                app.handle_log_line(line);
                needs_redraw = true;
            }
            // Deploy progress lines (tracing capture)
            Some(line) = deploy_rx.recv() => {
                app.push_deploy_line(line);
                needs_redraw = true;
            }
            // Keyboard events
            Some(Ok(evt)) = event_stream.next() => {
                needs_redraw = true;
                if let Event::Key(key) = evt {
                    match key {
                        // Ctrl+C -> exit
                        KeyEvent { code: KeyCode::Char('c'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            break;
                        }
                        // q -> exit
                        KeyEvent { code: KeyCode::Char('q'), .. } => {
                            break;
                        }
                        // Tab -> next service tab
                        KeyEvent { code: KeyCode::Tab, modifiers, .. }
                            if !modifiers.contains(KeyModifiers::SHIFT) =>
                        {
                            if app.tab_count() > 0 {
                                app.active_tab = (app.active_tab + 1) % app.tab_count();
                            }
                        }
                        // Shift+Tab -> prev service tab
                        KeyEvent { code: KeyCode::BackTab, .. } => {
                            if app.tab_count() > 0 {
                                app.active_tab = app.active_tab
                                    .checked_sub(1)
                                    .unwrap_or(app.tab_count() - 1);
                            }
                        }
                        // Scroll up (container logs)
                        KeyEvent { code: KeyCode::Up, .. } => {
                            if !app.scroll_offsets.is_empty() {
                                let off = &mut app.scroll_offsets[app.active_tab];
                                *off = off.saturating_sub(1);
                            }
                        }
                        // Scroll down (container logs)
                        KeyEvent { code: KeyCode::Down, .. } => {
                            if !app.log_buffers.is_empty() {
                                let max = app.log_buffers[app.active_tab]
                                    .lines
                                    .len()
                                    .saturating_sub(1);
                                let off = &mut app.scroll_offsets[app.active_tab];
                                *off = (*off + 1).min(max);
                            }
                        }
                        // Page up (deploy progress)
                        KeyEvent { code: KeyCode::PageUp, .. } => {
                            app.deploy_scroll = app.deploy_scroll.saturating_sub(PAGE_SCROLL_LINES);
                        }
                        // Page down (deploy progress)
                        KeyEvent { code: KeyCode::PageDown, .. } => {
                            let max = app.deploy_lines.len().saturating_sub(1);
                            app.deploy_scroll = (app.deploy_scroll + PAGE_SCROLL_LINES).min(max);
                        }
                        // Home -> top of deploy pane
                        KeyEvent { code: KeyCode::Home, .. } => {
                            app.deploy_scroll = 0;
                        }
                        // End -> bottom of deploy pane
                        KeyEvent { code: KeyCode::End, .. } => {
                            app.deploy_scroll = app.deploy_lines.len().saturating_sub(1);
                        }
                        // Alt+s -> SSH into active service
                        KeyEvent { code: KeyCode::Char('s'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::ALT) =>
                        {
                            if !ssh_targets.is_empty() && !app.log_buffers.is_empty() {
                                let active_label = &app.log_buffers[app.active_tab].label;
                                let target = ssh_targets
                                    .iter()
                                    .find(|t| &t.label == active_label)
                                    .or_else(|| ssh_targets.first());

                                if let Some(target) = target {
                                    execute!(stdout(), LeaveAlternateScreen)?;
                                    disable_raw_mode()?;
                                    use std::io::Write;
                                    io::stdout().flush().ok();

                                    eprintln!(
                                        "\n  SSH -> root@{}:{} (key: {})\n  Ctrl+D or 'exit' to return.\n",
                                        target.host, target.port, target.ssh_key_path.display(),
                                    );

                                    if !target.ssh_key_path.exists() {
                                        eprintln!("  ERROR: key not found at {}\n", target.ssh_key_path.display());
                                    } else {
                                        let status = std::process::Command::new("ssh")
                                            .arg("-i").arg(&target.ssh_key_path)
                                            .arg("-p").arg(&target.port)
                                            .arg("-o").arg("StrictHostKeyChecking=accept-new")
                                            .arg("-o").arg("UserKnownHostsFile=/dev/null")
                                            .arg("-o").arg("ConnectTimeout=10")
                                            .arg("-o").arg("ServerAliveInterval=15")
                                            .arg(format!("root@{}", target.host))
                                            .stdin(std::process::Stdio::inherit())
                                            .stdout(std::process::Stdio::inherit())
                                            .stderr(std::process::Stdio::inherit())
                                            .status();

                                        match &status {
                                            Ok(s) if !s.success() => eprintln!("\n  SSH exited: {}", s),
                                            Err(e) => eprintln!("\n  SSH failed: {}", e),
                                            _ => {}
                                        }
                                    }

                                    enable_raw_mode()?;
                                    execute!(stdout(), EnterAlternateScreen)?;
                                    terminal = ratatui::Terminal::new(
                                        CrosstermBackend::new(stdout()),
                                    )?;
                                    event_stream = EventStream::new();
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if needs_redraw {
            terminal.draw(|f| ui::draw_deploy(f, &app))?;
        }
    }

    // Cleanup
    execute!(stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;

    Ok(())
}

// ── Summary screen (raw mode, normal screen) ───────────────────────────────────

async fn summary_loop(
    app: &mut TuiApp,
    rx: &mut Option<mpsc::UnboundedReceiver<LogLine>>,
    event_stream: &mut EventStream,
    terminal: &mut Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        tokio::select! {
            // Drain log lines in background
            Some(line) = async {
                match rx.as_mut() {
                    Some(r) => r.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                app.handle_log_line(line);
            }
            Some(Ok(evt)) = event_stream.next() => {
                if let Event::Key(key) = evt {
                    match key {
                        // Ctrl+L -> enter log viewer
                        KeyEvent { code: KeyCode::Char('l'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            execute!(stdout(), EnterAlternateScreen)?;
                            let t = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
                            *terminal = Some(t);
                            app.screen = Screen::LogViewer;
                            return Ok(());
                        }
                        // Ctrl+C or q -> exit
                        KeyEvent { code: KeyCode::Char('c'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.running = false;
                            return Ok(());
                        }
                        KeyEvent { code: KeyCode::Char('q'), .. } => {
                            app.running = false;
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

// ── Log viewer screen (raw mode, alternate screen) ─────────────────────────────

async fn log_viewer_loop(
    app: &mut TuiApp,
    rx: &mut Option<mpsc::UnboundedReceiver<LogLine>>,
    event_stream: &mut EventStream,
    terminal: &mut Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>>,
    ssh_targets: &[SshTarget],
) -> Result<(), Box<dyn std::error::Error>> {
    // Initial draw
    if let Some(t) = terminal.as_mut() {
        t.draw(|f| ui::draw(f, app))?;
    }

    loop {
        let needs_redraw;

        tokio::select! {
            Some(line) = async {
                match rx.as_mut() {
                    Some(r) => r.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                app.handle_log_line(line);
                needs_redraw = true;
            }
            Some(Ok(evt)) = event_stream.next() => {
                needs_redraw = true;
                if let Event::Key(key) = evt {
                    match key {
                        // Esc -> back to summary
                        KeyEvent { code: KeyCode::Esc, .. } => {
                            execute!(stdout(), LeaveAlternateScreen)?;
                            *terminal = None;
                            app.screen = Screen::Summary;
                            return Ok(());
                        }
                        // Ctrl+C -> exit entirely
                        KeyEvent { code: KeyCode::Char('c'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.running = false;
                            return Ok(());
                        }
                        // q -> exit
                        KeyEvent { code: KeyCode::Char('q'), .. } => {
                            app.running = false;
                            return Ok(());
                        }
                        // Tab -> next service
                        KeyEvent { code: KeyCode::Tab, modifiers, .. }
                            if !modifiers.contains(KeyModifiers::SHIFT) =>
                        {
                            if app.tab_count() > 0 {
                                app.active_tab = (app.active_tab + 1) % app.tab_count();
                            }
                        }
                        // Shift+Tab -> prev service
                        KeyEvent { code: KeyCode::BackTab, .. } => {
                            if app.tab_count() > 0 {
                                app.active_tab = app.active_tab
                                    .checked_sub(1)
                                    .unwrap_or(app.tab_count() - 1);
                            }
                        }
                        // Scroll up
                        KeyEvent { code: KeyCode::Up, .. } => {
                            if !app.scroll_offsets.is_empty() {
                                let off = &mut app.scroll_offsets[app.active_tab];
                                *off = off.saturating_sub(1);
                            }
                        }
                        // Scroll down
                        KeyEvent { code: KeyCode::Down, .. } => {
                            if !app.log_buffers.is_empty() {
                                let max = app.log_buffers[app.active_tab]
                                    .lines
                                    .len()
                                    .saturating_sub(1);
                                let off = &mut app.scroll_offsets[app.active_tab];
                                *off = (*off + 1).min(max);
                            }
                        }
                        // Page up
                        KeyEvent { code: KeyCode::PageUp, .. } => {
                            if !app.scroll_offsets.is_empty() {
                                let off = &mut app.scroll_offsets[app.active_tab];
                                *off = off.saturating_sub(PAGE_SCROLL_LINES);
                            }
                        }
                        // Page down
                        KeyEvent { code: KeyCode::PageDown, .. } => {
                            if !app.log_buffers.is_empty() {
                                let max = app.log_buffers[app.active_tab]
                                    .lines
                                    .len()
                                    .saturating_sub(1);
                                let off = &mut app.scroll_offsets[app.active_tab];
                                *off = (*off + PAGE_SCROLL_LINES).min(max);
                            }
                        }
                        // Home -> scroll to top
                        KeyEvent { code: KeyCode::Home, .. } => {
                            if !app.scroll_offsets.is_empty() {
                                app.scroll_offsets[app.active_tab] = 0;
                            }
                        }
                        // End -> scroll to bottom
                        KeyEvent { code: KeyCode::End, .. } => {
                            if !app.log_buffers.is_empty() {
                                let max = app.log_buffers[app.active_tab]
                                    .lines
                                    .len()
                                    .saturating_sub(1);
                                app.scroll_offsets[app.active_tab] = max;
                            }
                        }
                        // Alt+s -> SSH into active service
                        KeyEvent { code: KeyCode::Char('s'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::ALT) =>
                        {
                            if !ssh_targets.is_empty() && !app.log_buffers.is_empty() {
                                let active_label = app.log_buffers[app.active_tab].label.clone();
                                let target = ssh_targets
                                    .iter()
                                    .find(|t| t.label == active_label)
                                    .or_else(|| ssh_targets.first());

                                if let Some(target) = target.cloned() {
                                    // Drop terminal cleanly before touching stdout
                                    *terminal = None;
                                    execute!(stdout(), LeaveAlternateScreen)?;
                                    disable_raw_mode()?;
                                    use std::io::Write;
                                    io::stdout().flush().ok();

                                    eprintln!(
                                        "\n  SSH -> root@{}:{} (key: {})\n  Ctrl+D or 'exit' to return.\n",
                                        target.host, target.port, target.ssh_key_path.display(),
                                    );

                                    if !target.ssh_key_path.exists() {
                                        eprintln!("  ERROR: key not found at {}\n", target.ssh_key_path.display());
                                    } else {
                                        let status = std::process::Command::new("ssh")
                                            .arg("-i").arg(&target.ssh_key_path)
                                            .arg("-p").arg(&target.port)
                                            .arg("-o").arg("StrictHostKeyChecking=accept-new")
                                            .arg("-o").arg("UserKnownHostsFile=/dev/null")
                                            .arg("-o").arg("ConnectTimeout=10")
                                            .arg("-o").arg("ServerAliveInterval=15")
                                            .arg(format!("root@{}", target.host))
                                            .stdin(std::process::Stdio::inherit())
                                            .stdout(std::process::Stdio::inherit())
                                            .stderr(std::process::Stdio::inherit())
                                            .status();

                                        match &status {
                                            Ok(s) if !s.success() => eprintln!("\n  SSH exited: {}", s),
                                            Err(e) => eprintln!("\n  SSH failed: {}", e),
                                            _ => {}
                                        }
                                    }

                                    // Restore TUI with fresh terminal + event stream
                                    enable_raw_mode()?;
                                    execute!(stdout(), EnterAlternateScreen)?;
                                    *terminal = Some(ratatui::Terminal::new(
                                        CrosstermBackend::new(stdout()),
                                    )?);
                                    *event_stream = EventStream::new();
                                } else {
                                    let available: Vec<&str> = ssh_targets.iter().map(|t| t.label.as_str()).collect();
                                    app.log_buffers[app.active_tab].push(format!(
                                        "[ssh] No target for '{}'. Available: {:?}",
                                        active_label, available,
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if needs_redraw {
            if let Some(t) = terminal.as_mut() {
                t.draw(|f| ui::draw(f, app))?;
            }
        }
    }
}
