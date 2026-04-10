use std::io::{self, stdout};

use crossterm::{
    event::{Event, KeyCode, KeyEvent, KeyModifiers, EventStream},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::prelude::CrosstermBackend;
use tokio::sync::mpsc;

use super::log_stream::{
    build_log_targets, spawn_log_collectors, ConnStatus, LogBuffer, LogLine,
};
use super::ui;
use crate::workflow::context::OLineContext;

/// Page-scroll jump size (fraction of visible height).
const PAGE_SCROLL_LINES: usize = 20;

// ── Screen state ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    /// Normal terminal — deployment summary is in scrollback.
    Summary,
    /// Alternate-screen TUI with tabbed log viewer.
    LogViewer,
}

// ── App state ──────────────────────────────────────────────────────────────────

pub struct App {
    screen: Screen,
    pub log_buffers: Vec<LogBuffer>,
    pub active_tab: usize,
    pub scroll_offsets: Vec<usize>,
    running: bool,
}

impl App {
    fn new(labels: Vec<String>) -> Self {
        let count = labels.len();
        let buffers = labels.into_iter().map(LogBuffer::new).collect();
        Self {
            screen: Screen::Summary,
            log_buffers: buffers,
            active_tab: 0,
            scroll_offsets: vec![0; count],
            running: true,
        }
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
        // Consider "at bottom" if within PAGE_SCROLL_LINES of the end.
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
}

// ── Entry point ────────────────────────────────────────────────────────────────

/// Post-deploy TUI: background log collection + interactive viewer.
///
/// Call after `workflow.run()` completes and stdin is released.
pub async fn run_post_deploy_tui(ctx: &OLineContext) -> Result<(), Box<dyn std::error::Error>> {
    let targets = build_log_targets(ctx);
    if targets.is_empty() {
        tracing::info!("No deployed services found for log streaming.");
        return Ok(());
    }

    tracing::info!(
        "Log streaming available for {} service(s). Press Ctrl+L to view logs, Ctrl+C to exit.",
        targets.len()
    );

    let labels: Vec<String> = targets.iter().map(|t| t.label.clone()).collect();
    let mut app = App::new(labels);

    let (mut rx, _handles) = spawn_log_collectors(&targets);

    // Install panic hook that restores terminal state.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut event_stream = EventStream::new();

    // Terminal instance (created lazily when entering LogViewer).
    let mut terminal: Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>> = None;

    while app.running {
        match app.screen {
            Screen::Summary => {
                summary_loop(&mut app, &mut rx, &mut event_stream, &mut terminal).await?;
            }
            Screen::LogViewer => {
                log_viewer_loop(&mut app, &mut rx, &mut event_stream, &mut terminal).await?;
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

// ── Summary screen (raw mode, normal screen) ───────────────────────────────────

async fn summary_loop(
    app: &mut App,
    rx: &mut mpsc::UnboundedReceiver<LogLine>,
    event_stream: &mut EventStream,
    terminal: &mut Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        tokio::select! {
            // Drain log lines in background (buffering even while in summary view)
            Some(line) = rx.recv() => {
                app.handle_log_line(line);
            }
            Some(Ok(evt)) = event_stream.next() => {
                if let Event::Key(key) = evt {
                    match key {
                        // Ctrl+L → enter log viewer
                        KeyEvent { code: KeyCode::Char('l'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            execute!(stdout(), EnterAlternateScreen)?;
                            let t = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
                            *terminal = Some(t);
                            app.screen = Screen::LogViewer;
                            return Ok(());
                        }
                        // Ctrl+C or q → exit
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
    app: &mut App,
    rx: &mut mpsc::UnboundedReceiver<LogLine>,
    event_stream: &mut EventStream,
    terminal: &mut Option<ratatui::Terminal<CrosstermBackend<io::Stdout>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initial draw
    if let Some(t) = terminal.as_mut() {
        t.draw(|f| ui::draw(f, app))?;
    }

    loop {
        let needs_redraw;

        tokio::select! {
            Some(line) = rx.recv() => {
                app.handle_log_line(line);
                needs_redraw = true;
            }
            Some(Ok(evt)) = event_stream.next() => {
                needs_redraw = true;
                if let Event::Key(key) = evt {
                    match key {
                        // Esc → back to summary
                        KeyEvent { code: KeyCode::Esc, .. } => {
                            execute!(stdout(), LeaveAlternateScreen)?;
                            *terminal = None;
                            app.screen = Screen::Summary;
                            return Ok(());
                        }
                        // Ctrl+C → exit entirely
                        KeyEvent { code: KeyCode::Char('c'), modifiers, .. }
                            if modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.running = false;
                            return Ok(());
                        }
                        // Tab → next service
                        KeyEvent { code: KeyCode::Tab, modifiers, .. }
                            if !modifiers.contains(KeyModifiers::SHIFT) =>
                        {
                            if app.tab_count() > 0 {
                                app.active_tab = (app.active_tab + 1) % app.tab_count();
                            }
                        }
                        // Shift+Tab → prev service
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
                                let max = app.log_buffers[app.active_tab].lines.len().saturating_sub(1);
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
                                let max = app.log_buffers[app.active_tab].lines.len().saturating_sub(1);
                                let off = &mut app.scroll_offsets[app.active_tab];
                                *off = (*off + PAGE_SCROLL_LINES).min(max);
                            }
                        }
                        // Home → scroll to top
                        KeyEvent { code: KeyCode::Home, .. } => {
                            if !app.scroll_offsets.is_empty() {
                                app.scroll_offsets[app.active_tab] = 0;
                            }
                        }
                        // End → scroll to bottom
                        KeyEvent { code: KeyCode::End, .. } => {
                            if !app.log_buffers.is_empty() {
                                let max = app.log_buffers[app.active_tab].lines.len().saturating_sub(1);
                                app.scroll_offsets[app.active_tab] = max;
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
