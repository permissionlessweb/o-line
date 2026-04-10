use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs, Wrap},
    Frame,
};

use super::app::App;
use super::log_stream::ConnStatus;

/// Render the log viewer TUI into the given frame.
pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),  // tab bar
        Constraint::Min(1),    // log area
        Constraint::Length(1), // status bar
    ])
    .split(f.area());

    draw_tabs(f, app, chunks[0]);
    draw_logs(f, app, chunks[1]);
    draw_status_bar(f, chunks[2]);
}

/// Render the tab bar with service labels and connection indicators.
fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    if app.log_buffers.is_empty() {
        return;
    }

    let titles: Vec<Line> = app
        .log_buffers
        .iter()
        .map(|buf| {
            let dot = match &buf.status {
                ConnStatus::Connected => Span::styled("● ", Style::default().fg(Color::Green)),
                ConnStatus::Connecting => Span::styled("◌ ", Style::default().fg(Color::Yellow)),
                ConnStatus::Disconnected(_) => Span::styled("● ", Style::default().fg(Color::Red)),
            };
            Line::from(vec![dot, Span::raw(&buf.label)])
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" Services "))
        .select(app.active_tab)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");

    f.render_widget(tabs, area);
}

/// Render the scrollable log area for the active tab.
fn draw_logs(f: &mut Frame, app: &App, area: Rect) {
    if app.log_buffers.is_empty() {
        let empty = Paragraph::new("No deployed services found.")
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(empty, area);
        return;
    }

    let buf = &app.log_buffers[app.active_tab];
    let offset = app.scroll_offsets[app.active_tab];

    let lines: Vec<Line> = buf
        .lines
        .iter()
        .map(|l| {
            let lower = l.to_lowercase();
            let style = if lower.contains("err") || lower.contains("error") {
                Style::default().fg(Color::Red)
            } else if lower.contains("warn") || lower.contains("warning") {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(l.as_str(), style))
        })
        .collect();

    let title = format!(" {} ({} lines) ", buf.label, buf.lines.len());
    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((offset as u16, 0));

    f.render_widget(paragraph, area);
}

/// Render the bottom status bar with keybinding hints.
fn draw_status_bar(f: &mut Frame, area: Rect) {
    let hints = Line::from(vec![
        Span::styled(" Tab", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(":switch  "),
        Span::styled("↑↓/PgUp/PgDn", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(":scroll  "),
        Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(":back  "),
        Span::styled("Ctrl+C", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(":exit"),
    ]);

    let bar = Paragraph::new(hints).style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::White),
    );
    f.render_widget(bar, area);
}
