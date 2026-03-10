// SPDX-License-Identifier: GPL-3.0-or-later

//! Terminal UI for local `moshwatchd` snapshots and session controls.
//!
//! ## Rationale
//! Provide a low-friction operator view over the local Unix-socket API without
//! introducing a second source of truth or a browser dependency.
//!
//! ## Interpretation Notes
//! * The UI polls the daemon's API; it is not reading daemon memory directly.
//! * Detail sparklines show the newest points on the right.
//! * RTT history auto-scales, while retransmit history is fixed to `0..100%`.
//! * History spacing follows telemetry events, not uniform wall-clock buckets.

use std::{
    io::{self, Stdout},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use moshwatch_core::{
    ApiConfigResponse, ApiSessionControlResponse, ApiSessionResponse, ApiSessionsResponse,
    HealthState, HealthThresholds, RetransmitWindowBreakdown, RuntimePaths, SessionControlAction,
    SessionKind, SessionMetrics, SessionSnapshot, SessionSummary,
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, RenderDirection, Row, Sparkline, Table, Wrap},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{timeout, timeout_at},
};

const MAX_HTTP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
struct PendingTerminate {
    session_id: String,
    pid: i32,
    label: String,
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    api_socket: Option<PathBuf>,
    #[arg(long, default_value_t = 1_000)]
    refresh_ms: u64,
}

struct App {
    api_socket: PathBuf,
    refresh_ms: u64,
    thresholds: HealthThresholds,
    snapshot_stale: bool,
    snapshot_generated_at_unix_ms: Option<i64>,
    total_sessions: usize,
    truncated_session_count: usize,
    dropped_sessions_total: u64,
    summaries: Vec<SessionSummary>,
    detail: Option<SessionSnapshot>,
    selected: usize,
    pending_terminate: Option<PendingTerminate>,
    last_notice: Option<String>,
    last_error: Option<String>,
    last_refresh: Instant,
}

impl App {
    fn new(api_socket: PathBuf, refresh_ms: u64) -> Self {
        Self {
            api_socket,
            refresh_ms,
            thresholds: HealthThresholds::default(),
            snapshot_stale: false,
            snapshot_generated_at_unix_ms: None,
            total_sessions: 0,
            truncated_session_count: 0,
            dropped_sessions_total: 0,
            summaries: Vec::new(),
            detail: None,
            selected: 0,
            pending_terminate: None,
            last_notice: None,
            last_error: None,
            last_refresh: Instant::now() - Duration::from_millis(refresh_ms),
        }
    }

    fn selected_id(&self) -> Option<&str> {
        self.summaries
            .get(self.selected)
            .map(|summary| summary.session_id.as_str())
    }

    fn selected_summary(&self) -> Option<&SessionSummary> {
        self.summaries.get(self.selected)
    }

    fn arm_terminate(&mut self) {
        let Some(summary) = self.selected_summary() else {
            self.last_notice = Some("no session selected".to_string());
            return;
        };
        self.pending_terminate = Some(PendingTerminate {
            session_id: summary.session_id.clone(),
            pid: summary.pid,
            label: session_label(summary),
        });
        self.last_notice = None;
        self.last_error = None;
    }

    fn cancel_terminate(&mut self) {
        self.pending_terminate = None;
        self.last_notice = Some("terminate cancelled".to_string());
        self.last_error = None;
    }

    async fn refresh(&mut self) {
        match request_json::<ApiSessionsResponse>(&self.api_socket, "/v1/sessions").await {
            Ok(response) => {
                self.snapshot_generated_at_unix_ms = Some(response.generated_at_unix_ms);
                if let Ok(config) =
                    request_json::<ApiConfigResponse>(&self.api_socket, "/v1/config").await
                {
                    self.thresholds = config.config.thresholds;
                }
                let previous_id = self.selected_id().map(str::to_owned);
                let previous_detail = self.detail.clone();
                self.total_sessions = response.total_sessions;
                self.truncated_session_count = response.truncated_session_count;
                self.dropped_sessions_total = response.dropped_sessions_total;
                self.snapshot_stale = false;
                self.summaries = response.sessions;
                if self.summaries.is_empty() {
                    self.selected = 0;
                    self.detail = None;
                } else if let Some(ref previous_id) = previous_id {
                    if let Some(position) = self
                        .summaries
                        .iter()
                        .position(|summary| &summary.session_id == previous_id)
                    {
                        self.selected = position;
                    } else {
                        self.selected = self.selected.min(self.summaries.len().saturating_sub(1));
                    }
                } else {
                    self.selected = self.selected.min(self.summaries.len().saturating_sub(1));
                }

                self.detail = None;
                if let Some(session_id) = self.selected_id().map(str::to_owned) {
                    let path = format!("/v1/sessions/{session_id}");
                    match request_json::<ApiSessionResponse>(&self.api_socket, &path).await {
                        Ok(detail) => {
                            self.snapshot_generated_at_unix_ms = Some(detail.generated_at_unix_ms);
                            self.detail = Some(detail.session);
                            self.last_error = None;
                        }
                        Err(error) => {
                            if previous_id.as_deref() == Some(session_id.as_str()) {
                                self.detail = previous_detail;
                            }
                            self.last_error = Some(format!("detail refresh failed: {error:#}"));
                        }
                    }
                } else {
                    self.last_error = None;
                }
            }
            Err(error) => {
                self.last_error = Some(format!("session refresh failed: {error:#}"));
                self.snapshot_stale = true;
            }
        }
        self.last_refresh = Instant::now();
    }

    async fn confirm_terminate(&mut self) {
        let Some(pending) = self.pending_terminate.take() else {
            self.last_notice = Some("no terminate action pending".to_string());
            return;
        };
        let path = format!("/v1/sessions/{}/terminate", pending.session_id);
        match request_json_with_method::<ApiSessionControlResponse>(&self.api_socket, "POST", &path)
            .await
        {
            Ok(response) => {
                if response.action != SessionControlAction::Terminate {
                    self.last_error =
                        Some("terminate failed: unexpected control response".to_string());
                    return;
                }
                self.last_notice = Some(format!(
                    "SIGTERM requested for pid {} ({})",
                    pending.pid, pending.label
                ));
                self.last_error = None;
                self.refresh().await;
            }
            Err(error) => {
                self.last_error = Some(format!(
                    "terminate failed for pid {} ({}): {error:#}",
                    pending.pid, pending.label
                ));
            }
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.summaries.is_empty() {
            self.selected = 0;
            return;
        }
        let len = self.summaries.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1);
        self.selected = next as usize;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut paths = RuntimePaths::discover();
    if let Some(api_socket) = args.api_socket {
        paths.api_socket = api_socket;
    }

    let mut terminal = setup_terminal()?;
    let mut app = App::new(paths.api_socket.clone(), args.refresh_ms);
    app.refresh().await;

    let result = run_app(&mut terminal, &mut app).await;
    restore_terminal(&mut terminal)?;
    result
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;

        if app.last_refresh.elapsed() >= Duration::from_millis(app.refresh_ms) {
            app.refresh().await;
        }

        if event::poll(Duration::from_millis(100)).context("poll input")? {
            let Event::Key(key) = event::read().context("read input")? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if app.pending_terminate.is_some() {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Enter => {
                        app.confirm_terminate().await;
                    }
                    KeyCode::Char('n') | KeyCode::Esc => app.cancel_terminate(),
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => {
                    app.move_selection(1);
                    app.refresh().await;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.move_selection(-1);
                    app.refresh().await;
                }
                KeyCode::Char('g') => {
                    app.selected = 0;
                    app.refresh().await;
                }
                KeyCode::Char('G') => {
                    if !app.summaries.is_empty() {
                        app.selected = app.summaries.len() - 1;
                        app.refresh().await;
                    }
                }
                KeyCode::Char('x') => app.arm_terminate(),
                KeyCode::Char('r') => app.refresh().await,
                _ => {}
            }
        }
    }
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).context("create terminal")
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode().context("disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).context("leave alternate screen")?;
    terminal.show_cursor().context("restore cursor")
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(frame.area());
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(layout[1]);

    let session_summary = if app.truncated_session_count > 0 {
        format!(
            "{} shown / {} total ({} hidden)",
            app.summaries.len(),
            app.total_sessions,
            app.truncated_session_count
        )
    } else {
        format!("{} sessions", app.total_sessions)
    };
    let drop_note = if app.dropped_sessions_total > 0 {
        format!(" | shed {}", app.dropped_sessions_total)
    } else {
        String::new()
    };
    let snapshot_note = app
        .snapshot_generated_at_unix_ms
        .and_then(snapshot_age_ms)
        .map(|age_ms| format!(" | snapshot {}", fmt_duration_ms(Some(age_ms))))
        .unwrap_or_default();
    let stale_note = if app.snapshot_stale { " | stale" } else { "" };
    let error_note = app
        .last_error
        .as_deref()
        .map(|error| format!(" | {error}"))
        .unwrap_or_default();
    let notice_note = app
        .last_notice
        .as_deref()
        .map(|notice| format!(" | {notice}"))
        .unwrap_or_default();
    let action_note = app
        .pending_terminate
        .as_ref()
        .map(|pending| {
            format!(
                " | terminate {} (pid {})? y confirm | n cancel",
                pending.label, pending.pid
            )
        })
        .unwrap_or_else(|| " | x terminate | r refresh | q quit".to_string());
    let status = format!(
        "{session_summary}{drop_note}{snapshot_note}{stale_note} | socket {}{notice_note}{error_note}{action_note}",
        app.api_socket.display()
    );
    let status_block =
        Paragraph::new(status).block(Block::default().borders(Borders::ALL).title("moshwatch"));
    frame.render_widget(status_block, layout[0]);

    draw_table(frame, body[0], app);
    draw_detail(frame, body[1], app);
}

fn draw_table(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let rows = app.summaries.iter().enumerate().map(|(index, summary)| {
        let style = row_style(summary, index == app.selected);
        Row::new(vec![
            Cell::from(health_label(&summary.health)),
            Cell::from(summary.pid.to_string()),
            Cell::from(
                summary
                    .udp_port
                    .map_or_else(|| "-".to_string(), |value| value.to_string()),
            ),
            Cell::from(
                summary
                    .client_addr
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(fmt_f64(summary.metrics.srtt_ms, "ms")),
            Cell::from(fmt_windowed_pct(
                summary.metrics.retransmit_pct_10s,
                summary.metrics.retransmit_window_10s_complete,
            )),
            Cell::from(fmt_u64(summary.metrics.last_heard_age_ms, "ms")),
            Cell::from(session_label(summary)),
        ])
        .style(style)
    });

    let header = Row::new(vec![
        "State", "PID", "Port", "Client", "RTT", "RTX10", "Heard", "Session",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(22),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Sessions"));
    frame.render_widget(table, area);
}

fn draw_detail(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(11),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Min(5),
        ])
        .split(area);

    if let Some(detail) = &app.detail {
        let summary = &detail.summary;
        let retransmit_color = retransmit_color(&summary.metrics, &app.thresholds);
        let history_diagnostics = summarize_history(detail);
        let health_reasons = health_reasons(summary, &app.thresholds);
        let health_reason_text = if health_reasons.is_empty() {
            "no active threshold breach".to_string()
        } else {
            health_reasons.join(", ")
        };
        let snapshot_age = app
            .snapshot_generated_at_unix_ms
            .and_then(snapshot_age_ms)
            .map(|value| fmt_duration_ms(Some(value)))
            .unwrap_or_else(|| "-".to_string());
        let last_sample_age = app
            .snapshot_generated_at_unix_ms
            .and_then(|generated_at| observed_age_ms(generated_at, summary.last_observed_unix_ms))
            .map(|value| fmt_duration_ms(Some(value)))
            .unwrap_or_else(|| "-".to_string());
        let info = vec![
            Line::from(vec![
                Span::styled("Session ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(session_label(summary)),
                Span::raw("  "),
                Span::styled("Health ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(health_label(&summary.health)),
            ]),
            Line::from(vec![
                Span::styled("Identity ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(summary.session_id.clone()),
            ]),
            Line::from(vec![
                Span::styled("PID ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(summary.pid.to_string()),
                Span::raw("  "),
                Span::styled("Bind ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(summary.bind_addr.clone().unwrap_or_else(|| "-".to_string())),
                Span::raw(":"),
                Span::raw(
                    summary
                        .udp_port
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
                Span::raw("  "),
                Span::styled("Client ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    summary
                        .client_addr
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                ),
            ]),
            Line::from(vec![
                Span::styled("RTT ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(fmt_f64(summary.metrics.srtt_ms, "ms")),
                Span::raw("  "),
                Span::styled("RTTVAR ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(fmt_f64(summary.metrics.rttvar_ms, "ms")),
                Span::raw("  "),
                Span::styled("Last RTT ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(fmt_f64(summary.metrics.last_rtt_ms, "ms")),
            ]),
            Line::from(vec![
                Span::styled("Snapshot ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(snapshot_age),
                Span::raw("  "),
                Span::styled(
                    "Last Sample ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(last_sample_age),
                Span::raw("  "),
                Span::styled("RTX10 ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    fmt_windowed_pct(
                        summary.metrics.retransmit_pct_10s,
                        summary.metrics.retransmit_window_10s_complete,
                    ),
                    Style::default().fg(retransmit_color),
                ),
                Span::raw("  "),
                Span::styled("RTX60 ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    fmt_windowed_pct(
                        summary.metrics.retransmit_pct_60s,
                        summary.metrics.retransmit_window_60s_complete,
                    ),
                    Style::default().fg(retransmit_color),
                ),
            ]),
            Line::from(vec![
                Span::styled("Last Heard ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(fmt_u64(summary.metrics.last_heard_age_ms, "ms")),
                Span::raw("  "),
                Span::styled(
                    "Remote State ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(fmt_u64(summary.metrics.remote_state_age_ms, "ms")),
            ]),
            Line::from(vec![
                Span::styled("TX ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    summary
                        .metrics
                        .packets_tx_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
                Span::raw("  "),
                Span::styled("RX ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    summary
                        .metrics
                        .packets_rx_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
                Span::raw("  "),
                Span::styled("Resends ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    summary
                        .metrics
                        .retransmits_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
                Span::raw("  "),
                Span::styled("Empty ACKs ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    summary
                        .metrics
                        .empty_acks_tx_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "State Updates ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(
                    summary
                        .metrics
                        .state_updates_tx_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
                Span::raw("/"),
                Span::raw(
                    summary
                        .metrics
                        .state_updates_rx_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
                Span::raw("  "),
                Span::styled("Dup RX ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    summary
                        .metrics
                        .duplicate_states_rx_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
                Span::raw("  "),
                Span::styled("OOO RX ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    summary
                        .metrics
                        .out_of_order_states_rx_total
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
            ]),
            Line::from(vec![
                Span::styled("Command ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(summary.cmdline.clone()),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(info)
                .block(Block::default().borders(Borders::ALL).title("Details"))
                .wrap(Wrap { trim: true }),
            chunks[0],
        );

        let rtt_data = detail
            .history
            .iter()
            .rev()
            .map(|point| point.srtt_ms.unwrap_or_default().round() as u64)
            .collect::<Vec<_>>();
        // `RenderDirection::RightToLeft` plus reversed history means the newest
        // sample is rendered on the right edge. RTT uses auto-scaling so spikes
        // stay visible even when absolute values are small.
        frame.render_widget(
            Sparkline::default()
                .block(Block::default().borders(Borders::ALL).title(format!(
                    "RTT History (right=newest, auto, peak {})",
                    fmt_f64(history_diagnostics.max_rtt_ms, "ms")
                )))
                .data(&rtt_data)
                .direction(RenderDirection::RightToLeft)
                .style(Style::default().fg(Color::Cyan)),
            chunks[1],
        );

        let retransmit_data = detail
            .history
            .iter()
            .rev()
            .map(|point| sparkline_point_from_pct(point.retransmit_pct_10s))
            .collect::<Vec<_>>();
        // Retransmit uses a fixed `0..100` scale so reconnect spikes and idle
        // periods can be compared across sessions. Missing values stay absent
        // instead of being coerced to zero.
        frame.render_widget(
            Sparkline::default()
                .block(Block::default().borders(Borders::ALL).title(format!(
                    "RTX10 History (right=newest, 0..100%, peak {})",
                    fmt_f64(history_diagnostics.max_retransmit_pct, "%")
                )))
                .data(&retransmit_data)
                .max(100)
                .direction(RenderDirection::RightToLeft)
                .style(Style::default().fg(retransmit_color)),
            chunks[2],
        );

        let diagnostics = vec![
            Line::from(vec![
                Span::styled("Why ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(health_reason_text),
            ]),
            Line::from(vec![
                Span::styled("RTX10 Math ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format_retransmit_window(
                    10,
                    summary.metrics.retransmit_pct_10s,
                    summary.metrics.retransmit_window_10s_complete,
                    &summary.metrics.retransmit_window_10s_breakdown,
                )),
            ]),
            Line::from(vec![
                Span::styled("RTX60 Math ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format_retransmit_window(
                    60,
                    summary.metrics.retransmit_pct_60s,
                    summary.metrics.retransmit_window_60s_complete,
                    &summary.metrics.retransmit_window_60s_breakdown,
                )),
            ]),
            Line::from(vec![
                Span::styled("History ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "{} shown / {} total over {} | largest gap {} | max RTT {} | max RTX10 {}",
                    history_diagnostics.shown_points,
                    detail.total_history_points,
                    fmt_duration_ms(history_diagnostics.span_ms),
                    fmt_duration_ms(history_diagnostics.largest_gap_ms),
                    fmt_f64(history_diagnostics.max_rtt_ms, "ms"),
                    fmt_f64(history_diagnostics.max_retransmit_pct, "%"),
                )),
            ]),
            Line::from(vec![
                Span::styled("Graphs ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "right=newest | RTT auto-scale | RTX fixed 0..100% | spacing follows telemetry events | RTX warn {:.1}% / crit {:.1}%",
                    app.thresholds.warn_retransmit_pct, app.thresholds.critical_retransmit_pct,
                )),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(diagnostics)
                .block(Block::default().borders(Borders::ALL).title("Diagnostics"))
                .wrap(Wrap { trim: true }),
            chunks[3],
        );
    } else {
        frame.render_widget(
            Paragraph::new("No session selected.")
                .block(Block::default().borders(Borders::ALL).title("Details")),
            area,
        );
    }
}

fn health_label(health: &HealthState) -> &'static str {
    match health {
        HealthState::Ok => "ok",
        HealthState::Degraded => "degraded",
        HealthState::Critical => "critical",
        HealthState::Legacy => "legacy",
    }
}

fn row_style(summary: &SessionSummary, selected: bool) -> Style {
    let base = match summary.health {
        HealthState::Ok => Style::default().fg(Color::Green),
        HealthState::Degraded => Style::default().fg(Color::Yellow),
        HealthState::Critical => Style::default().fg(Color::Red),
        HealthState::Legacy => Style::default().fg(Color::DarkGray),
    };
    if selected {
        base.bg(Color::Blue).add_modifier(Modifier::BOLD)
    } else {
        base
    }
}

fn fmt_f64(value: Option<f64>, suffix: &str) -> String {
    value
        .map(|value| format!("{value:.1}{suffix}"))
        .unwrap_or_else(|| "-".to_string())
}

fn fmt_windowed_pct(value: Option<f64>, complete: bool) -> String {
    if !complete {
        return "warming".to_string();
    }
    fmt_f64(value, "%")
}

fn fmt_u64(value: Option<u64>, suffix: &str) -> String {
    value
        .map(|value| format!("{value}{suffix}"))
        .unwrap_or_else(|| "-".to_string())
}

fn sparkline_point_from_pct(value: Option<f64>) -> Option<u64> {
    value.and_then(|value| {
        if !value.is_finite() {
            return None;
        }
        Some(value.clamp(0.0, 100.0).round() as u64)
    })
}

fn retransmit_color(metrics: &SessionMetrics, thresholds: &HealthThresholds) -> Color {
    let has_retransmit_value =
        metrics.retransmit_pct_10s.is_some() || metrics.retransmit_pct_60s.is_some();
    let critical = metrics.retransmit_window_60s_complete
        && metrics
            .retransmit_pct_60s
            .is_some_and(|value| value >= thresholds.critical_retransmit_pct);
    let warn = (metrics.retransmit_window_10s_complete
        && metrics
            .retransmit_pct_10s
            .is_some_and(|value| value >= thresholds.warn_retransmit_pct))
        || (metrics.retransmit_window_60s_complete
            && metrics
                .retransmit_pct_60s
                .is_some_and(|value| value >= thresholds.warn_retransmit_pct));

    if critical {
        Color::Red
    } else if warn {
        Color::Yellow
    } else if metrics.retransmit_window_10s_complete && has_retransmit_value {
        Color::Green
    } else {
        Color::DarkGray
    }
}

fn session_label(summary: &SessionSummary) -> String {
    summary
        .display_session_id
        .clone()
        .unwrap_or_else(|| summary.session_id.clone())
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct HistoryDiagnostics {
    shown_points: usize,
    span_ms: Option<u64>,
    largest_gap_ms: Option<u64>,
    max_rtt_ms: Option<f64>,
    max_retransmit_pct: Option<f64>,
}

fn summarize_history(detail: &SessionSnapshot) -> HistoryDiagnostics {
    let span_ms = detail
        .history
        .first()
        .zip(detail.history.last())
        .and_then(|(first, last)| observed_age_ms(last.unix_ms, first.unix_ms));
    let largest_gap_ms = detail
        .history
        .windows(2)
        .filter_map(|window| observed_age_ms(window[1].unix_ms, window[0].unix_ms))
        .max();
    let max_rtt_ms = max_f64(detail.history.iter().filter_map(|point| point.srtt_ms));
    let max_retransmit_pct = max_f64(
        detail
            .history
            .iter()
            .filter_map(|point| point.retransmit_pct_10s),
    );

    let shown_points = detail.history.len();

    HistoryDiagnostics {
        shown_points,
        span_ms,
        largest_gap_ms,
        max_rtt_ms,
        max_retransmit_pct,
    }
}

fn health_reasons(summary: &SessionSummary, thresholds: &HealthThresholds) -> Vec<String> {
    if summary.kind == SessionKind::Legacy {
        return vec!["legacy session (no verified telemetry)".to_string()];
    }

    let metrics = &summary.metrics;
    let mut reasons = Vec::new();

    if let Some(value) = metrics.last_heard_age_ms {
        if value >= thresholds.critical_silence_ms {
            reasons.push(format!(
                "silence {} >= crit {}",
                fmt_duration_ms(Some(value)),
                fmt_duration_ms(Some(thresholds.critical_silence_ms)),
            ));
        } else if value >= thresholds.warn_silence_ms {
            reasons.push(format!(
                "silence {} >= warn {}",
                fmt_duration_ms(Some(value)),
                fmt_duration_ms(Some(thresholds.warn_silence_ms)),
            ));
        }
    }

    if let Some(value) = metrics.srtt_ms {
        if value >= thresholds.critical_rtt_ms as f64 {
            reasons.push(format!(
                "RTT {} >= crit {}",
                fmt_f64(Some(value), "ms"),
                fmt_u64(Some(thresholds.critical_rtt_ms), "ms"),
            ));
        } else if value >= thresholds.warn_rtt_ms as f64 {
            reasons.push(format!(
                "RTT {} >= warn {}",
                fmt_f64(Some(value), "ms"),
                fmt_u64(Some(thresholds.warn_rtt_ms), "ms"),
            ));
        }
    }

    if metrics.retransmit_window_60s_complete
        && let Some(value) = metrics.retransmit_pct_60s
    {
        if value >= thresholds.critical_retransmit_pct {
            reasons.push(format!(
                "RTX60 {} >= crit {}",
                fmt_f64(Some(value), "%"),
                fmt_f64(Some(thresholds.critical_retransmit_pct), "%"),
            ));
        } else if value >= thresholds.warn_retransmit_pct {
            reasons.push(format!(
                "RTX60 {} >= warn {}",
                fmt_f64(Some(value), "%"),
                fmt_f64(Some(thresholds.warn_retransmit_pct), "%"),
            ));
        }
    }

    if metrics.retransmit_window_10s_complete
        && let Some(value) = metrics.retransmit_pct_10s
        && value >= thresholds.warn_retransmit_pct
    {
        reasons.push(format!(
            "RTX10 {} >= warn {}",
            fmt_f64(Some(value), "%"),
            fmt_f64(Some(thresholds.warn_retransmit_pct), "%"),
        ));
    }

    if reasons.is_empty() {
        // Distinguish between "warming", "idle", and "unknown counters" so the
        // detail panel explains whether a quiet graph means calm traffic,
        // insufficient history, or incomplete telemetry fields.
        if !metrics.retransmit_window_10s_complete || !metrics.retransmit_window_60s_complete {
            reasons.push("RTX windows warming".to_string());
        } else if metrics.retransmit_window_10s_breakdown.transmissions_total == Some(0)
            && metrics.retransmit_window_60s_breakdown.transmissions_total == Some(0)
        {
            reasons.push("RTX windows idle".to_string());
        } else if metrics.retransmit_pct_10s.is_none() && metrics.retransmit_pct_60s.is_none() {
            reasons.push("RTX counters missing".to_string());
        }
    }

    reasons
}

fn format_retransmit_window(
    window_secs: u64,
    pct: Option<f64>,
    complete: bool,
    breakdown: &RetransmitWindowBreakdown,
) -> String {
    if !complete {
        return format!("warming (<{window_secs}s history)");
    }
    let has_breakdown = breakdown.transmissions_total.is_some()
        || breakdown.retransmits_total.is_some()
        || breakdown.state_updates_total.is_some()
        || breakdown.empty_acks_total.is_some();
    match (pct, breakdown.transmissions_total) {
        (Some(value), Some(0)) => format!("{value:.1}% = idle window (0 tx)"),
        (None, Some(0)) => "idle window (0 tx)".to_string(),
        (Some(value), Some(transmissions_total)) => format!(
            "{value:.1}% = {} resend / {transmissions_total} tx (updates {}, empty ack {})",
            breakdown
                .retransmits_total
                .map_or_else(|| "?".to_string(), |count| count.to_string()),
            breakdown
                .state_updates_total
                .map_or_else(|| "?".to_string(), |count| count.to_string()),
            breakdown
                .empty_acks_total
                .map_or_else(|| "?".to_string(), |count| count.to_string()),
        ),
        (Some(value), None) => format!("{value:.1}%"),
        (None, _) if has_breakdown => format!(
            "unknown (tx {}, resend {}, updates {}, empty ack {})",
            breakdown
                .transmissions_total
                .map_or_else(|| "?".to_string(), |count| count.to_string()),
            breakdown
                .retransmits_total
                .map_or_else(|| "?".to_string(), |count| count.to_string()),
            breakdown
                .state_updates_total
                .map_or_else(|| "?".to_string(), |count| count.to_string()),
            breakdown
                .empty_acks_total
                .map_or_else(|| "?".to_string(), |count| count.to_string()),
        ),
        (None, _) => "unknown (counter fields missing)".to_string(),
    }
}

fn fmt_duration_ms(value: Option<u64>) -> String {
    match value {
        None => "-".to_string(),
        Some(value) if value < 1_000 => format!("{value}ms"),
        Some(value) if value < 60_000 => format!("{:.1}s", value as f64 / 1_000.0),
        Some(value) if value < 3_600_000 => format!("{:.1}m", value as f64 / 60_000.0),
        Some(value) => format!("{:.1}h", value as f64 / 3_600_000.0),
    }
}

fn observed_age_ms(later_unix_ms: i64, earlier_unix_ms: i64) -> Option<u64> {
    later_unix_ms
        .checked_sub(earlier_unix_ms)
        .and_then(|delta| u64::try_from(delta).ok())
}

fn snapshot_age_ms(snapshot_generated_at_unix_ms: i64) -> Option<u64> {
    observed_age_ms(
        moshwatch_core::time::unix_time_ms(),
        snapshot_generated_at_unix_ms,
    )
}

fn max_f64(values: impl Iterator<Item = f64>) -> Option<f64> {
    values
        .filter(|value| value.is_finite() && *value >= 0.0)
        .fold(None, |best, value| {
            Some(best.map_or(value, |best| best.max(value)))
        })
}

async fn request_json<T>(socket_path: &Path, path: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    request_json_with_method(socket_path, "GET", path).await
}

async fn request_json_with_method<T>(socket_path: &Path, method: &str, path: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    // Speak a tiny subset of HTTP over the owner-only Unix socket so the TUI
    // stays decoupled from daemon internals and can treat the API as the
    // contract boundary.
    let mut stream = timeout(Duration::from_secs(2), UnixStream::connect(socket_path))
        .await
        .context("connect timed out")?
        .with_context(|| format!("connect {}", socket_path.display()))?;
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    timeout(Duration::from_secs(2), stream.write_all(request.as_bytes()))
        .await
        .context("write request timed out")?
        .context("write request")?;
    timeout(Duration::from_secs(2), stream.flush())
        .await
        .context("flush request timed out")?
        .context("flush request")?;

    let response = read_bounded_response(&mut stream, Duration::from_secs(2)).await?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("malformed http response")?;
    let header = String::from_utf8_lossy(&response[..split]);
    if !header.starts_with("HTTP/1.1 200") && !header.starts_with("HTTP/1.0 200") {
        anyhow::bail!(
            "request failed: {}",
            header.lines().next().unwrap_or_default()
        );
    }
    serde_json::from_slice(&response[split + 4..]).context("decode json body")
}

async fn read_bounded_response<R>(reader: &mut R, total_timeout: Duration) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let deadline = Instant::now() + total_timeout;
    let mut response = Vec::new();
    loop {
        let mut chunk = [0u8; 8192];
        let read = timeout_at(deadline.into(), reader.read(&mut chunk))
            .await
            .context("read response timed out")?
            .context("read response")?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_HTTP_RESPONSE_BYTES {
            anyhow::bail!("response exceeded {MAX_HTTP_RESPONSE_BYTES} bytes");
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ratatui::style::Color;
    use tokio::io::AsyncWriteExt;

    use moshwatch_core::{
        HealthState, HealthThresholds, MetricPoint, RetransmitWindowBreakdown, SessionKind,
        SessionMetrics, SessionSnapshot, SessionSummary,
    };

    use super::{
        MAX_HTTP_RESPONSE_BYTES, fmt_duration_ms, fmt_windowed_pct, format_retransmit_window,
        health_reasons, read_bounded_response, retransmit_color, session_label,
        sparkline_point_from_pct, summarize_history,
    };

    fn summary() -> SessionSummary {
        SessionSummary {
            session_id: "instrumented:1:42".to_string(),
            display_session_id: Some("display-1".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: 1,
            last_observed_unix_ms: 2,
            bind_addr: None,
            udp_port: None,
            client_addr: None,
            cmdline: "mosh-server-real".to_string(),
            metrics: SessionMetrics::default(),
        }
    }

    #[test]
    fn session_label_prefers_display_id() {
        assert_eq!(session_label(&summary()), "display-1");
    }

    #[test]
    fn incomplete_window_is_rendered_as_warming() {
        assert_eq!(fmt_windowed_pct(Some(1.2), false), "warming");
        assert_eq!(fmt_windowed_pct(Some(1.2), true), "1.2%");
    }

    #[test]
    fn retransmit_sparkline_points_preserve_missing_and_use_fixed_range() {
        assert_eq!(sparkline_point_from_pct(None), None);
        assert_eq!(sparkline_point_from_pct(Some(f64::NAN)), None);
        assert_eq!(sparkline_point_from_pct(Some(-3.2)), Some(0));
        assert_eq!(sparkline_point_from_pct(Some(1.49)), Some(1));
        assert_eq!(sparkline_point_from_pct(Some(1.5)), Some(2));
        assert_eq!(sparkline_point_from_pct(Some(101.0)), Some(100));
    }

    #[tokio::test]
    async fn bounded_response_reader_rejects_oversized_payloads() {
        let (mut writer, mut reader) = tokio::io::duplex(MAX_HTTP_RESPONSE_BYTES + 1024);
        tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; MAX_HTTP_RESPONSE_BYTES + 1])
                .await
                .expect("write oversized payload");
        });

        let error = read_bounded_response(&mut reader, Duration::from_secs(2))
            .await
            .expect_err("reject oversized response");
        assert!(error.to_string().contains("response exceeded"));
    }

    #[test]
    fn retransmit_history_mapping_does_not_force_warming_points_to_zero() {
        let snapshot = SessionSnapshot {
            summary: summary(),
            total_history_points: 3,
            truncated_history_points: 0,
            history: vec![
                MetricPoint {
                    unix_ms: 1,
                    srtt_ms: None,
                    retransmit_pct_10s: None,
                    remote_state_age_ms: None,
                },
                MetricPoint {
                    unix_ms: 2,
                    srtt_ms: None,
                    retransmit_pct_10s: Some(0.8),
                    remote_state_age_ms: None,
                },
                MetricPoint {
                    unix_ms: 3,
                    srtt_ms: None,
                    retransmit_pct_10s: Some(2.2),
                    remote_state_age_ms: None,
                },
            ],
        };
        let mapped = snapshot
            .history
            .iter()
            .map(|point| sparkline_point_from_pct(point.retransmit_pct_10s))
            .collect::<Vec<_>>();
        assert_eq!(mapped, vec![None, Some(1), Some(2)]);
    }

    #[test]
    fn retransmit_color_tracks_window_threshold_state() {
        let thresholds = HealthThresholds::default();

        let warming = SessionMetrics::default();
        assert_eq!(retransmit_color(&warming, &thresholds), Color::DarkGray);

        let missing = SessionMetrics {
            retransmit_window_10s_complete: true,
            retransmit_window_60s_complete: true,
            ..SessionMetrics::default()
        };
        assert_eq!(retransmit_color(&missing, &thresholds), Color::DarkGray);

        let healthy = SessionMetrics {
            retransmit_pct_10s: Some(0.6),
            retransmit_pct_60s: Some(0.3),
            retransmit_window_10s_complete: true,
            retransmit_window_60s_complete: true,
            ..SessionMetrics::default()
        };
        assert_eq!(retransmit_color(&healthy, &thresholds), Color::Green);

        let warn = SessionMetrics {
            retransmit_pct_10s: Some(3.2),
            retransmit_pct_60s: Some(1.0),
            retransmit_window_10s_complete: true,
            retransmit_window_60s_complete: true,
            ..SessionMetrics::default()
        };
        assert_eq!(retransmit_color(&warn, &thresholds), Color::Yellow);

        let critical = SessionMetrics {
            retransmit_pct_10s: Some(12.0),
            retransmit_pct_60s: Some(10.0),
            retransmit_window_10s_complete: true,
            retransmit_window_60s_complete: true,
            ..SessionMetrics::default()
        };
        assert_eq!(retransmit_color(&critical, &thresholds), Color::Red);
    }

    #[test]
    fn retransmit_window_formatter_explains_window_math() {
        let breakdown = RetransmitWindowBreakdown {
            transmissions_total: Some(12),
            retransmits_total: Some(2),
            state_updates_total: Some(2),
            empty_acks_total: Some(8),
        };
        assert_eq!(
            format_retransmit_window(10, Some(16.6666666667), true, &breakdown),
            "16.7% = 2 resend / 12 tx (updates 2, empty ack 8)"
        );
        assert_eq!(
            format_retransmit_window(10, None, true, &RetransmitWindowBreakdown::default()),
            "unknown (counter fields missing)"
        );
        assert_eq!(
            format_retransmit_window(
                10,
                Some(0.0),
                true,
                &RetransmitWindowBreakdown {
                    transmissions_total: Some(0),
                    retransmits_total: Some(0),
                    state_updates_total: Some(0),
                    empty_acks_total: Some(0),
                }
            ),
            "0.0% = idle window (0 tx)"
        );
        assert_eq!(
            format_retransmit_window(
                10,
                None,
                true,
                &RetransmitWindowBreakdown {
                    transmissions_total: Some(0),
                    retransmits_total: Some(0),
                    state_updates_total: Some(0),
                    empty_acks_total: Some(0),
                }
            ),
            "idle window (0 tx)"
        );
    }

    #[test]
    fn history_summary_reports_span_gap_and_peaks() {
        let snapshot = SessionSnapshot {
            summary: summary(),
            total_history_points: 3,
            truncated_history_points: 0,
            history: vec![
                MetricPoint {
                    unix_ms: 1_000,
                    srtt_ms: Some(12.0),
                    retransmit_pct_10s: Some(1.0),
                    remote_state_age_ms: None,
                },
                MetricPoint {
                    unix_ms: 4_000,
                    srtt_ms: Some(48.0),
                    retransmit_pct_10s: None,
                    remote_state_age_ms: None,
                },
                MetricPoint {
                    unix_ms: 10_000,
                    srtt_ms: Some(33.0),
                    retransmit_pct_10s: Some(9.5),
                    remote_state_age_ms: None,
                },
            ],
        };

        let diagnostics = summarize_history(&snapshot);
        assert_eq!(diagnostics.shown_points, 3);
        assert_eq!(diagnostics.span_ms, Some(9_000));
        assert_eq!(diagnostics.largest_gap_ms, Some(6_000));
        assert_eq!(diagnostics.max_rtt_ms, Some(48.0));
        assert_eq!(diagnostics.max_retransmit_pct, Some(9.5));
    }

    #[test]
    fn health_reasons_surface_threshold_breaches_and_warming_state() {
        let thresholds = HealthThresholds::default();
        let degraded_summary = SessionSummary {
            metrics: SessionMetrics {
                srtt_ms: Some(500.0),
                last_heard_age_ms: Some(6_000),
                retransmit_pct_10s: Some(3.5),
                retransmit_pct_60s: Some(12.0),
                retransmit_window_10s_complete: true,
                retransmit_window_60s_complete: true,
                ..SessionMetrics::default()
            },
            ..summary()
        };
        let reasons = health_reasons(&degraded_summary, &thresholds);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("silence 6.0s >= warn 5.0s"))
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("RTT 500.0ms >= warn 400ms"))
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("RTX10 3.5% >= warn 2.0%"))
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("RTX60 12.0% >= crit 10.0%"))
        );

        let warming = health_reasons(&summary(), &thresholds);
        assert_eq!(warming, vec!["RTX windows warming".to_string()]);

        let idle = SessionSummary {
            metrics: SessionMetrics {
                retransmit_window_10s_complete: true,
                retransmit_window_60s_complete: true,
                retransmit_window_10s_breakdown: RetransmitWindowBreakdown {
                    transmissions_total: Some(0),
                    retransmits_total: Some(0),
                    state_updates_total: Some(0),
                    empty_acks_total: Some(0),
                },
                retransmit_window_60s_breakdown: RetransmitWindowBreakdown {
                    transmissions_total: Some(0),
                    retransmits_total: Some(0),
                    state_updates_total: Some(0),
                    empty_acks_total: Some(0),
                },
                ..SessionMetrics::default()
            },
            ..summary()
        };
        assert_eq!(
            health_reasons(&idle, &thresholds),
            vec!["RTX windows idle".to_string()]
        );
    }

    #[test]
    fn duration_formatter_uses_human_units() {
        assert_eq!(fmt_duration_ms(Some(900)), "900ms");
        assert_eq!(fmt_duration_ms(Some(1_500)), "1.5s");
        assert_eq!(fmt_duration_ms(Some(90_000)), "1.5m");
        assert_eq!(fmt_duration_ms(Some(7_200_000)), "2.0h");
    }
}
