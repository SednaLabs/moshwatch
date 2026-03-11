// SPDX-License-Identifier: GPL-3.0-or-later

//! Prometheus rendering and optional TCP metrics listener.
//!
//! The same renderer is shared by the owner-only Unix-socket `/metrics` route
//! and the optional TCP listener. The trust model differs: Unix-socket access
//! is filesystem-gated, while the TCP listener always requires a bearer token,
//! even on loopback.

use std::{fmt::Write as _, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use moshwatch_core::{HealthState, ObserverInfo, SessionSummary};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{RwLock, Semaphore},
    time::timeout,
};

use crate::{
    history::{HistoryStatsSnapshot, HistoryStore},
    runtime_stats::{DAEMON_WORKER_THREADS, RuntimeStats, RuntimeStatsSnapshot},
    state::{ExportedSummaries, ServiceState},
};

pub type SharedState = Arc<RwLock<ServiceState>>;
const METRICS_CONNECTION_SLOTS: usize = 64;
const METRICS_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_METRICS_RENDERED_SESSIONS: usize = 256;

pub fn render_metrics(
    observer: &ObserverInfo,
    export: &ExportedSummaries,
    history: Option<HistoryStatsSnapshot>,
    runtime: RuntimeStatsSnapshot,
) -> String {
    let mut output = String::new();
    output.push_str("# HELP moshwatch_build_info Build information for moshwatchd.\n");
    output.push_str("# TYPE moshwatch_build_info gauge\n");
    let _ = writeln!(
        output,
        "moshwatch_build_info{{version=\"{}\"}} 1",
        escape_label(env!("CARGO_PKG_VERSION"))
    );
    output.push_str("# HELP moshwatch_observer_info Host identity for this moshwatchd instance.\n");
    output.push_str("# TYPE moshwatch_observer_info gauge\n");
    let _ = writeln!(
        output,
        "moshwatch_observer_info{{node_name=\"{}\",system_id=\"{}\"}} 1",
        escape_label(&observer.node_name),
        escape_label(&observer.system_id),
    );

    output.push_str("# HELP moshwatch_sessions Number of sessions by kind.\n");
    output.push_str("# TYPE moshwatch_sessions gauge\n");
    let _ = writeln!(
        output,
        "moshwatch_sessions{{kind=\"instrumented\"}} {}",
        export.instrumented_sessions
    );
    let _ = writeln!(
        output,
        "moshwatch_sessions{{kind=\"legacy\"}} {}",
        export.legacy_sessions
    );
    output.push_str(
        "# HELP moshwatch_metrics_rendered_sessions Number of session series rendered into the Prometheus export.\n",
    );
    output.push_str("# TYPE moshwatch_metrics_rendered_sessions gauge\n");
    let _ = writeln!(
        output,
        "moshwatch_metrics_rendered_sessions {}",
        export.sessions.len()
    );
    output.push_str(
        "# HELP moshwatch_metrics_truncated_sessions Number of sessions omitted from the Prometheus export due to render caps.\n",
    );
    output.push_str("# TYPE moshwatch_metrics_truncated_sessions gauge\n");
    let _ = writeln!(
        output,
        "moshwatch_metrics_truncated_sessions {}",
        export.truncated_session_count
    );
    output.push_str(
        "# HELP moshwatch_runtime_dropped_sessions_total Number of session tracking admissions or records dropped due to capacity limits.\n",
    );
    output.push_str("# TYPE moshwatch_runtime_dropped_sessions_total counter\n");
    let _ = writeln!(
        output,
        "moshwatch_runtime_dropped_sessions_total {}",
        export.dropped_sessions_total
    );
    output.push_str(
        "# HELP moshwatch_runtime_worker_threads Configured Tokio worker threads for moshwatchd.\n",
    );
    output.push_str("# TYPE moshwatch_runtime_worker_threads gauge\n");
    let _ = writeln!(
        output,
        "moshwatch_runtime_worker_threads {}",
        DAEMON_WORKER_THREADS
    );
    output.push_str(
        "# HELP moshwatch_runtime_loop_interval_ms Configured interval for periodic daemon loops in milliseconds.\n",
    );
    output.push_str("# TYPE moshwatch_runtime_loop_interval_ms gauge\n");
    output.push_str(
        "# HELP moshwatch_runtime_loop_last_duration_ms Last observed runtime for a periodic daemon loop in milliseconds.\n",
    );
    output.push_str("# TYPE moshwatch_runtime_loop_last_duration_ms gauge\n");
    output.push_str(
        "# HELP moshwatch_runtime_loop_overruns_total Number of times a periodic daemon loop took longer than its configured interval.\n",
    );
    output.push_str("# TYPE moshwatch_runtime_loop_overruns_total counter\n");
    write_runtime_loop_metrics(
        &mut output,
        "discovery",
        runtime.discovery_interval_ms,
        runtime.discovery_last_duration_ms,
        runtime.discovery_overruns_total,
    );
    write_runtime_loop_metrics(
        &mut output,
        "history",
        runtime.history_interval_ms,
        runtime.history_last_duration_ms,
        runtime.history_overruns_total,
    );
    write_runtime_loop_metrics(
        &mut output,
        "snapshot",
        runtime.snapshot_interval_ms,
        runtime.snapshot_last_duration_ms,
        runtime.snapshot_overruns_total,
    );
    output.push_str(
        "# HELP moshwatch_history_current_bytes Current on-disk bytes retained in persistent history.\n",
    );
    output.push_str("# TYPE moshwatch_history_current_bytes gauge\n");
    let _ = writeln!(
        output,
        "moshwatch_history_current_bytes {}",
        history.map_or(0, |stats| stats.current_bytes)
    );
    output.push_str(
        "# HELP moshwatch_history_written_bytes_total Total history bytes successfully written to disk.\n",
    );
    output.push_str("# TYPE moshwatch_history_written_bytes_total counter\n");
    let _ = writeln!(
        output,
        "moshwatch_history_written_bytes_total {}",
        history.map_or(0, |stats| stats.written_bytes_total)
    );
    output.push_str(
        "# HELP moshwatch_history_write_failures_total Number of failed persistent history writes.\n",
    );
    output.push_str("# TYPE moshwatch_history_write_failures_total counter\n");
    let _ = writeln!(
        output,
        "moshwatch_history_write_failures_total {}",
        history.map_or(0, |stats| stats.write_failures_total)
    );
    output.push_str(
        "# HELP moshwatch_history_prune_failures_total Number of expired history files that failed to prune.\n",
    );
    output.push_str("# TYPE moshwatch_history_prune_failures_total counter\n");
    let _ = writeln!(
        output,
        "moshwatch_history_prune_failures_total {}",
        history.map_or(0, |stats| stats.prune_failures_total)
    );
    output.push_str(
        "# HELP moshwatch_history_dropped_samples_total Number of history samples dropped because persistence exceeded its disk budget.\n",
    );
    output.push_str("# TYPE moshwatch_history_dropped_samples_total counter\n");
    let _ = writeln!(
        output,
        "moshwatch_history_dropped_samples_total {}",
        history.map_or(0, |stats| stats.dropped_samples_total)
    );

    output.push_str("# HELP moshwatch_session_info Static session metadata.\n");
    output.push_str("# TYPE moshwatch_session_info gauge\n");
    output.push_str("# HELP moshwatch_session_health_level Session health severity: ok=0, degraded=1, critical=2, legacy=3.\n");
    output.push_str("# TYPE moshwatch_session_health_level gauge\n");
    output.push_str("# HELP moshwatch_session_srtt_ms Smoothed round-trip time in milliseconds.\n");
    output.push_str("# TYPE moshwatch_session_srtt_ms gauge\n");
    output.push_str("# HELP moshwatch_session_rttvar_ms RTT variance in milliseconds.\n");
    output.push_str("# TYPE moshwatch_session_rttvar_ms gauge\n");
    output.push_str("# HELP moshwatch_session_last_rtt_ms Latest RTT sample in milliseconds.\n");
    output.push_str("# TYPE moshwatch_session_last_rtt_ms gauge\n");
    output.push_str(
        "# HELP moshwatch_session_last_heard_age_ms Age in milliseconds since the daemon last heard any packet from the peer.\n",
    );
    output.push_str("# TYPE moshwatch_session_last_heard_age_ms gauge\n");
    output.push_str(
        "# HELP moshwatch_session_remote_state_age_ms Age in milliseconds since the peer last sent a new remote state.\n",
    );
    output.push_str("# TYPE moshwatch_session_remote_state_age_ms gauge\n");
    output.push_str(
        "# HELP moshwatch_session_retransmit_pct_10s Retransmit ratio over the last 10 seconds.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmit_pct_10s gauge\n");
    output.push_str(
        "# HELP moshwatch_session_retransmit_pct_60s Retransmit ratio over the last 60 seconds.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmit_pct_60s gauge\n");
    output.push_str(
        "# HELP moshwatch_session_retransmit_window_complete Whether the retransmit window is fully populated for a given session and window.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmit_window_complete gauge\n");
    output.push_str(
        "# HELP moshwatch_session_retransmit_window_transmissions Number of transmissions counted inside the retransmit lookback window.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmit_window_transmissions gauge\n");
    output.push_str(
        "# HELP moshwatch_session_retransmit_window_retransmits Number of retransmits counted inside the retransmit lookback window.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmit_window_retransmits gauge\n");
    output.push_str(
        "# HELP moshwatch_session_retransmit_window_state_updates Number of state-update transmissions counted inside the retransmit lookback window.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmit_window_state_updates gauge\n");
    output.push_str(
        "# HELP moshwatch_session_retransmit_window_empty_acks Number of empty-ack transmissions counted inside the retransmit lookback window.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmit_window_empty_acks gauge\n");
    output.push_str("# HELP moshwatch_session_packets_tx_total Total transmitted packets seen by the session.\n");
    output.push_str("# TYPE moshwatch_session_packets_tx_total counter\n");
    output.push_str(
        "# HELP moshwatch_session_packets_rx_total Total received packets seen by the session.\n",
    );
    output.push_str("# TYPE moshwatch_session_packets_rx_total counter\n");
    output.push_str(
        "# HELP moshwatch_session_retransmits_total Total retransmits seen by the session.\n",
    );
    output.push_str("# TYPE moshwatch_session_retransmits_total counter\n");

    for session in &export.sessions {
        let info_labels = info_metric_labels(session);
        let value_labels = value_metric_labels(session);
        let _ = writeln!(output, "moshwatch_session_info{{{info_labels}}} 1");
        let _ = writeln!(
            output,
            "moshwatch_session_health_level{{{value_labels}}} {}",
            health_level(&session.health)
        );
        write_optional_gauge(
            &mut output,
            "moshwatch_session_srtt_ms",
            &value_labels,
            session.metrics.srtt_ms,
        );
        write_optional_gauge(
            &mut output,
            "moshwatch_session_rttvar_ms",
            &value_labels,
            session.metrics.rttvar_ms,
        );
        write_optional_gauge(
            &mut output,
            "moshwatch_session_last_rtt_ms",
            &value_labels,
            session.metrics.last_rtt_ms,
        );
        write_optional_u64(
            &mut output,
            "moshwatch_session_last_heard_age_ms",
            &value_labels,
            session.metrics.last_heard_age_ms,
        );
        write_optional_u64(
            &mut output,
            "moshwatch_session_remote_state_age_ms",
            &value_labels,
            session.metrics.remote_state_age_ms,
        );
        write_optional_gauge(
            &mut output,
            "moshwatch_session_retransmit_pct_10s",
            &value_labels,
            session.metrics.retransmit_pct_10s,
        );
        write_optional_gauge(
            &mut output,
            "moshwatch_session_retransmit_pct_60s",
            &value_labels,
            session.metrics.retransmit_pct_60s,
        );
        write_window_complete(
            &mut output,
            &value_labels,
            "10s",
            session.metrics.retransmit_window_10s_complete,
        );
        write_window_complete(
            &mut output,
            &value_labels,
            "60s",
            session.metrics.retransmit_window_60s_complete,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_transmissions",
            &value_labels,
            "10s",
            session
                .metrics
                .retransmit_window_10s_breakdown
                .transmissions_total,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_transmissions",
            &value_labels,
            "60s",
            session
                .metrics
                .retransmit_window_60s_breakdown
                .transmissions_total,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_retransmits",
            &value_labels,
            "10s",
            session
                .metrics
                .retransmit_window_10s_breakdown
                .retransmits_total,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_retransmits",
            &value_labels,
            "60s",
            session
                .metrics
                .retransmit_window_60s_breakdown
                .retransmits_total,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_state_updates",
            &value_labels,
            "10s",
            session
                .metrics
                .retransmit_window_10s_breakdown
                .state_updates_total,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_state_updates",
            &value_labels,
            "60s",
            session
                .metrics
                .retransmit_window_60s_breakdown
                .state_updates_total,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_empty_acks",
            &value_labels,
            "10s",
            session
                .metrics
                .retransmit_window_10s_breakdown
                .empty_acks_total,
        );
        write_optional_window_u64(
            &mut output,
            "moshwatch_session_retransmit_window_empty_acks",
            &value_labels,
            "60s",
            session
                .metrics
                .retransmit_window_60s_breakdown
                .empty_acks_total,
        );
        write_optional_u64(
            &mut output,
            "moshwatch_session_packets_tx_total",
            &value_labels,
            session.metrics.packets_tx_total,
        );
        write_optional_u64(
            &mut output,
            "moshwatch_session_packets_rx_total",
            &value_labels,
            session.metrics.packets_rx_total,
        );
        write_optional_u64(
            &mut output,
            "moshwatch_session_retransmits_total",
            &value_labels,
            session.metrics.retransmits_total,
        );
    }

    output
}

pub async fn run_metrics_server(
    state: SharedState,
    history: Option<Arc<HistoryStore>>,
    runtime_stats: RuntimeStats,
    observer: ObserverInfo,
    listen_addr: String,
    auth_token: Arc<str>,
) -> Result<()> {
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind metrics listener {listen_addr}"))?;
    let connection_slots = Arc::new(Semaphore::new(METRICS_CONNECTION_SLOTS));
    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("accept metrics connection")?;
        let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
            let mut stream = stream;
            let _ = write_response_with_timeout(
                &mut stream,
                503,
                b"{\"error\":\"metrics server busy\"}",
                "application/json",
            )
            .await;
            continue;
        };
        let state = state.clone();
        let history = history.clone();
        let runtime_stats = runtime_stats.clone();
        let observer = observer.clone();
        let auth_token = auth_token.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_metrics_connection(
                stream,
                state,
                history,
                runtime_stats,
                observer,
                auth_token,
            )
            .await
            {
                tracing::warn!("metrics request from {peer_addr} failed: {error:#}");
            }
        });
    }
}

async fn handle_metrics_connection(
    mut stream: TcpStream,
    state: SharedState,
    history: Option<Arc<HistoryStore>>,
    runtime_stats: RuntimeStats,
    observer: ObserverInfo,
    auth_token: Arc<str>,
) -> Result<()> {
    // Unlike the owner-only Unix-socket API route, the TCP listener is always
    // bearer-protected because network reachability is a broader trust
    // boundary than local filesystem permissions.
    let request = timeout(Duration::from_secs(2), read_request_head(&mut stream))
        .await
        .context("read metrics request timed out")??;
    if request.trim().is_empty() {
        return Ok(());
    }
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if method != "GET" {
        return write_response_with_timeout(
            &mut stream,
            405,
            b"{\"error\":\"method not allowed\"}",
            "application/json",
        )
        .await;
    }
    if path != "/metrics" {
        return write_response_with_timeout(
            &mut stream,
            404,
            b"{\"error\":\"not found\"}",
            "application/json",
        )
        .await;
    }
    if !metrics_request_is_authorized(&request, &auth_token) {
        return timeout(
            METRICS_WRITE_TIMEOUT,
            write_response_with_headers(
                &mut stream,
                401,
                b"{\"error\":\"unauthorized\"}",
                "application/json",
                &[("WWW-Authenticate", "Bearer realm=\"moshwatch-metrics\"")],
            ),
        )
        .await
        .context("write metrics unauthorized response timed out")?;
    }

    let now_ms = moshwatch_core::time::unix_time_ms();
    let export = {
        let guard = state.read().await;
        guard.export_summaries(now_ms, MAX_METRICS_RENDERED_SESSIONS)
    };
    let body = render_metrics(
        &observer,
        &export,
        history.as_ref().map(|store| store.stats_snapshot()),
        runtime_stats.snapshot(),
    );
    timeout(
        METRICS_WRITE_TIMEOUT,
        write_response(
            &mut stream,
            200,
            body.as_bytes(),
            "text/plain; version=0.0.4",
        ),
    )
    .await
    .context("write metrics response timed out")?
}

async fn read_request_head<S>(stream: &mut S) -> Result<String>
where
    S: AsyncReadExt + Unpin,
{
    const MAX_REQUEST_HEAD_BYTES: usize = 16 * 1024;

    let mut buffer = Vec::with_capacity(1024);
    loop {
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&buffer).into_owned());
        }
        if buffer.len() >= MAX_REQUEST_HEAD_BYTES {
            anyhow::bail!("request head exceeded {MAX_REQUEST_HEAD_BYTES} bytes");
        }

        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.context("read request")?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(String::new());
            }
            anyhow::bail!("unexpected eof while reading request");
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

async fn write_response<S>(
    stream: &mut S,
    status: u16,
    body: &[u8],
    content_type: &str,
) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    write_response_with_headers(stream, status, body, content_type, &[]).await
}

async fn write_response_with_headers<S>(
    stream: &mut S,
    status: u16,
    body: &[u8],
    content_type: &str,
    headers: &[(&str, &str)],
) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let status_text = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let mut header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
        body.len()
    );
    for (name, value) in headers {
        header.push_str(name);
        header.push_str(": ");
        header.push_str(value);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");
    stream
        .write_all(header.as_bytes())
        .await
        .context("write response header")?;
    stream
        .write_all(body)
        .await
        .context("write response body")?;
    stream.flush().await.context("flush response")
}

async fn write_response_with_timeout<S>(
    stream: &mut S,
    status: u16,
    body: &[u8],
    content_type: &str,
) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    timeout(
        METRICS_WRITE_TIMEOUT,
        write_response(stream, status, body, content_type),
    )
    .await
    .context("write response timed out")?
}

fn metrics_request_is_authorized(request: &str, expected_token: &str) -> bool {
    let Some(token) = extract_bearer_token(request) else {
        return false;
    };
    constant_time_eq(token.as_bytes(), expected_token.as_bytes())
}

fn extract_bearer_token(request: &str) -> Option<&str> {
    request.lines().skip(1).find_map(|line| {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("authorization") {
            return None;
        }
        let value = value.trim();
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        Some(token.trim())
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max_len {
        let left_byte = left.get(idx).copied().unwrap_or(0);
        let right_byte = right.get(idx).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn info_metric_labels(session: &SessionSummary) -> String {
    let display_id = session.display_session_id.as_deref().unwrap_or("");
    let bind_addr = session.bind_addr.as_deref().unwrap_or("");
    let client_addr = session.client_addr.as_deref().unwrap_or("");
    let current_client_addr = session.peer.current_client_addr.as_deref().unwrap_or("");
    let udp_port = session
        .udp_port
        .map(|value| value.to_string())
        .unwrap_or_default();
    format!(
        "session_id=\"{}\",display_session_id=\"{}\",kind=\"{}\",pid=\"{}\",started_at_unix_ms=\"{}\",bind_addr=\"{}\",udp_port=\"{}\",client_addr=\"{}\",current_client_addr=\"{}\"",
        escape_label(&session.session_id),
        escape_label(display_id),
        escape_label(match session.kind {
            moshwatch_core::SessionKind::Instrumented => "instrumented",
            moshwatch_core::SessionKind::Legacy => "legacy",
        }),
        session.pid,
        session.started_at_unix_ms,
        escape_label(bind_addr),
        escape_label(&udp_port),
        escape_label(client_addr),
        escape_label(current_client_addr),
    )
}

fn value_metric_labels(session: &SessionSummary) -> String {
    let display_id = session.display_session_id.as_deref().unwrap_or("");
    format!(
        "session_id=\"{}\",display_session_id=\"{}\",kind=\"{}\"",
        escape_label(&session.session_id),
        escape_label(display_id),
        escape_label(match session.kind {
            moshwatch_core::SessionKind::Instrumented => "instrumented",
            moshwatch_core::SessionKind::Legacy => "legacy",
        }),
    )
}

fn health_level(health: &HealthState) -> u8 {
    match health {
        HealthState::Ok => 0,
        HealthState::Degraded => 1,
        HealthState::Critical => 2,
        HealthState::Legacy => 3,
    }
}

fn write_optional_gauge(output: &mut String, name: &str, labels: &str, value: Option<f64>) {
    if let Some(value) = value {
        let _ = writeln!(output, "{name}{{{labels}}} {value}");
    }
}

fn write_optional_u64(output: &mut String, name: &str, labels: &str, value: Option<u64>) {
    if let Some(value) = value {
        let _ = writeln!(output, "{name}{{{labels}}} {value}");
    }
}

fn write_window_complete(output: &mut String, labels: &str, window: &str, complete: bool) {
    let _ = writeln!(
        output,
        "moshwatch_session_retransmit_window_complete{{{labels},window=\"{}\"}} {}",
        escape_label(window),
        if complete { 1 } else { 0 }
    );
}

fn write_optional_window_u64(
    output: &mut String,
    name: &str,
    labels: &str,
    window: &str,
    value: Option<u64>,
) {
    let Some(value) = value else {
        return;
    };
    let _ = writeln!(
        output,
        "{name}{{{labels},window=\"{}\"}} {value}",
        escape_label(window)
    );
}

fn write_runtime_loop_metrics(
    output: &mut String,
    loop_name: &str,
    interval_ms: u64,
    last_duration_ms: u64,
    overruns_total: u64,
) {
    if interval_ms == 0 {
        return;
    }
    let loop_name = escape_label(loop_name);
    let _ = writeln!(
        output,
        "moshwatch_runtime_loop_interval_ms{{loop=\"{loop_name}\"}} {interval_ms}"
    );
    let _ = writeln!(
        output,
        "moshwatch_runtime_loop_last_duration_ms{{loop=\"{loop_name}\"}} {last_duration_ms}"
    );
    let _ = writeln!(
        output,
        "moshwatch_runtime_loop_overruns_total{{loop=\"{loop_name}\"}} {overruns_total}"
    );
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use moshwatch_core::{
        HealthState, ObserverInfo, RetransmitWindowBreakdown, SessionKind, SessionMetrics,
        SessionPeerInfo, SessionSummary,
    };

    use super::{extract_bearer_token, metrics_request_is_authorized, render_metrics};
    use crate::runtime_stats::RuntimeStatsSnapshot;
    use crate::{history::HistoryStatsSnapshot, state::ExportedSummaries};

    #[test]
    fn renders_prometheus_metrics_for_sessions() {
        let metrics = render_metrics(
            &ObserverInfo {
                node_name: "node-1".to_string(),
                system_id: "system-1".to_string(),
            },
            &ExportedSummaries {
                total_sessions: 1,
                truncated_session_count: 2,
                instrumented_sessions: 1,
                legacy_sessions: 0,
                dropped_sessions_total: 7,
                sessions: vec![SessionSummary {
                    session_id: "instrumented:1:42".to_string(),
                    display_session_id: Some("display".to_string()),
                    pid: 42,
                    kind: SessionKind::Instrumented,
                    health: HealthState::Degraded,
                    started_at_unix_ms: 1,
                    last_observed_unix_ms: 2,
                    bind_addr: Some("127.0.0.1".to_string()),
                    udp_port: Some(60001),
                    client_addr: Some("192.0.2.10:60001".to_string()),
                    peer: SessionPeerInfo {
                        current_client_addr: Some("192.0.2.10:60001".to_string()),
                        last_client_addr: Some("192.0.2.10:60001".to_string()),
                        ..SessionPeerInfo::default()
                    },
                    cmdline: "mosh-server-real".to_string(),
                    metrics: SessionMetrics {
                        srtt_ms: Some(12.5),
                        last_heard_age_ms: Some(250),
                        remote_state_age_ms: Some(1_250),
                        retransmit_pct_10s: Some(1.2),
                        retransmit_window_10s_complete: true,
                        retransmit_window_10s_breakdown: RetransmitWindowBreakdown {
                            transmissions_total: Some(25),
                            retransmits_total: Some(1),
                            state_updates_total: Some(20),
                            empty_acks_total: Some(4),
                        },
                        ..SessionMetrics::default()
                    },
                }],
            },
            Some(HistoryStatsSnapshot {
                current_bytes: 1024,
                written_bytes_total: 4096,
                write_failures_total: 2,
                prune_failures_total: 5,
                dropped_samples_total: 3,
            }),
            RuntimeStatsSnapshot {
                discovery_interval_ms: 5_000,
                discovery_last_duration_ms: 20,
                discovery_overruns_total: 1,
                history_interval_ms: 10_000,
                history_last_duration_ms: 15,
                history_overruns_total: 0,
                snapshot_interval_ms: 1_000,
                snapshot_last_duration_ms: 4,
                snapshot_overruns_total: 2,
            },
        );

        assert!(metrics.contains("moshwatch_build_info"));
        assert!(
            metrics
                .contains("moshwatch_observer_info{node_name=\"node-1\",system_id=\"system-1\"} 1")
        );
        assert!(metrics.contains("moshwatch_session_srtt_ms"));
        assert!(metrics.contains("moshwatch_session_last_heard_age_ms"));
        assert!(metrics.contains("moshwatch_session_remote_state_age_ms"));
        assert!(metrics.contains("display_session_id=\"display\""));
        assert!(metrics.contains("moshwatch_session_retransmit_window_complete"));
        assert!(metrics.contains("window=\"10s\""));
        assert!(metrics.contains("moshwatch_session_retransmit_window_transmissions"));
        assert!(metrics.contains("moshwatch_session_retransmit_window_retransmits"));
        assert!(metrics.contains("client_addr=\"192.0.2.10:60001\""));
        assert!(metrics.contains("current_client_addr=\"192.0.2.10:60001\""));
        assert!(metrics.contains("moshwatch_metrics_truncated_sessions 2"));
        assert!(metrics.contains("moshwatch_runtime_dropped_sessions_total 7"));
        assert!(metrics.contains("moshwatch_runtime_worker_threads 2"));
        assert!(metrics.contains("moshwatch_runtime_loop_interval_ms{loop=\"discovery\"} 5000"));
        assert!(metrics.contains("moshwatch_runtime_loop_last_duration_ms{loop=\"snapshot\"} 4"));
        assert!(metrics.contains("moshwatch_runtime_loop_overruns_total{loop=\"snapshot\"} 2"));
        assert!(metrics.contains("moshwatch_history_current_bytes 1024"));
        assert!(metrics.contains("moshwatch_history_written_bytes_total 4096"));
        assert!(metrics.contains("moshwatch_history_write_failures_total 2"));
        assert!(metrics.contains("moshwatch_history_prune_failures_total 5"));
        assert!(metrics.contains("moshwatch_history_dropped_samples_total 3"));
        assert!(
            !metrics.contains(
                "moshwatch_session_srtt_ms{session_id=\"instrumented:1:42\",display_session_id=\"display\",kind=\"instrumented\",pid=\"42\""
            )
        );
    }

    #[test]
    fn preserves_compatible_and_current_peer_metric_labels() {
        let metrics = render_metrics(
            &ObserverInfo {
                node_name: "node-1".to_string(),
                system_id: "system-1".to_string(),
            },
            &ExportedSummaries {
                total_sessions: 1,
                truncated_session_count: 0,
                instrumented_sessions: 1,
                legacy_sessions: 0,
                dropped_sessions_total: 0,
                sessions: vec![SessionSummary {
                    session_id: "instrumented:1:42".to_string(),
                    display_session_id: Some("display".to_string()),
                    pid: 42,
                    kind: SessionKind::Instrumented,
                    health: HealthState::Ok,
                    started_at_unix_ms: 1,
                    last_observed_unix_ms: 2,
                    bind_addr: Some("127.0.0.1".to_string()),
                    udp_port: Some(60001),
                    client_addr: Some("192.0.2.10:60001".to_string()),
                    peer: SessionPeerInfo {
                        current_client_addr: None,
                        last_client_addr: Some("192.0.2.10:60001".to_string()),
                        ..SessionPeerInfo::default()
                    },
                    cmdline: "mosh-server-real".to_string(),
                    metrics: SessionMetrics::default(),
                }],
            },
            None,
            RuntimeStatsSnapshot::default(),
        );

        assert!(metrics.contains("client_addr=\"192.0.2.10:60001\""));
        assert!(metrics.contains("current_client_addr=\"\""));
    }

    #[test]
    fn extracts_bearer_token_case_insensitively() {
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret-token\r\n\r\n";
        assert_eq!(extract_bearer_token(request), Some("secret-token"));

        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nauthorization: bearer another-token\r\n\r\n";
        assert_eq!(extract_bearer_token(request), Some("another-token"));
    }

    #[test]
    fn metrics_request_requires_matching_bearer_token() {
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer expected-token\r\n\r\n";
        assert!(metrics_request_is_authorized(request, "expected-token"));
        assert!(!metrics_request_is_authorized(request, "wrong-token"));
        assert!(!metrics_request_is_authorized(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "expected-token"
        ));
    }
}
