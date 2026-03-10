// SPDX-License-Identifier: GPL-3.0-or-later

//! Local HTTP-over-Unix API and latest-state snapshot stream.
//!
//! ## Rationale
//! Keep the UI and other local tooling on a small, dependency-free HTTP
//! surface exposed over an owner-only Unix socket instead of adding a separate
//! RPC protocol.
//!
//! ## Security Boundaries
//! * The Unix socket is owner-only and therefore trusted differently from the
//!   optional TCP metrics listener.
//! * Export surfaces are intentionally bounded and return truncation metadata.
//! * The event stream is latest-state NDJSON, not a replayable event log.
//!
//! ## References
//! * `docs/design/modularisation-and-boundaries.md`

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use moshwatch_core::{
    API_SCHEMA_VERSION, ApiConfigResponse, ApiHistoryResponse, ApiSessionControlResponse,
    ApiSessionResponse, ApiSessionsResponse, EventStreamEvent, EventStreamFrame, ObserverInfo,
    SessionControlAction, remove_socket_if_present, set_socket_owner_only,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{RwLock, Semaphore, watch},
    time::{MissedTickBehavior, interval, timeout},
};

use crate::{
    discovery::{is_supported_mosh_server_metadata, read_process_metadata},
    history::HistoryStore,
    metrics::render_metrics,
    runtime_stats::RuntimeStats,
    state::{ExportedSummaries, ServiceState},
};

pub type SharedState = Arc<RwLock<ServiceState>>;
const API_CONNECTION_SLOTS: usize = 64;
pub const STREAM_CONNECTION_SLOTS: usize = 8;
pub const HISTORY_QUERY_SLOTS: usize = 4;
pub const MAX_EXPORTED_SESSIONS: usize = 512;
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct SnapshotHub {
    observer: ObserverInfo,
    tx: watch::Sender<EventStreamFrame>,
    sequence: Arc<AtomicU64>,
}

impl SnapshotHub {
    pub fn new(observer: ObserverInfo) -> Self {
        let (tx, _) = watch::channel(EventStreamFrame {
            schema_version: API_SCHEMA_VERSION,
            observer: observer.clone(),
            event: EventStreamEvent::Snapshot,
            sequence: Some(0),
            generated_at_unix_ms: moshwatch_core::time::unix_time_ms(),
            total_sessions: Some(0),
            truncated_session_count: Some(0),
            dropped_sessions_total: Some(0),
            sessions: Some(Vec::new()),
        });
        Self {
            observer,
            tx,
            sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn publish_snapshot(&self, export: ExportedSummaries, now_ms: i64) {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        self.tx.send_replace(EventStreamFrame {
            schema_version: API_SCHEMA_VERSION,
            observer: self.observer.clone(),
            event: EventStreamEvent::Snapshot,
            sequence: Some(sequence),
            generated_at_unix_ms: now_ms,
            total_sessions: Some(export.total_sessions),
            truncated_session_count: Some(export.truncated_session_count),
            dropped_sessions_total: Some(export.dropped_sessions_total),
            sessions: Some(export.sessions),
        });
    }

    pub fn subscribe(&self) -> watch::Receiver<EventStreamFrame> {
        self.tx.subscribe()
    }

    /// Build a heartbeat frame for idle stream periods.
    ///
    /// Heartbeats intentionally carry no sequence and no session payload so
    /// clients do not mistake them for a missed snapshot.
    pub fn heartbeat_frame(&self, now_ms: i64) -> EventStreamFrame {
        EventStreamFrame {
            schema_version: API_SCHEMA_VERSION,
            observer: self.observer.clone(),
            event: EventStreamEvent::Heartbeat,
            sequence: None,
            generated_at_unix_ms: now_ms,
            total_sessions: None,
            truncated_session_count: None,
            dropped_sessions_total: None,
            sessions: None,
        }
    }
}

#[derive(Clone)]
pub struct AppContext {
    pub observer: ObserverInfo,
    pub state: SharedState,
    pub snapshots: SnapshotHub,
    pub history: Option<Arc<HistoryStore>>,
    pub runtime_stats: RuntimeStats,
    pub stream_heartbeat_ms: u64,
    pub stream_slots: Arc<Semaphore>,
    pub history_query_slots: Arc<Semaphore>,
}

pub async fn run_api(context: AppContext, socket_path: PathBuf) -> Result<()> {
    remove_socket_if_present(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind api socket {}", socket_path.display()))?;
    set_socket_owner_only(&socket_path)?;
    let connection_slots = Arc::new(Semaphore::new(API_CONNECTION_SLOTS));
    loop {
        let (stream, _) = listener.accept().await.context("accept api connection")?;
        let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
            let mut stream = stream;
            let _ = write_response_with_timeout(
                &mut stream,
                503,
                b"{\"error\":\"api server busy\"}",
                "application/json",
            )
            .await;
            continue;
        };
        let context = context.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, context).await {
                tracing::warn!("api request failed: {error:#}");
            }
        });
    }
}

async fn handle_connection(mut stream: UnixStream, context: AppContext) -> Result<()> {
    let request = match timeout(Duration::from_secs(2), read_request_head(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            let body = format!("{{\"error\":\"bad request: {error}\"}}");
            write_response_with_timeout(&mut stream, 400, body.as_bytes(), "application/json")
                .await?;
            return Ok(());
        }
        Err(_) => {
            write_response_with_timeout(
                &mut stream,
                408,
                b"{\"error\":\"request timeout\"}",
                "application/json",
            )
            .await?;
            return Ok(());
        }
    };
    if request.trim().is_empty() {
        return Ok(());
    }
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    if method != "GET" && method != "POST" {
        write_response_with_timeout(
            &mut stream,
            405,
            b"{\"error\":\"method not allowed\"}",
            "application/json",
        )
        .await?;
        return Ok(());
    }

    let (path, query) = split_target(target);
    if path == "/v1/events/stream" {
        return stream_events(stream, context).await;
    }

    let (status, body, content_type) = match build_response(method, path, query, context).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!("api request processing failed: {error:#}");
            (
                500,
                b"{\"error\":\"internal server error\"}".to_vec(),
                "application/json",
            )
        }
    };
    write_response_with_timeout(&mut stream, status, &body, content_type).await
}

async fn stream_events(mut stream: UnixStream, context: AppContext) -> Result<()> {
    let Ok(_stream_permit) = context.stream_slots.clone().try_acquire_owned() else {
        write_response_with_timeout(
            &mut stream,
            503,
            b"{\"error\":\"event stream busy\"}",
            "application/json",
        )
        .await?;
        return Ok(());
    };

    timeout(
        STREAM_WRITE_TIMEOUT,
        write_streaming_headers(&mut stream, 200, "application/x-ndjson"),
    )
    .await
    .context("write event stream headers timed out")??;
    let mut receiver = context.snapshots.subscribe();
    let initial = receiver.borrow().clone();
    timeout(
        STREAM_WRITE_TIMEOUT,
        write_ndjson_frame(&mut stream, &initial),
    )
    .await
    .context("write initial event stream frame timed out")??;
    let mut heartbeat = interval(Duration::from_millis(context.stream_heartbeat_ms));
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    heartbeat.tick().await;
    loop {
        // This stream is "latest snapshot plus heartbeat", not a durable event
        // history. Snapshot frames advance sequence numbers; heartbeats do not.
        tokio::select! {
            changed = receiver.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let frame = receiver.borrow().clone();
                timeout(STREAM_WRITE_TIMEOUT, write_ndjson_frame(&mut stream, &frame))
                    .await
                    .context("write event stream snapshot timed out")??;
            }
            _ = heartbeat.tick() => {
                let frame = context.snapshots.heartbeat_frame(moshwatch_core::time::unix_time_ms());
                timeout(STREAM_WRITE_TIMEOUT, write_ndjson_frame(&mut stream, &frame))
                    .await
                    .context("write event stream heartbeat timed out")??;
            }
        }
    }
}

async fn build_response(
    method: &str,
    path: &str,
    query: Option<&str>,
    context: AppContext,
) -> Result<(u16, Vec<u8>, &'static str)> {
    let now_ms = moshwatch_core::time::unix_time_ms();
    Ok(match (method, path) {
        ("GET", "/v1/sessions") => {
            let guard = context.state.read().await;
            let export = guard.export_summaries(now_ms, MAX_EXPORTED_SESSIONS);
            let response = ApiSessionsResponse {
                observer: context.observer.clone(),
                generated_at_unix_ms: now_ms,
                total_sessions: export.total_sessions,
                truncated_session_count: export.truncated_session_count,
                dropped_sessions_total: export.dropped_sessions_total,
                sessions: export.sessions,
            };
            (
                200,
                serde_json::to_vec(&response).context("encode sessions response")?,
                "application/json",
            )
        }
        ("GET", "/v1/config") => {
            let guard = context.state.read().await;
            let response = ApiConfigResponse {
                observer: context.observer.clone(),
                generated_at_unix_ms: now_ms,
                config: guard.config().clone(),
            };
            (
                200,
                serde_json::to_vec(&response).context("encode config response")?,
                "application/json",
            )
        }
        ("GET", "/metrics") => {
            let guard = context.state.read().await;
            let export =
                guard.export_summaries(now_ms, crate::metrics::MAX_METRICS_RENDERED_SESSIONS);
            // The owner-only Unix socket may expose `/metrics` without bearer
            // auth because access is already constrained by filesystem
            // permissions. The separate TCP metrics listener always enforces a
            // bearer token even on loopback; both routes intentionally share
            // the same renderer.
            (
                200,
                render_metrics(
                    &context.observer,
                    &export,
                    context.history.as_ref().map(|store| store.stats_snapshot()),
                    context.runtime_stats.snapshot(),
                )
                .into_bytes(),
                "text/plain; version=0.0.4",
            )
        }
        ("GET", _) if path.starts_with("/v1/sessions/") => {
            let session_id = path.trim_start_matches("/v1/sessions/");
            let guard = context.state.read().await;
            if let Some(session) = guard.session_detail(session_id, now_ms) {
                let response = ApiSessionResponse {
                    observer: context.observer.clone(),
                    generated_at_unix_ms: now_ms,
                    session,
                };
                (
                    200,
                    serde_json::to_vec(&response).context("encode session response")?,
                    "application/json",
                )
            } else {
                (
                    404,
                    b"{\"error\":\"session not found\"}".to_vec(),
                    "application/json",
                )
            }
        }
        ("POST", _) if path.starts_with("/v1/sessions/") && path.ends_with("/terminate") => {
            let session_id = path
                .trim_start_matches("/v1/sessions/")
                .trim_end_matches("/terminate")
                .trim_end_matches('/');
            terminate_session(context, session_id, now_ms).await?
        }
        ("GET", _) if path.starts_with("/v1/history/") => match context.history.clone() {
            Some(history) => {
                let Ok(_permit) = context.history_query_slots.clone().try_acquire_owned() else {
                    return Ok((
                        503,
                        b"{\"error\":\"history query busy\"}".to_vec(),
                        "application/json",
                    ));
                };
                let session_id = path.trim_start_matches("/v1/history/");
                let since_seconds = match parse_nonnegative_i64_query(query, "since_seconds") {
                    Ok(value) => value.unwrap_or(3_600),
                    Err(error) => {
                        return Ok((
                            400,
                            format!("{{\"error\":\"bad request: {error}\"}}").into_bytes(),
                            "application/json",
                        ));
                    }
                };
                let since_seconds = since_seconds.min(history.retention_window_secs());
                let limit = match parse_usize_query(query, "limit") {
                    Ok(value) => value.unwrap_or(1_000),
                    Err(error) => {
                        return Ok((
                            400,
                            format!("{{\"error\":\"bad request: {error}\"}}").into_bytes(),
                            "application/json",
                        ));
                    }
                };
                let since_unix_ms = now_ms.saturating_sub(since_seconds.saturating_mul(1_000));
                let session_id = session_id.to_string();
                let query_session_id = session_id.clone();
                let samples = tokio::task::spawn_blocking(move || {
                    history.query_session(&query_session_id, since_unix_ms, limit)
                })
                .await
                .context("wait for history query task")??;
                let response = ApiHistoryResponse {
                    observer: context.observer.clone(),
                    generated_at_unix_ms: now_ms,
                    session_id,
                    samples,
                };
                (
                    200,
                    serde_json::to_vec(&response).context("encode history response")?,
                    "application/json",
                )
            }
            None => (
                501,
                b"{\"error\":\"history persistence is disabled\"}".to_vec(),
                "application/json",
            ),
        },
        _ => (
            404,
            b"{\"error\":\"not found\"}".to_vec(),
            "application/json",
        ),
    })
}

async fn terminate_session(
    context: AppContext,
    session_id: &str,
    now_ms: i64,
) -> Result<(u16, Vec<u8>, &'static str)> {
    let Some(summary) = context
        .state
        .read()
        .await
        .session_summary(session_id, now_ms)
    else {
        return Ok((
            404,
            b"{\"error\":\"session not found\"}".to_vec(),
            "application/json",
        ));
    };

    let metadata = match read_process_metadata(summary.pid) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Ok((
                409,
                b"{\"error\":\"tracked process is no longer available\"}".to_vec(),
                "application/json",
            ));
        }
    };
    // Revalidate the process start time before signaling so a recycled PID
    // cannot target the wrong process. These 409s are deliberate "tracked
    // state changed underneath you" responses, not internal server faults.
    if metadata.started_at_unix_ms != summary.started_at_unix_ms {
        return Ok((
            409,
            b"{\"error\":\"tracked pid no longer matches the recorded session\"}".to_vec(),
            "application/json",
        ));
    }
    if !is_supported_mosh_server_metadata(&metadata) {
        return Ok((
            409,
            b"{\"error\":\"tracked pid is no longer a supported mosh server\"}".to_vec(),
            "application/json",
        ));
    }

    // SAFETY: `kill(2)` does not dereference the pid or signal values. The pid
    // is a validated tracked session pid, and SIGTERM is an explicit constant.
    let rc = unsafe { libc::kill(summary.pid, libc::SIGTERM) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok((
                409,
                b"{\"error\":\"tracked process exited before signal delivery\"}".to_vec(),
                "application/json",
            ));
        }
        return Err(error).with_context(|| format!("send SIGTERM to pid {}", summary.pid));
    }

    let response = ApiSessionControlResponse {
        observer: context.observer.clone(),
        generated_at_unix_ms: now_ms,
        session_id: summary.session_id,
        pid: summary.pid,
        action: SessionControlAction::Terminate,
    };
    Ok((
        200,
        serde_json::to_vec(&response).context("encode session control response")?,
        "application/json",
    ))
}

fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

fn parse_query_value<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?
        .split('&')
        .filter(|pair| !pair.is_empty())
        .find_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name == key).then_some(value)
        })
}

fn parse_nonnegative_i64_query(query: Option<&str>, key: &str) -> Result<Option<i64>> {
    let Some(value) = parse_query_value(query, key) else {
        return Ok(None);
    };
    let parsed = value
        .parse::<i64>()
        .with_context(|| format!("invalid {key} query parameter"))?;
    if parsed < 0 {
        anyhow::bail!("{key} must be non-negative");
    }
    Ok(Some(parsed))
}

fn parse_usize_query(query: Option<&str>, key: &str) -> Result<Option<usize>> {
    let Some(value) = parse_query_value(query, key) else {
        return Ok(None);
    };
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("invalid {key} query parameter"))?;
    if parsed == 0 {
        anyhow::bail!("{key} must be greater than zero");
    }
    Ok(Some(parsed))
}

async fn read_request_head<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
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
    S: AsyncWrite + Unpin,
{
    write_headers(stream, status, content_type, Some(body.len())).await?;
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
    S: AsyncWrite + Unpin,
{
    timeout(
        RESPONSE_WRITE_TIMEOUT,
        write_response(stream, status, body, content_type),
    )
    .await
    .context("write response timed out")?
}

async fn write_streaming_headers<S>(stream: &mut S, status: u16, content_type: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_headers(stream, status, content_type, None).await
}

async fn write_headers<S>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    content_length: Option<usize>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let mut header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nConnection: close\r\nCache-Control: no-store\r\n"
    );
    if let Some(content_length) = content_length {
        header.push_str(&format!("Content-Length: {content_length}\r\n"));
    }
    header.push_str("\r\n");
    stream
        .write_all(header.as_bytes())
        .await
        .context("write response header")?;
    stream.flush().await.context("flush response header")
}

async fn write_ndjson_frame<S>(stream: &mut S, frame: &EventStreamFrame) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(frame).context("encode event stream frame")?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .await
        .context("write ndjson frame")?;
    stream.flush().await.context("flush ndjson frame")
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc, time::Duration};

    use moshwatch_core::{AppConfig, ObserverInfo, TelemetryEvent, TelemetryEventKind};
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        sync::{RwLock, Semaphore},
        task::JoinHandle,
        time::sleep,
    };

    use super::{
        AppContext, HISTORY_QUERY_SLOTS, MAX_EXPORTED_SESSIONS, STREAM_CONNECTION_SLOTS,
        SharedState, SnapshotHub, run_api,
    };
    use crate::{
        history::HistoryStore,
        runtime_stats::RuntimeStats,
        state::{ServiceState, instrumented_session_id},
    };

    fn observer() -> ObserverInfo {
        ObserverInfo {
            node_name: "node-1".to_string(),
            system_id: "system-1".to_string(),
        }
    }

    async fn spawn_api(
        state: SharedState,
        snapshots: SnapshotHub,
        history: Option<Arc<HistoryStore>>,
        socket_path: &Path,
    ) -> JoinHandle<()> {
        spawn_api_with_stream_slots(
            state,
            snapshots,
            history,
            socket_path,
            Arc::new(Semaphore::new(STREAM_CONNECTION_SLOTS)),
        )
        .await
    }

    async fn spawn_api_with_stream_slots(
        state: SharedState,
        snapshots: SnapshotHub,
        history: Option<Arc<HistoryStore>>,
        socket_path: &Path,
        stream_slots: Arc<Semaphore>,
    ) -> JoinHandle<()> {
        let context = AppContext {
            observer: observer(),
            state,
            snapshots,
            history,
            runtime_stats: RuntimeStats::default(),
            stream_heartbeat_ms: 100,
            stream_slots,
            history_query_slots: Arc::new(Semaphore::new(HISTORY_QUERY_SLOTS)),
        };
        let socket_path = socket_path.to_path_buf();
        tokio::spawn(async move {
            run_api(context, socket_path).await.expect("run api");
        })
    }

    async fn wait_for_socket(path: &Path) {
        for _ in 0..50 {
            if path.exists() {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("socket {} was not created", path.display());
    }

    async fn request(socket_path: &Path, target: &str) -> String {
        request_method(socket_path, "GET", target).await
    }

    async fn request_method(socket_path: &Path, method: &str, target: &str) -> String {
        let mut stream = UnixStream::connect(socket_path).await.expect("connect");
        let request =
            format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        String::from_utf8(response).expect("utf8 response")
    }

    fn sample_event(unix_ms: i64) -> TelemetryEvent {
        TelemetryEvent {
            event: TelemetryEventKind::SessionTick,
            display_session_id: Some("display-1".to_string()),
            pid: 42,
            unix_ms,
            started_at_unix_ms: Some(1_000),
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001".to_string()),
            last_heard_age_ms: Some(10),
            remote_state_age_ms: Some(10),
            srtt_ms: Some(12.0),
            rttvar_ms: Some(3.0),
            last_rtt_ms: Some(11.0),
            packets_tx_total: Some(10),
            packets_rx_total: Some(9),
            retransmits_total: Some(1),
            empty_acks_tx_total: Some(0),
            state_updates_tx_total: Some(9),
            state_updates_rx_total: Some(9),
            duplicate_states_rx_total: Some(0),
            out_of_order_states_rx_total: Some(0),
            cmdline: Some("mosh-server-real".to_string()),
            shutdown: Some(false),
        }
    }

    #[tokio::test]
    async fn sessions_endpoint_returns_export_metadata() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let config = AppConfig {
            max_tracked_sessions: 1,
            ..AppConfig::default()
        };
        let state = Arc::new(RwLock::new(ServiceState::new(config)));
        let snapshots = SnapshotHub::new(observer());
        for idx in 0..2 {
            let mut event = sample_event(2_000 + idx);
            event.pid = 42 + idx as i32;
            event.started_at_unix_ms = Some(1_000 + idx);
            let session_id =
                instrumented_session_id(event.pid, event.started_at_unix_ms.expect("start"));
            state.write().await.apply_telemetry(session_id, event);
        }
        snapshots.publish_snapshot(
            state
                .read()
                .await
                .export_summaries(3_000, MAX_EXPORTED_SESSIONS),
            3_000,
        );

        let task = spawn_api(state, snapshots, None, &socket_path).await;
        wait_for_socket(&socket_path).await;

        let response = request(&socket_path, "/v1/sessions").await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(
            response.contains("\"observer\":{\"node_name\":\"node-1\",\"system_id\":\"system-1\"}")
        );
        assert!(response.contains("\"total_sessions\":1"));
        assert!(response.contains("\"dropped_sessions_total\":1"));
        assert!(response.contains("\"truncated_session_count\":0"));
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus_text() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());
        let session_id = instrumented_session_id(42, 1_000);
        state
            .write()
            .await
            .apply_telemetry(session_id, sample_event(2_000));
        snapshots.publish_snapshot(
            state
                .read()
                .await
                .export_summaries(2_000, MAX_EXPORTED_SESSIONS),
            2_000,
        );

        let task = spawn_api(state, snapshots, None, &socket_path).await;
        wait_for_socket(&socket_path).await;

        let response = request(&socket_path, "/metrics").await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(
            response
                .contains("moshwatch_observer_info{node_name=\"node-1\",system_id=\"system-1\"} 1")
        );
        assert!(response.contains("moshwatch_session_srtt_ms"));
        assert!(response.contains("display_session_id=\"display-1\""));
    }

    #[tokio::test]
    async fn history_endpoint_returns_persisted_samples() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let history_store = Arc::new(HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            128,
            1024 * 1024,
        ));
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());
        let session_id = instrumented_session_id(42, 1_000);
        state
            .write()
            .await
            .apply_telemetry(session_id.clone(), sample_event(2_000));
        let exported = state
            .read()
            .await
            .export_summaries(2_000, MAX_EXPORTED_SESSIONS);
        history_store
            .record_summaries(2_000, &exported.sessions)
            .expect("record summaries");
        snapshots.publish_snapshot(exported, 2_000);

        let task = spawn_api(state, snapshots, Some(history_store), &socket_path).await;
        wait_for_socket(&socket_path).await;

        let response = request(
            &socket_path,
            &format!("/v1/history/{session_id}?since_seconds=60"),
        )
        .await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"samples\""));
        assert!(
            response.contains("\"observer\":{\"node_name\":\"node-1\",\"system_id\":\"system-1\"}")
        );
        assert!(response.contains(&session_id));
    }

    #[tokio::test]
    async fn terminate_endpoint_returns_not_found_for_unknown_session() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());

        let task = spawn_api(state, snapshots, None, &socket_path).await;
        wait_for_socket(&socket_path).await;

        let response = request_method(
            &socket_path,
            "POST",
            "/v1/sessions/instrumented:1000:42/terminate",
        )
        .await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(response.contains("session not found"));
    }

    #[tokio::test]
    async fn terminate_endpoint_rejects_stale_pid() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());
        let mut event = sample_event(2_000);
        event.pid = 999_999;
        event.started_at_unix_ms = Some(1_000);
        let session_id = instrumented_session_id(999_999, 1_000);
        state.write().await.apply_telemetry(session_id, event);

        let task = spawn_api(state, snapshots, None, &socket_path).await;
        wait_for_socket(&socket_path).await;

        let response = request_method(
            &socket_path,
            "POST",
            "/v1/sessions/instrumented:1000:999999/terminate",
        )
        .await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 409 Conflict"));
        assert!(response.contains("tracked process is no longer available"));
    }

    #[tokio::test]
    async fn history_endpoint_rejects_negative_since_seconds() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let history_store = Arc::new(HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            128,
            1024 * 1024,
        ));
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());

        let task = spawn_api(state, snapshots, Some(history_store), &socket_path).await;
        wait_for_socket(&socket_path).await;

        let response = request(
            &socket_path,
            "/v1/history/instrumented:1000:42?since_seconds=-1",
        )
        .await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("since_seconds must be non-negative"));
    }

    #[tokio::test]
    async fn history_endpoint_rejects_zero_limit() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let history_store = Arc::new(HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            128,
            1024 * 1024,
        ));
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());

        let task = spawn_api(state, snapshots, Some(history_store), &socket_path).await;
        wait_for_socket(&socket_path).await;

        let response = request(&socket_path, "/v1/history/instrumented:1000:42?limit=0").await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("limit must be greater than zero"));
    }

    #[tokio::test]
    async fn event_stream_returns_busy_when_stream_slots_are_exhausted() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());

        let task = spawn_api_with_stream_slots(
            state,
            snapshots,
            None,
            &socket_path,
            Arc::new(Semaphore::new(0)),
        )
        .await;
        wait_for_socket(&socket_path).await;

        let response = request(&socket_path, "/v1/events/stream").await;
        task.abort();

        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("event stream busy"));
    }

    #[tokio::test]
    async fn event_stream_starts_with_snapshot_frame() {
        let tempdir = tempdir().expect("tempdir");
        let socket_path = tempdir.path().join("api.sock");
        let state = Arc::new(RwLock::new(ServiceState::new(AppConfig::default())));
        let snapshots = SnapshotHub::new(observer());
        let session_id = instrumented_session_id(42, 1_000);
        state
            .write()
            .await
            .apply_telemetry(session_id.clone(), sample_event(2_000));
        snapshots.publish_snapshot(
            state
                .read()
                .await
                .export_summaries(2_000, MAX_EXPORTED_SESSIONS),
            2_000,
        );

        let task = spawn_api(state, snapshots, None, &socket_path).await;
        wait_for_socket(&socket_path).await;

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
        stream
            .write_all(
                b"GET /v1/events/stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write request");
        stream.flush().await.expect("flush");

        let mut buffer = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let mut chunk = [0u8; 1024];
            let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
                .await
                .expect("read timeout")
                .expect("read");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(split) = buffer.windows(4).position(|window| window == b"\r\n\r\n")
                && buffer[split + 4..].contains(&b'\n')
            {
                break;
            }
        }
        task.abort();

        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"event\":\"snapshot\""));
        assert!(
            response.contains("\"observer\":{\"node_name\":\"node-1\",\"system_id\":\"system-1\"}")
        );
        assert!(response.contains(&session_id));
    }
}
