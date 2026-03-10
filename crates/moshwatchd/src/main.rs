// SPDX-License-Identifier: GPL-3.0-or-later

//! Daemon entrypoint, task topology, and telemetry trust boundary.
//!
//! ## Rationale
//! This file wires together discovery, verified telemetry ingestion, snapshot
//! publication, persistence, the local API, and optional TCP metrics exposure.
//! The interesting behavior is not in any one loop, but in how they are
//! composed.
//!
//! ## Security Boundaries
//! * Telemetry is accepted only from verified local peers on the owner-only
//!   Unix socket.
//! * Snapshot publication is coalesced latest-state delivery, not a replayable
//!   event log.
//! * Non-loopback TCP metrics exposure stays explicit opt-in.
//!
//! ## References
//! * `docs/design/modularisation-and-boundaries.md`

mod api;
mod discovery;
mod history;
mod metrics;
mod runtime_stats;
mod sanitize;
mod state;

use std::sync::atomic::{AtomicBool, Ordering};
use std::{future::pending, net::SocketAddr, path::PathBuf, sync::Arc};
#[cfg(unix)]
use std::{mem, os::fd::AsRawFd};

use anyhow::{Context, Result};
use clap::Parser;
use moshwatch_core::{
    RuntimePaths, TelemetryEvent, discover_observer_info, remove_socket_if_present,
    set_socket_owner_only,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Notify, RwLock, Semaphore},
    task::JoinHandle,
    time::{Duration, Instant, MissedTickBehavior, interval, sleep_until, timeout_at},
};

use crate::{
    api::{
        AppContext, HISTORY_QUERY_SLOTS, MAX_EXPORTED_SESSIONS, STREAM_CONNECTION_SLOTS,
        SharedState, SnapshotHub,
    },
    discovery::{
        discover_mosh_sessions, expected_instrumented_server_path, is_supported_mosh_server_exe,
        read_process_metadata,
    },
    history::HistoryStore,
    metrics::run_metrics_server,
    runtime_stats::RuntimeStats,
    state::{ServiceState, instrumented_session_id},
};

const MAX_TELEMETRY_FRAME_BYTES: usize = 16 * 1024;
const INITIAL_TELEMETRY_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const TELEMETRY_FRAME_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_INVALID_TELEMETRY_FRAMES: usize = 8;
const METRICS_TOKEN_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct SnapshotTrigger {
    dirty: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl SnapshotTrigger {
    fn request_publish(&self) {
        self.dirty.store(true, Ordering::Release);
        self.notify.notify_one();
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    api_socket: Option<PathBuf>,
    #[arg(long)]
    telemetry_socket: Option<PathBuf>,
    #[arg(long)]
    metrics_listen: Option<String>,
    #[arg(long, default_value_t = false)]
    allow_public_metrics: bool,
    #[arg(long, default_value_t = false)]
    no_write_config: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "moshwatchd=info".to_string()),
        )
        .init();

    let args = Args::parse();
    let mut paths = RuntimePaths::discover();
    if let Some(api_socket) = args.api_socket {
        paths.api_socket = api_socket;
    }
    if let Some(telemetry_socket) = args.telemetry_socket {
        paths.telemetry_socket = telemetry_socket;
    }

    paths.ensure_runtime_dir()?;
    paths.ensure_state_dir()?;
    if !args.no_write_config {
        paths.maybe_write_default_config()?;
    }
    let mut config = paths.load_config()?;
    if let Some(metrics_listen) = args.metrics_listen {
        config.metrics.listen_addr = Some(metrics_listen);
    }
    if args.allow_public_metrics {
        config.metrics.allow_non_loopback = true;
    }
    enforce_metrics_listener_policy(
        config.metrics.listen_addr.as_deref(),
        config.metrics.allow_non_loopback,
    )?;

    remove_socket_if_present(&paths.api_socket)?;
    remove_socket_if_present(&paths.telemetry_socket)?;

    let observer = discover_observer_info();
    let state = Arc::new(RwLock::new(ServiceState::new(config.clone())));
    let snapshots = SnapshotHub::new(observer.clone());
    let runtime_stats = RuntimeStats::new(
        config.discovery_interval_ms,
        config
            .persistence
            .enabled
            .then_some(config.persistence.sample_interval_ms),
        config.refresh_ms,
    );
    publish_snapshot_now(&state, &snapshots, moshwatch_core::time::unix_time_ms()).await;
    let (snapshot_trigger, mut snapshot_task) = spawn_snapshot_publisher(
        state.clone(),
        snapshots.clone(),
        runtime_stats.clone(),
        config.refresh_ms,
    );

    let history_store = config.persistence.enabled.then(|| {
        Arc::new(HistoryStore::new(
            observer.clone(),
            paths.history_dir.clone(),
            config.persistence.retention_days,
            config.persistence.max_query_samples,
            config.persistence.max_disk_bytes,
        ))
    });
    let metrics_auth_token = config
        .metrics
        .listen_addr
        .as_ref()
        .map(|_| paths.load_or_create_metrics_auth_token())
        .transpose()?
        .map(Arc::<str>::from);

    let context = AppContext {
        observer: observer.clone(),
        state: state.clone(),
        snapshots: snapshots.clone(),
        history: history_store.clone(),
        runtime_stats: runtime_stats.clone(),
        stream_heartbeat_ms: config.stream.heartbeat_ms,
        stream_slots: Arc::new(Semaphore::new(STREAM_CONNECTION_SLOTS)),
        history_query_slots: Arc::new(Semaphore::new(HISTORY_QUERY_SLOTS)),
    };

    let mut discovery_task = spawn_discovery_loop(
        state.clone(),
        snapshot_trigger.clone(),
        runtime_stats.clone(),
        config.discovery_interval_ms,
    );
    let mut telemetry_task = spawn_telemetry_listener(
        state.clone(),
        snapshot_trigger.clone(),
        paths.telemetry_socket.clone(),
    )
    .await?;
    let mut api_task = spawn_api_server(context, paths.api_socket.clone());
    let mut history_task = history_store.clone().map(|store| {
        spawn_history_sampler(
            state.clone(),
            store,
            runtime_stats.clone(),
            config.persistence.sample_interval_ms,
        )
    });
    let mut metrics_task = config.metrics.listen_addr.clone().map(|listen_addr| {
        let history_store = history_store.clone();
        let metrics_auth_token = metrics_auth_token.clone().expect("metrics token");
        let runtime_stats = runtime_stats.clone();
        let observer = observer.clone();
        tokio::spawn(async move {
            if let Err(error) = run_metrics_server(
                state.clone(),
                history_store,
                runtime_stats,
                observer,
                listen_addr.clone(),
                metrics_auth_token,
            )
            .await
            {
                tracing::error!("metrics server stopped: {error:#}");
            }
        })
    });
    let mut metrics_token_task = config.metrics.listen_addr.clone().map(|_| {
        let paths = paths.clone();
        let metrics_auth_token = metrics_auth_token.clone().expect("metrics token");
        spawn_metrics_token_reconciler(paths, metrics_auth_token)
    });

    tracing::info!(
        api_socket = %paths.api_socket.display(),
        telemetry_socket = %paths.telemetry_socket.display(),
        history_dir = %paths.history_dir.display(),
        metrics_listen = ?config.metrics.listen_addr,
        metrics_token_path = config
            .metrics
            .listen_addr
            .as_ref()
            .map(|_| paths.metrics_token_path.display().to_string()),
        "moshwatchd started"
    );

    let shutdown_result = tokio::select! {
        result = wait_for_shutdown_signal() => result,
        result = &mut discovery_task => unexpected_task_exit("discovery", result),
        result = &mut telemetry_task => unexpected_task_exit("telemetry", result),
        result = &mut api_task => unexpected_task_exit("api", result),
        result = await_optional_task(history_task.as_mut(), "history") => result,
        result = await_optional_task(metrics_task.as_mut(), "metrics") => result,
        result = await_optional_task(metrics_token_task.as_mut(), "metrics_token") => result,
        result = &mut snapshot_task => unexpected_task_exit("snapshot", result),
    };
    tracing::info!("shutting down moshwatchd");
    discovery_task.abort();
    telemetry_task.abort();
    api_task.abort();
    if let Some(history_task) = history_task {
        history_task.abort();
    }
    if let Some(metrics_task) = metrics_task {
        metrics_task.abort();
    }
    if let Some(metrics_token_task) = metrics_token_task {
        metrics_token_task.abort();
    }
    snapshot_task.abort();
    remove_socket_if_present(&paths.api_socket)?;
    remove_socket_if_present(&paths.telemetry_socket)?;
    shutdown_result
}

fn spawn_discovery_loop(
    state: SharedState,
    snapshots: SnapshotTrigger,
    runtime_stats: RuntimeStats,
    interval_ms: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(interval_ms));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let cycle_started = std::time::Instant::now();
            match tokio::task::spawn_blocking(discover_mosh_sessions)
                .await
                .context("wait for discovery task")
            {
                Ok(Ok(sessions)) => {
                    state
                        .write()
                        .await
                        .refresh_discovery(sessions, moshwatch_core::time::unix_time_ms());
                    snapshots.request_publish();
                }
                Ok(Err(error)) => tracing::warn!("discovery failed: {error:#}"),
                Err(error) => tracing::warn!("discovery task failed: {error:#}"),
            }
            runtime_stats.record_discovery(cycle_started.elapsed());
        }
    })
}

fn spawn_history_sampler(
    state: SharedState,
    store: Arc<HistoryStore>,
    runtime_stats: RuntimeStats,
    interval_ms: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_millis(interval_ms));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let cycle_started = std::time::Instant::now();
            let now_ms = moshwatch_core::time::unix_time_ms();
            let summaries = state.read().await.summaries(now_ms);
            let store = store.clone();
            if let Err(error) =
                tokio::task::spawn_blocking(move || store.record_summaries(now_ms, &summaries))
                    .await
                    .context("wait for history sampler task")
                    .and_then(|result| result)
            {
                tracing::warn!("history sampler failed: {error:#}");
            }
            runtime_stats.record_history(cycle_started.elapsed());
        }
    })
}

async fn spawn_telemetry_listener(
    state: SharedState,
    snapshots: SnapshotTrigger,
    socket_path: PathBuf,
) -> Result<JoinHandle<()>> {
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind telemetry socket {}", socket_path.display()))?;
    set_socket_owner_only(&socket_path)?;
    let connection_slots = Arc::new(Semaphore::new(64));
    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
                        tracing::warn!(
                            "dropping telemetry connection because all handler slots are busy"
                        );
                        drop(stream);
                        continue;
                    };
                    let state = state.clone();
                    let snapshots = snapshots.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_telemetry_stream(stream, state, snapshots).await
                        {
                            tracing::warn!("telemetry stream failed: {error:#}");
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!("telemetry accept failed: {error:#}");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }))
}

fn spawn_api_server(context: AppContext, socket_path: PathBuf) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = api::run_api(context, socket_path).await {
            tracing::error!("api server stopped: {error:#}");
        }
    })
}

fn spawn_metrics_token_reconciler(paths: RuntimePaths, auth_token: Arc<str>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(METRICS_TOKEN_RECONCILE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let paths = paths.clone();
            let expected_token = auth_token.to_string();
            match tokio::task::spawn_blocking(move || {
                paths.ensure_metrics_auth_token_file_matches(&expected_token)
            })
            .await
            .context("wait for metrics token reconciler task")
            {
                Ok(Ok(true)) => {
                    tracing::warn!("restored metrics auth token file to the active daemon token");
                }
                Ok(Ok(false)) => {}
                Ok(Err(error)) => {
                    tracing::warn!("metrics token reconciliation failed: {error:#}");
                }
                Err(error) => tracing::warn!("metrics token reconciliation task failed: {error:#}"),
            }
        }
    })
}

async fn await_optional_task(task: Option<&mut JoinHandle<()>>, name: &'static str) -> Result<()> {
    match task {
        Some(task) => unexpected_task_exit(name, task.await),
        None => pending::<Result<()>>().await,
    }
}

fn unexpected_task_exit(
    name: &'static str,
    result: std::result::Result<(), tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(()) => anyhow::bail!("{name} task exited unexpectedly"),
        Err(error) => Err(error).with_context(|| format!("{name} task failed")),
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt()).context("register SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("register SIGTERM handler")?;
    tokio::select! {
        _ = sigint.recv() => Ok(()),
        _ = sigterm.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("wait for shutdown signal")
}

fn telemetry_event_is_plausible(event: &TelemetryEvent) -> bool {
    const MAX_EVENT_SKEW_MS: i64 = 60_000;
    let now_ms = moshwatch_core::time::unix_time_ms();
    event.unix_ms >= now_ms - MAX_EVENT_SKEW_MS
        && event.unix_ms <= now_ms + MAX_EVENT_SKEW_MS
        && telemetry_metric_is_plausible(event.srtt_ms)
        && telemetry_metric_is_plausible(event.rttvar_ms)
        && telemetry_metric_is_plausible(event.last_rtt_ms)
}

fn telemetry_metric_is_plausible(value: Option<f64>) -> bool {
    value.is_none_or(|value| value.is_finite() && value >= 0.0)
}

async fn handle_telemetry_stream(
    stream: UnixStream,
    state: SharedState,
    snapshots: SnapshotTrigger,
) -> Result<()> {
    let peer = verified_telemetry_peer(&stream)?;
    let mut reader = BufReader::new(stream);
    let mut invalid_frames = 0usize;
    let mut valid_frame_seen = false;
    loop {
        let mut buffer = match read_bounded_telemetry_frame(
            &mut reader,
            MAX_TELEMETRY_FRAME_BYTES,
            telemetry_frame_timeout(valid_frame_seen),
        )
        .await?
        {
            TelemetryFrameRead::Eof => return Ok(()),
            TelemetryFrameRead::Frame(buffer) => buffer,
            TelemetryFrameRead::Oversized { bytes } => {
                invalid_frames += 1;
                tracing::warn!(
                    pid = peer.pid,
                    bytes,
                    invalid_frames,
                    "ignore oversized telemetry frame from verified peer"
                );
                if invalid_frames >= MAX_INVALID_TELEMETRY_FRAMES {
                    anyhow::bail!(
                        "disconnect telemetry peer after {MAX_INVALID_TELEMETRY_FRAMES} invalid frames"
                    );
                }
                continue;
            }
        };
        while buffer
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            buffer.pop();
        }
        if buffer.is_empty() {
            continue;
        }

        let mut event = match serde_json::from_slice::<TelemetryEvent>(&buffer) {
            Ok(event) => event,
            Err(error) => {
                invalid_frames += 1;
                tracing::warn!(
                    pid = peer.pid,
                    invalid_frames,
                    "ignore malformed telemetry frame from verified peer: {error}"
                );
                if invalid_frames >= MAX_INVALID_TELEMETRY_FRAMES {
                    anyhow::bail!(
                        "disconnect telemetry peer after {MAX_INVALID_TELEMETRY_FRAMES} invalid frames"
                    );
                }
                continue;
            }
        };
        if !telemetry_event_matches_peer(&event, &peer) {
            invalid_frames += 1;
            tracing::warn!(
                pid = peer.pid,
                invalid_frames,
                display_session_id = ?event.display_session_id,
                "ignore telemetry event that does not match verified peer"
            );
            if invalid_frames >= MAX_INVALID_TELEMETRY_FRAMES {
                anyhow::bail!(
                    "disconnect telemetry peer after {MAX_INVALID_TELEMETRY_FRAMES} invalid frames"
                );
            }
            continue;
        }
        invalid_frames = 0;
        valid_frame_seen = true;
        let session_id = instrumented_session_id(peer.pid, peer.started_at_unix_ms);
        // Rewrite identity-bearing fields from the verified peer so downstream
        // state never trusts the transport payload for process identity.
        event.pid = peer.pid;
        event.started_at_unix_ms = Some(peer.started_at_unix_ms);
        event.cmdline = Some(peer.cmdline.clone());
        state.write().await.apply_telemetry(session_id, event);
        snapshots.request_publish();
    }
}

fn spawn_snapshot_publisher(
    state: SharedState,
    snapshots: SnapshotHub,
    runtime_stats: RuntimeStats,
    refresh_ms: u64,
) -> (SnapshotTrigger, JoinHandle<()>) {
    let trigger = SnapshotTrigger {
        dirty: Arc::new(AtomicBool::new(false)),
        notify: Arc::new(Notify::new()),
    };
    let worker_trigger = trigger.clone();
    let task = tokio::spawn(async move {
        let min_interval = Duration::from_millis(refresh_ms);
        loop {
            // The stream is a latest-state feed, not a per-change log. Coalesce
            // bursty updates behind `dirty` and publish at most once per
            // `refresh_ms` interval so slow consumers only miss intermediate
            // states, not the newest snapshot.
            while !worker_trigger.dirty.swap(false, Ordering::AcqRel) {
                worker_trigger.notify.notified().await;
            }
            let now_ms = moshwatch_core::time::unix_time_ms();
            let cycle_started = std::time::Instant::now();
            publish_snapshot_now(&state, &snapshots, now_ms).await;
            runtime_stats.record_snapshot(cycle_started.elapsed());
            let deadline = Instant::now() + min_interval;
            loop {
                tokio::select! {
                    _ = sleep_until(deadline) => break,
                    _ = worker_trigger.notify.notified() => {}
                }
            }
        }
    });
    (trigger, task)
}

#[derive(Debug, PartialEq)]
enum TelemetryFrameRead {
    Eof,
    Frame(Vec<u8>),
    Oversized { bytes: usize },
}

async fn read_bounded_telemetry_frame<R>(
    reader: &mut R,
    max_bytes: usize,
    total_timeout: Duration,
) -> Result<TelemetryFrameRead>
where
    R: AsyncBufRead + Unpin,
{
    let deadline = Instant::now() + total_timeout;
    let mut frame = Vec::with_capacity(1024);
    loop {
        let chunk = timeout_at(deadline, reader.fill_buf())
            .await
            .context("telemetry read timed out")?
            .context("read telemetry frame")?;
        if chunk.is_empty() {
            return if frame.is_empty() {
                Ok(TelemetryFrameRead::Eof)
            } else {
                Ok(TelemetryFrameRead::Frame(frame))
            };
        }
        if let Some(newline_idx) = chunk.iter().position(|byte| *byte == b'\n') {
            let take = newline_idx + 1;
            let total = frame.len().saturating_add(take);
            if total > max_bytes {
                reader.consume(take);
                return Ok(TelemetryFrameRead::Oversized { bytes: total });
            }
            frame.extend_from_slice(&chunk[..take]);
            reader.consume(take);
            return Ok(TelemetryFrameRead::Frame(frame));
        }
        if frame.len().saturating_add(chunk.len()) > max_bytes {
            let bytes = drain_telemetry_frame_remainder(reader, frame.len(), deadline).await?;
            return Ok(TelemetryFrameRead::Oversized { bytes });
        }
        frame.extend_from_slice(chunk);
        let consumed = chunk.len();
        reader.consume(consumed);
    }
}

async fn drain_telemetry_frame_remainder<R>(
    reader: &mut R,
    mut bytes: usize,
    deadline: Instant,
) -> Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let chunk = timeout_at(deadline, reader.fill_buf())
            .await
            .context("telemetry read timed out")?
            .context("read telemetry frame")?;
        if chunk.is_empty() {
            return Ok(bytes);
        }
        if let Some(newline_idx) = chunk.iter().position(|byte| *byte == b'\n') {
            let take = newline_idx + 1;
            bytes = bytes.saturating_add(take);
            reader.consume(take);
            return Ok(bytes);
        }
        bytes = bytes.saturating_add(chunk.len());
        let consumed = chunk.len();
        reader.consume(consumed);
    }
}

#[derive(Debug, Clone)]
struct VerifiedTelemetryPeer {
    pid: i32,
    started_at_unix_ms: i64,
    cmdline: String,
    exe_name: String,
}

fn telemetry_event_matches_peer(event: &TelemetryEvent, peer: &VerifiedTelemetryPeer) -> bool {
    const MAX_START_DRIFT_MS: i64 = 10_000;

    // Treat JSON fields as untrusted until they match the verified local peer.
    // `pid` and `started_at` are a consistency check only; accepted events are
    // later rewritten from `SO_PEERCRED`-anchored metadata before entering
    // state.
    if !telemetry_event_is_plausible(event) {
        return false;
    }
    if event.pid != peer.pid {
        return false;
    }
    if !is_supported_mosh_server_exe(&peer.exe_name) {
        return false;
    }
    if let Some(started_at_unix_ms) = event.started_at_unix_ms
        && (peer.started_at_unix_ms - started_at_unix_ms).abs() > MAX_START_DRIFT_MS
    {
        return false;
    }
    true
}

fn verified_telemetry_peer(stream: &UnixStream) -> Result<VerifiedTelemetryPeer> {
    // This is the main anti-spoofing boundary for telemetry. The daemon trusts
    // only peers whose Unix credentials belong to the current user and whose
    // executable path is the exact instrumented `mosh-server-real` installed
    // alongside the daemon.
    let credentials = unix_peer_credentials(stream)?;
    let expected_uid = unsafe { libc::geteuid() };
    if credentials.uid != expected_uid {
        anyhow::bail!(
            "reject telemetry peer uid {} (expected {})",
            credentials.uid,
            expected_uid
        );
    }

    let metadata = read_process_metadata(credentials.pid as i32)
        .with_context(|| format!("read process metadata for pid {}", credentials.pid))?;
    if !is_supported_mosh_server_exe(&metadata.exe_name) {
        anyhow::bail!(
            "reject telemetry peer pid {} with executable {}",
            credentials.pid,
            metadata.exe_name
        );
    }
    let expected_exe_path = expected_instrumented_server_path()?;
    if metadata.exe_path != expected_exe_path {
        anyhow::bail!(
            "reject telemetry peer pid {} at executable {} (expected {})",
            credentials.pid,
            metadata.exe_path.display(),
            expected_exe_path.display()
        );
    }

    Ok(VerifiedTelemetryPeer {
        pid: credentials.pid as i32,
        started_at_unix_ms: metadata.started_at_unix_ms,
        cmdline: metadata.cmdline,
        exe_name: metadata.exe_name,
    })
}

#[cfg(unix)]
fn unix_peer_credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let fd = stream.as_raw_fd();
    let mut credentials = unsafe { mem::zeroed::<libc::ucred>() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("read SO_PEERCRED");
    }
    Ok(credentials)
}

#[cfg(not(unix))]
fn unix_peer_credentials(_stream: &UnixStream) -> Result<libc::ucred> {
    anyhow::bail!("telemetry peer credential verification requires unix support")
}

fn metrics_listener_is_not_loopback(listen_addr: Option<&str>) -> bool {
    let Some(listen_addr) = listen_addr else {
        return false;
    };
    if let Ok(socket_addr) = listen_addr.parse::<SocketAddr>() {
        return !socket_addr.ip().is_loopback();
    }
    let Some((host, _port)) = split_host_port(listen_addr) else {
        return true;
    };
    !host.eq_ignore_ascii_case("localhost")
}

fn split_host_port(listen_addr: &str) -> Option<(&str, &str)> {
    if let Some(rest) = listen_addr.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host, port));
    }
    listen_addr.rsplit_once(':')
}

fn enforce_metrics_listener_policy(
    listen_addr: Option<&str>,
    allow_non_loopback: bool,
) -> Result<()> {
    if metrics_listener_is_not_loopback(listen_addr) {
        if !allow_non_loopback {
            anyhow::bail!(
                "metrics listener {} is not loopback; set metrics.allow_non_loopback=true or pass --allow-public-metrics to opt in",
                listen_addr.unwrap_or_default()
            );
        }
        tracing::warn!(
            listen_addr = listen_addr.unwrap_or_default(),
            "metrics listener is not bound to loopback; ensure network exposure is intentional"
        );
    }
    Ok(())
}

fn telemetry_frame_timeout(valid_frame_seen: bool) -> Duration {
    if valid_frame_seen {
        TELEMETRY_FRAME_TIMEOUT
    } else {
        INITIAL_TELEMETRY_FRAME_TIMEOUT
    }
}

async fn publish_snapshot_now(state: &SharedState, snapshots: &SnapshotHub, now_ms: i64) {
    let export = state
        .read()
        .await
        .export_summaries(now_ms, MAX_EXPORTED_SESSIONS);
    snapshots.publish_snapshot(export, now_ms);
}

#[cfg(test)]
mod tests {
    use super::{
        INITIAL_TELEMETRY_FRAME_TIMEOUT, MAX_TELEMETRY_FRAME_BYTES, TELEMETRY_FRAME_TIMEOUT,
        TelemetryFrameRead, VerifiedTelemetryPeer, enforce_metrics_listener_policy,
        metrics_listener_is_not_loopback, read_bounded_telemetry_frame,
        telemetry_event_is_plausible, telemetry_event_matches_peer, telemetry_frame_timeout,
    };
    use anyhow::Result;
    use moshwatch_core::{TelemetryEvent, TelemetryEventKind};
    use tokio::{
        io::{AsyncWriteExt, BufReader, duplex},
        time::Duration,
    };

    fn event() -> TelemetryEvent {
        TelemetryEvent {
            event: TelemetryEventKind::SessionTick,
            display_session_id: Some("session-1".to_string()),
            pid: 42,
            unix_ms: moshwatch_core::time::unix_time_ms(),
            started_at_unix_ms: Some(10_000),
            bind_addr: None,
            udp_port: None,
            client_addr: None,
            last_heard_age_ms: Some(100),
            remote_state_age_ms: Some(100),
            srtt_ms: None,
            rttvar_ms: None,
            last_rtt_ms: None,
            packets_tx_total: None,
            packets_rx_total: None,
            retransmits_total: None,
            empty_acks_tx_total: None,
            state_updates_tx_total: None,
            state_updates_rx_total: None,
            duplicate_states_rx_total: None,
            out_of_order_states_rx_total: None,
            cmdline: None,
            shutdown: None,
        }
    }

    fn peer() -> VerifiedTelemetryPeer {
        VerifiedTelemetryPeer {
            pid: 42,
            started_at_unix_ms: 10_001,
            cmdline: "mosh-server-real new".to_string(),
            exe_name: "mosh-server-real".to_string(),
        }
    }

    #[test]
    fn peer_match_requires_same_pid_and_supported_exe() {
        assert!(telemetry_event_matches_peer(&event(), &peer()));

        let wrong_pid = VerifiedTelemetryPeer { pid: 7, ..peer() };
        assert!(!telemetry_event_matches_peer(&event(), &wrong_pid));

        let wrong_exe = VerifiedTelemetryPeer {
            exe_name: "python3".to_string(),
            ..peer()
        };
        assert!(!telemetry_event_matches_peer(&event(), &wrong_exe));
    }

    #[test]
    fn telemetry_plausibility_rejects_nonfinite_or_negative_metrics() {
        let mut nonfinite = event();
        nonfinite.srtt_ms = Some(f64::INFINITY);
        assert!(!telemetry_event_is_plausible(&nonfinite));

        let mut negative = event();
        negative.last_rtt_ms = Some(-1.0);
        assert!(!telemetry_event_is_plausible(&negative));
    }

    #[test]
    fn metrics_listener_loopback_detection_is_conservative() {
        assert!(!metrics_listener_is_not_loopback(None));
        assert!(!metrics_listener_is_not_loopback(Some("127.0.0.1:9947")));
        assert!(!metrics_listener_is_not_loopback(Some("localhost:9947")));
        assert!(metrics_listener_is_not_loopback(Some("[::]:9947")));
        assert!(metrics_listener_is_not_loopback(Some("0.0.0.0:9947")));
        assert!(metrics_listener_is_not_loopback(Some("example.com:9947")));
    }

    #[test]
    fn metrics_listener_policy_rejects_public_bind_without_opt_in() {
        let error = enforce_metrics_listener_policy(Some("0.0.0.0:9947"), false)
            .expect_err("reject public metrics bind");
        assert!(error.to_string().contains("allow_non_loopback"));
    }

    #[test]
    fn metrics_listener_policy_allows_public_bind_with_opt_in() {
        enforce_metrics_listener_policy(Some("0.0.0.0:9947"), true)
            .expect("allow public metrics bind");
    }

    #[test]
    fn telemetry_frame_timeout_is_strict_until_first_valid_frame() {
        assert_eq!(
            telemetry_frame_timeout(false),
            INITIAL_TELEMETRY_FRAME_TIMEOUT
        );
        assert_eq!(telemetry_frame_timeout(true), TELEMETRY_FRAME_TIMEOUT);
    }

    #[tokio::test]
    async fn bounded_telemetry_reader_returns_complete_frame() -> Result<()> {
        let (mut writer, reader) = duplex(256);
        tokio::spawn(async move {
            writer.write_all(b"{\"event\":\"session_tick\"}\n").await?;
            writer.shutdown().await
        });
        let mut reader = BufReader::new(reader);

        let frame = read_bounded_telemetry_frame(&mut reader, 128, Duration::from_secs(2)).await?;
        assert!(matches!(frame, TelemetryFrameRead::Frame(buffer) if buffer.ends_with(b"\n")));
        Ok(())
    }

    #[tokio::test]
    async fn bounded_telemetry_reader_rejects_oversized_frame() -> Result<()> {
        let (mut writer, reader) = duplex(MAX_TELEMETRY_FRAME_BYTES + 64);
        let oversized = vec![b'x'; MAX_TELEMETRY_FRAME_BYTES + 32];
        tokio::spawn(async move {
            writer.write_all(&oversized).await?;
            writer.write_all(b"\n").await?;
            writer.shutdown().await
        });
        let mut reader = BufReader::new(reader);

        let frame = read_bounded_telemetry_frame(
            &mut reader,
            MAX_TELEMETRY_FRAME_BYTES,
            Duration::from_secs(2),
        )
        .await?;
        assert!(matches!(frame, TelemetryFrameRead::Oversized { .. }));
        Ok(())
    }
}
