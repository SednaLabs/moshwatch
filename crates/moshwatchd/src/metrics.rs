// SPDX-License-Identifier: GPL-3.0-or-later

//! Prometheus/OpenMetrics rendering and OTLP metrics export.
//!
//! The same collector powers the owner-only Unix-socket `/metrics` route, the
//! optional TCP scrape listener, and the optional OTLP exporter. The transport
//! trust model differs, but the metric contract should not.

use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use moshwatch_core::{
    AppConfig, HealthState, MetricDescriptor, MetricId, MetricType, MetricsDetailLevel,
    ObserverInfo, SessionKind, SessionSummary,
};
use opentelemetry_proto::tonic::{
    collector::metrics::v1::{ExportMetricsServiceRequest, ExportMetricsServiceResponse},
    common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value},
    metrics::v1::{
        AggregationTemporality, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
        metric, number_data_point,
    },
    resource::v1::Resource,
};
use prost::Message;
use reqwest::{
    Client,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{RwLock, Semaphore},
    time::{MissedTickBehavior, interval, timeout},
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
const OTLP_INSTRUMENTATION_SCOPE: &str = "moshwatchd.metrics";
const MAX_OTLP_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsTextFormat {
    PrometheusText,
    OpenMetricsText,
}

#[derive(Debug, Clone)]
struct MetricSample {
    labels: Vec<(&'static str, String)>,
    value: f64,
    start_time_unix_nano: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct MetricCollectionOptions {
    detail_tier: MetricsDetailLevel,
    include_observer_info: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OtlpExporterStatsSnapshot {
    pub success_total: u64,
    pub failure_total: u64,
    pub last_duration_ms: Option<u64>,
    pub last_success_unix_ms: Option<i64>,
    pub last_failure_unix_ms: Option<i64>,
    pub last_payload_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct OtlpExporterStats {
    inner: Arc<RwLock<OtlpExporterStatsSnapshot>>,
}

impl OtlpExporterStats {
    pub async fn snapshot(&self) -> OtlpExporterStatsSnapshot {
        self.inner.read().await.clone()
    }

    async fn record_success(&self, duration_ms: u64, finished_at_unix_ms: i64, payload_bytes: u64) {
        let mut guard = self.inner.write().await;
        guard.success_total += 1;
        guard.last_duration_ms = Some(duration_ms);
        guard.last_success_unix_ms = Some(finished_at_unix_ms);
        guard.last_payload_bytes = Some(payload_bytes);
    }

    async fn record_failure(&self, duration_ms: u64, finished_at_unix_ms: i64, payload_bytes: u64) {
        let mut guard = self.inner.write().await;
        guard.failure_total += 1;
        guard.last_duration_ms = Some(duration_ms);
        guard.last_failure_unix_ms = Some(finished_at_unix_ms);
        guard.last_payload_bytes = Some(payload_bytes);
    }
}

pub fn metrics_content_type(format: MetricsTextFormat) -> &'static str {
    match format {
        MetricsTextFormat::PrometheusText => "text/plain; version=0.0.4; charset=utf-8",
        MetricsTextFormat::OpenMetricsText => {
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        }
    }
}

pub fn requested_metrics_format(request: &str) -> MetricsTextFormat {
    for line in request.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("accept") {
            continue;
        }
        if accept_header_allows_openmetrics(value) {
            return MetricsTextFormat::OpenMetricsText;
        }
    }
    MetricsTextFormat::PrometheusText
}

fn accept_header_allows_openmetrics(value: &str) -> bool {
    value.split(',').any(accept_item_allows_openmetrics)
}

fn accept_item_allows_openmetrics(item: &str) -> bool {
    let mut parts = item.split(';');
    let Some(media_type) = parts.next().map(str::trim) else {
        return false;
    };
    if !media_type.eq_ignore_ascii_case("application/openmetrics-text") {
        return false;
    }

    let mut quality = 1.0_f32;
    for parameter in parts {
        let Some((name, raw_value)) = parameter.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        let Ok(parsed) = raw_value.trim().trim_matches('"').parse::<f32>() else {
            return false;
        };
        if !(0.0..=1.0).contains(&parsed) {
            return false;
        }
        quality = parsed;
        break;
    }

    quality > 0.0
}

pub fn render_metrics(
    config: &AppConfig,
    observer: &ObserverInfo,
    export: &ExportedSummaries,
    history: Option<HistoryStatsSnapshot>,
    runtime: RuntimeStatsSnapshot,
    otlp_stats: OtlpExporterStatsSnapshot,
    format: MetricsTextFormat,
) -> String {
    let samples = collect_metric_samples(
        config,
        observer,
        export,
        history,
        runtime,
        &otlp_stats,
        MetricCollectionOptions {
            detail_tier: config.metrics.prometheus.detail_tier,
            include_observer_info: true,
        },
    );
    render_metric_samples(&samples, format)
}

pub async fn run_metrics_server(
    state: SharedState,
    history: Option<Arc<HistoryStore>>,
    runtime_stats: RuntimeStats,
    observer: ObserverInfo,
    listen_addr: String,
    auth_token: Arc<str>,
    otlp_stats: OtlpExporterStats,
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
        let otlp_stats = otlp_stats.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_metrics_connection(
                stream,
                state,
                history,
                runtime_stats,
                observer,
                auth_token,
                otlp_stats,
            )
            .await
            {
                tracing::warn!("metrics request from {peer_addr} failed: {error:#}");
            }
        });
    }
}

pub async fn run_otlp_exporter(
    state: SharedState,
    history: Option<Arc<HistoryStore>>,
    runtime_stats: RuntimeStats,
    observer: ObserverInfo,
    config: AppConfig,
    stats: OtlpExporterStats,
) -> Result<()> {
    let endpoint = config.metrics.otlp.endpoint.clone();
    let client = build_otlp_client(&config)?;
    let headers = otlp_headers(&config)?;
    let export_started_unix_nano = unix_nanos(moshwatch_core::time::unix_time_ms());
    let mut ticker = interval(Duration::from_millis(
        config.metrics.otlp.export_interval_ms,
    ));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let cycle_started = Instant::now();
        let now_ms = moshwatch_core::time::unix_time_ms();
        let export = {
            let guard = state.read().await;
            guard.export_summaries(now_ms, MAX_METRICS_RENDERED_SESSIONS)
        };
        let samples = collect_metric_samples(
            &config,
            &observer,
            &export,
            history.as_ref().map(|store| store.stats_snapshot()),
            runtime_stats.snapshot(),
            &stats.snapshot().await,
            MetricCollectionOptions {
                detail_tier: config.metrics.otlp.detail_tier,
                include_observer_info: config.metrics.otlp.detail_tier.includes_sessions(),
            },
        );
        let payload = encode_otlp_metrics(
            &observer,
            &config,
            &samples,
            now_ms,
            export_started_unix_nano,
        )?;
        let payload_bytes = payload.len() as u64;
        let response_result = client
            .post(&endpoint)
            .headers(headers.clone())
            .body(payload)
            .send()
            .await;
        let duration_ms = u64::try_from(cycle_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match response_result {
            Ok(response) => {
                let finished_at = moshwatch_core::time::unix_time_ms();
                if let Err(error) = handle_otlp_response(response).await {
                    stats
                        .record_failure(duration_ms, finished_at, payload_bytes)
                        .await;
                    tracing::warn!("otlp metrics export failed: {error:#}");
                    continue;
                }
                stats
                    .record_success(duration_ms, finished_at, payload_bytes)
                    .await;
            }
            Err(error) => {
                let finished_at = moshwatch_core::time::unix_time_ms();
                stats
                    .record_failure(duration_ms, finished_at, payload_bytes)
                    .await;
                tracing::warn!("otlp metrics export request failed: {error:#}");
            }
        }
    }
}

async fn handle_metrics_connection(
    mut stream: TcpStream,
    state: SharedState,
    history: Option<Arc<HistoryStore>>,
    runtime_stats: RuntimeStats,
    observer: ObserverInfo,
    auth_token: Arc<str>,
    otlp_stats: OtlpExporterStats,
) -> Result<()> {
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
    let (export, config) = {
        let guard = state.read().await;
        (
            guard.export_summaries(now_ms, MAX_METRICS_RENDERED_SESSIONS),
            guard.config().clone(),
        )
    };
    let format = requested_metrics_format(&request);
    let body = render_metrics(
        &config,
        &observer,
        &export,
        history.as_ref().map(|store| store.stats_snapshot()),
        runtime_stats.snapshot(),
        otlp_stats.snapshot().await,
        format,
    );
    timeout(
        METRICS_WRITE_TIMEOUT,
        write_response(
            &mut stream,
            200,
            body.as_bytes(),
            metrics_content_type(format),
        ),
    )
    .await
    .context("write metrics response timed out")?
}

fn collect_metric_samples(
    config: &AppConfig,
    observer: &ObserverInfo,
    export: &ExportedSummaries,
    history: Option<HistoryStatsSnapshot>,
    runtime: RuntimeStatsSnapshot,
    otlp_stats: &OtlpExporterStatsSnapshot,
    options: MetricCollectionOptions,
) -> HashMap<MetricId, Vec<MetricSample>> {
    let mut samples = HashMap::<MetricId, Vec<MetricSample>>::new();
    add_sample(
        &mut samples,
        MetricId::BuildInfo,
        vec![("version", env!("CARGO_PKG_VERSION").to_string())],
        1.0,
    );
    if options.include_observer_info {
        add_sample(
            &mut samples,
            MetricId::ObserverInfo,
            vec![
                ("node_name", observer.node_name.clone()),
                ("system_id", observer.system_id.clone()),
            ],
            1.0,
        );
    }
    add_sample(
        &mut samples,
        MetricId::Sessions,
        vec![("kind", "instrumented".to_string())],
        export.instrumented_sessions as f64,
    );
    add_sample(
        &mut samples,
        MetricId::Sessions,
        vec![("kind", "legacy".to_string())],
        export.legacy_sessions as f64,
    );

    for count in &export.health_counts {
        add_sample(
            &mut samples,
            MetricId::SessionsByHealth,
            vec![
                ("kind", kind_label(&count.kind).to_string()),
                ("health", health_label(&count.health).to_string()),
            ],
            count.sessions as f64,
        );
    }

    let rendered_sessions = if options.detail_tier.includes_sessions() {
        export.sessions.len()
    } else {
        0
    };
    let truncated_sessions = if options.detail_tier.includes_sessions() {
        export.truncated_session_count
    } else {
        0
    };
    add_sample(
        &mut samples,
        MetricId::MetricsRenderedSessions,
        Vec::new(),
        rendered_sessions as f64,
    );
    add_sample(
        &mut samples,
        MetricId::MetricsTruncatedSessions,
        Vec::new(),
        truncated_sessions as f64,
    );
    add_sample(
        &mut samples,
        MetricId::RuntimeDroppedSessionsTotal,
        Vec::new(),
        export.dropped_sessions_total as f64,
    );
    add_sample(
        &mut samples,
        MetricId::RuntimeWorkerThreads,
        Vec::new(),
        DAEMON_WORKER_THREADS as f64,
    );
    add_runtime_loop_samples(
        &mut samples,
        "discovery",
        runtime.discovery_interval_ms,
        runtime.discovery_last_duration_ms,
        runtime.discovery_overruns_total,
    );
    add_runtime_loop_samples(
        &mut samples,
        "history",
        runtime.history_interval_ms,
        runtime.history_last_duration_ms,
        runtime.history_overruns_total,
    );
    add_runtime_loop_samples(
        &mut samples,
        "snapshot",
        runtime.snapshot_interval_ms,
        runtime.snapshot_last_duration_ms,
        runtime.snapshot_overruns_total,
    );

    let history = history.unwrap_or(HistoryStatsSnapshot {
        current_bytes: 0,
        written_bytes_total: 0,
        write_failures_total: 0,
        prune_failures_total: 0,
        dropped_samples_total: 0,
    });
    add_sample(
        &mut samples,
        MetricId::HistoryCurrentBytes,
        Vec::new(),
        history.current_bytes as f64,
    );
    add_sample(
        &mut samples,
        MetricId::HistoryWrittenBytesTotal,
        Vec::new(),
        history.written_bytes_total as f64,
    );
    add_sample(
        &mut samples,
        MetricId::HistoryWriteFailuresTotal,
        Vec::new(),
        history.write_failures_total as f64,
    );
    add_sample(
        &mut samples,
        MetricId::HistoryPruneFailuresTotal,
        Vec::new(),
        history.prune_failures_total as f64,
    );
    add_sample(
        &mut samples,
        MetricId::HistoryDroppedSamplesTotal,
        Vec::new(),
        history.dropped_samples_total as f64,
    );

    add_sample(
        &mut samples,
        MetricId::ThresholdRttMs,
        vec![("severity", "warn".to_string())],
        config.thresholds.warn_rtt_ms as f64,
    );
    add_sample(
        &mut samples,
        MetricId::ThresholdRttMs,
        vec![("severity", "critical".to_string())],
        config.thresholds.critical_rtt_ms as f64,
    );
    add_sample(
        &mut samples,
        MetricId::ThresholdRetransmitPct,
        vec![("severity", "warn".to_string())],
        config.thresholds.warn_retransmit_pct,
    );
    add_sample(
        &mut samples,
        MetricId::ThresholdRetransmitPct,
        vec![("severity", "critical".to_string())],
        config.thresholds.critical_retransmit_pct,
    );
    add_sample(
        &mut samples,
        MetricId::ThresholdSilenceMs,
        vec![("severity", "warn".to_string())],
        config.thresholds.warn_silence_ms as f64,
    );
    add_sample(
        &mut samples,
        MetricId::ThresholdSilenceMs,
        vec![("severity", "critical".to_string())],
        config.thresholds.critical_silence_ms as f64,
    );

    add_sample(
        &mut samples,
        MetricId::OtlpExportEnabled,
        vec![(
            "detail_tier",
            detail_tier_label(config.metrics.otlp.detail_tier).to_string(),
        )],
        if config.metrics.otlp.enabled {
            1.0
        } else {
            0.0
        },
    );
    add_sample(
        &mut samples,
        MetricId::OtlpExportsTotal,
        vec![("result", "success".to_string())],
        otlp_stats.success_total as f64,
    );
    add_sample(
        &mut samples,
        MetricId::OtlpExportsTotal,
        vec![("result", "failure".to_string())],
        otlp_stats.failure_total as f64,
    );
    add_optional_sample(
        &mut samples,
        MetricId::OtlpExportLastDurationMs,
        Vec::new(),
        otlp_stats.last_duration_ms.map(|value| value as f64),
    );
    add_optional_sample(
        &mut samples,
        MetricId::OtlpExportLastSuccessUnixMs,
        Vec::new(),
        otlp_stats.last_success_unix_ms.map(|value| value as f64),
    );
    add_optional_sample(
        &mut samples,
        MetricId::OtlpExportLastFailureUnixMs,
        Vec::new(),
        otlp_stats.last_failure_unix_ms.map(|value| value as f64),
    );
    add_optional_sample(
        &mut samples,
        MetricId::OtlpExportLastPayloadBytes,
        Vec::new(),
        otlp_stats.last_payload_bytes.map(|value| value as f64),
    );

    if options.detail_tier.includes_sessions() {
        for session in &export.sessions {
            let info_labels = session_info_labels(session);
            let value_labels = session_value_labels(session);
            add_sample(&mut samples, MetricId::SessionInfo, info_labels, 1.0);
            add_sample(
                &mut samples,
                MetricId::SessionHealthLevel,
                value_labels.clone(),
                health_level(&session.health) as f64,
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionSrttMs,
                value_labels.clone(),
                session.metrics.srtt_ms,
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRttvarMs,
                value_labels.clone(),
                session.metrics.rttvar_ms,
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionLastRttMs,
                value_labels.clone(),
                session.metrics.last_rtt_ms,
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionLastHeardAgeMs,
                value_labels.clone(),
                session.metrics.last_heard_age_ms.map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRemoteStateAgeMs,
                value_labels.clone(),
                session
                    .metrics
                    .remote_state_age_ms
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitPct10s,
                value_labels.clone(),
                session.metrics.retransmit_pct_10s,
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitPct60s,
                value_labels.clone(),
                session.metrics.retransmit_pct_60s,
            );
            add_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowComplete,
                window_labels(&value_labels, "10s"),
                if session.metrics.retransmit_window_10s_complete {
                    1.0
                } else {
                    0.0
                },
            );
            add_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowComplete,
                window_labels(&value_labels, "60s"),
                if session.metrics.retransmit_window_60s_complete {
                    1.0
                } else {
                    0.0
                },
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowTransmissions,
                window_labels(&value_labels, "10s"),
                session
                    .metrics
                    .retransmit_window_10s_breakdown
                    .transmissions_total
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowTransmissions,
                window_labels(&value_labels, "60s"),
                session
                    .metrics
                    .retransmit_window_60s_breakdown
                    .transmissions_total
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowRetransmits,
                window_labels(&value_labels, "10s"),
                session
                    .metrics
                    .retransmit_window_10s_breakdown
                    .retransmits_total
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowRetransmits,
                window_labels(&value_labels, "60s"),
                session
                    .metrics
                    .retransmit_window_60s_breakdown
                    .retransmits_total
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowStateUpdates,
                window_labels(&value_labels, "10s"),
                session
                    .metrics
                    .retransmit_window_10s_breakdown
                    .state_updates_total
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowStateUpdates,
                window_labels(&value_labels, "60s"),
                session
                    .metrics
                    .retransmit_window_60s_breakdown
                    .state_updates_total
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowEmptyAcks,
                window_labels(&value_labels, "10s"),
                session
                    .metrics
                    .retransmit_window_10s_breakdown
                    .empty_acks_total
                    .map(|value| value as f64),
            );
            add_optional_sample(
                &mut samples,
                MetricId::SessionRetransmitWindowEmptyAcks,
                window_labels(&value_labels, "60s"),
                session
                    .metrics
                    .retransmit_window_60s_breakdown
                    .empty_acks_total
                    .map(|value| value as f64),
            );
            let counter_start_ms = session
                .counter_reset_unix_ms
                .unwrap_or(session.started_at_unix_ms);
            add_optional_counter_sample(
                &mut samples,
                MetricId::SessionPacketsTxTotal,
                value_labels.clone(),
                counter_start_ms,
                session.metrics.packets_tx_total.map(|value| value as f64),
            );
            add_optional_counter_sample(
                &mut samples,
                MetricId::SessionPacketsRxTotal,
                value_labels.clone(),
                counter_start_ms,
                session.metrics.packets_rx_total.map(|value| value as f64),
            );
            add_optional_counter_sample(
                &mut samples,
                MetricId::SessionRetransmitsTotal,
                value_labels,
                counter_start_ms,
                session.metrics.retransmits_total.map(|value| value as f64),
            );
        }
    }

    samples
}

fn render_metric_samples(
    samples: &HashMap<MetricId, Vec<MetricSample>>,
    format: MetricsTextFormat,
) -> String {
    let mut output = String::new();
    for descriptor in moshwatch_core::metric_catalog() {
        let Some(series) = samples.get(&descriptor.id) else {
            continue;
        };
        let _ = writeln!(output, "# HELP {} {}", descriptor.name, descriptor.help);
        let _ = writeln!(
            output,
            "# TYPE {} {}",
            descriptor.name,
            metric_type_text(descriptor)
        );
        for sample in series {
            render_metric_sample(&mut output, descriptor, sample);
        }
    }
    if format == MetricsTextFormat::OpenMetricsText {
        output.push_str("# EOF\n");
    }
    output
}

fn render_metric_sample(output: &mut String, descriptor: &MetricDescriptor, sample: &MetricSample) {
    if sample.labels.is_empty() {
        let _ = writeln!(output, "{} {}", descriptor.name, sample.value);
        return;
    }
    output.push_str(descriptor.name);
    output.push('{');
    for (index, (name, value)) in sample.labels.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(name);
        output.push_str("=\"");
        output.push_str(&escape_label(value));
        output.push('\"');
    }
    output.push_str("} ");
    let _ = writeln!(output, "{}", sample.value);
}

fn metric_type_text(descriptor: &MetricDescriptor) -> &'static str {
    match descriptor.kind {
        MetricType::Gauge => "gauge",
        MetricType::Counter => "counter",
        MetricType::Info => "gauge",
    }
}

fn add_sample(
    samples: &mut HashMap<MetricId, Vec<MetricSample>>,
    id: MetricId,
    labels: Vec<(&'static str, String)>,
    value: f64,
) {
    add_sample_with_start_time(samples, id, labels, value, None);
}

fn add_sample_with_start_time(
    samples: &mut HashMap<MetricId, Vec<MetricSample>>,
    id: MetricId,
    labels: Vec<(&'static str, String)>,
    value: f64,
    start_time_unix_nano: Option<u64>,
) {
    samples.entry(id).or_default().push(MetricSample {
        labels,
        value,
        start_time_unix_nano,
    });
}

fn add_optional_sample(
    samples: &mut HashMap<MetricId, Vec<MetricSample>>,
    id: MetricId,
    labels: Vec<(&'static str, String)>,
    value: Option<f64>,
) {
    if let Some(value) = value {
        add_sample(samples, id, labels, value);
    }
}

fn add_optional_counter_sample(
    samples: &mut HashMap<MetricId, Vec<MetricSample>>,
    id: MetricId,
    labels: Vec<(&'static str, String)>,
    start_unix_ms: i64,
    value: Option<f64>,
) {
    if let Some(value) = value {
        add_sample_with_start_time(samples, id, labels, value, Some(unix_nanos(start_unix_ms)));
    }
}

fn add_runtime_loop_samples(
    samples: &mut HashMap<MetricId, Vec<MetricSample>>,
    loop_name: &str,
    interval_ms: u64,
    last_duration_ms: u64,
    overruns_total: u64,
) {
    if interval_ms == 0 {
        return;
    }
    let labels = vec![("loop", loop_name.to_string())];
    add_sample(
        samples,
        MetricId::RuntimeLoopIntervalMs,
        labels.clone(),
        interval_ms as f64,
    );
    add_sample(
        samples,
        MetricId::RuntimeLoopLastDurationMs,
        labels.clone(),
        last_duration_ms as f64,
    );
    add_sample(
        samples,
        MetricId::RuntimeLoopOverrunsTotal,
        labels,
        overruns_total as f64,
    );
}

fn session_info_labels(session: &SessionSummary) -> Vec<(&'static str, String)> {
    vec![
        ("session_id", session.session_id.clone()),
        (
            "display_session_id",
            session.display_session_id.clone().unwrap_or_default(),
        ),
        ("kind", kind_label(&session.kind).to_string()),
        ("pid", session.pid.to_string()),
        ("started_at_unix_ms", session.started_at_unix_ms.to_string()),
    ]
}

fn session_value_labels(session: &SessionSummary) -> Vec<(&'static str, String)> {
    vec![
        ("session_id", session.session_id.clone()),
        ("kind", kind_label(&session.kind).to_string()),
    ]
}

fn window_labels(labels: &[(&'static str, String)], window: &str) -> Vec<(&'static str, String)> {
    let mut combined = labels.to_vec();
    combined.push(("window", window.to_string()));
    combined
}

fn detail_tier_label(detail_tier: MetricsDetailLevel) -> &'static str {
    match detail_tier {
        MetricsDetailLevel::AggregateOnly => "aggregate_only",
        MetricsDetailLevel::PerSession => "per_session",
    }
}

fn kind_label(kind: &SessionKind) -> &'static str {
    match kind {
        SessionKind::Instrumented => "instrumented",
        SessionKind::Legacy => "legacy",
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

fn health_level(health: &HealthState) -> u8 {
    match health {
        HealthState::Ok => 0,
        HealthState::Degraded => 1,
        HealthState::Critical => 2,
        HealthState::Legacy => 3,
    }
}

fn build_otlp_client(config: &AppConfig) -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_millis(config.metrics.otlp.timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build OTLP HTTP client")
}

fn otlp_headers(config: &AppConfig) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in &config.metrics.otlp.headers {
        let header_name = HeaderName::try_from(name.as_str())
            .with_context(|| format!("parse OTLP header name {name}"))?;
        let header_value = HeaderValue::from_str(value)
            .with_context(|| format!("parse OTLP header value for {name}"))?;
        headers.insert(header_name, header_value);
    }
    // Always force the protobuf content negotiation required by the OTLP/HTTP payload.
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/x-protobuf"));
    Ok(headers)
}

async fn handle_otlp_response(response: reqwest::Response) -> Result<()> {
    let status = response.status();
    let body = read_otlp_response_body(response).await?;
    if !status.is_success() {
        let snippet = String::from_utf8_lossy(&body);
        anyhow::bail!(
            "collector responded with {}: {}",
            status,
            truncate_for_log(&snippet, 256)
        );
    }
    if body.is_empty() {
        return Ok(());
    }
    let response = ExportMetricsServiceResponse::decode(body.as_ref())
        .context("decode OTLP protobuf response")?;
    if let Some(partial) = response.partial_success
        && (partial.rejected_data_points > 0 || !partial.error_message.trim().is_empty())
    {
        anyhow::bail!(
            "collector reported partial success: rejected_data_points={}, error_message={}",
            partial.rejected_data_points,
            partial.error_message
        );
    }
    Ok(())
}

async fn read_otlp_response_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length()
        && length > MAX_OTLP_RESPONSE_BYTES as u64
    {
        anyhow::bail!(
            "collector response body ({} bytes) exceeds {} byte limit",
            length,
            MAX_OTLP_RESPONSE_BYTES
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read OTLP response chunk")? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_OTLP_RESPONSE_BYTES {
            anyhow::bail!(
                "collector response body exceeded {} bytes",
                MAX_OTLP_RESPONSE_BYTES
            );
        }
    }
    Ok(body)
}

fn encode_otlp_metrics(
    observer: &ObserverInfo,
    config: &AppConfig,
    samples: &HashMap<MetricId, Vec<MetricSample>>,
    now_unix_ms: i64,
    export_started_unix_nano: u64,
) -> Result<Vec<u8>> {
    let now_unix_nano = unix_nanos(now_unix_ms);
    let metrics = moshwatch_core::metric_catalog()
        .iter()
        .filter_map(|descriptor| {
            samples
                .get(&descriptor.id)
                .filter(|series| !series.is_empty())
                .map(|series| {
                    metric_to_otlp(descriptor, series, now_unix_nano, export_started_unix_nano)
                })
        })
        .collect();
    let mut resource_attributes = vec![
        string_attribute("service.name", "moshwatchd"),
        string_attribute("service.version", env!("CARGO_PKG_VERSION")),
    ];
    if config.metrics.otlp.detail_tier.includes_sessions() {
        resource_attributes.push(string_attribute(
            "moshwatch.observer.node_name",
            &observer.node_name,
        ));
        resource_attributes.push(string_attribute(
            "moshwatch.observer.system_id",
            &observer.system_id,
        ));
    }
    for (key, value) in &config.metrics.otlp.resource_attributes {
        resource_attributes.push(string_attribute(key, value));
    }
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: resource_attributes,
                dropped_attributes_count: 0,
                entity_refs: Vec::new(),
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: OTLP_INSTRUMENTATION_SCOPE.to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    attributes: Vec::new(),
                    dropped_attributes_count: 0,
                }),
                metrics,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    };
    Ok(request.encode_to_vec())
}

fn metric_to_otlp(
    descriptor: &MetricDescriptor,
    samples: &[MetricSample],
    now_unix_nano: u64,
    export_started_unix_nano: u64,
) -> Metric {
    let data_points = samples
        .iter()
        .map(|sample| NumberDataPoint {
            attributes: sample
                .labels
                .iter()
                .map(|(name, value)| string_attribute(name, value))
                .collect(),
            start_time_unix_nano: if matches!(descriptor.kind, MetricType::Counter) {
                sample
                    .start_time_unix_nano
                    .unwrap_or(export_started_unix_nano)
            } else {
                0
            },
            time_unix_nano: now_unix_nano,
            exemplars: Vec::new(),
            flags: 0,
            value: Some(number_data_point::Value::AsDouble(sample.value)),
        })
        .collect();
    let data = match descriptor.kind {
        MetricType::Counter => metric::Data::Sum(Sum {
            data_points,
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        }),
        MetricType::Gauge | MetricType::Info => metric::Data::Gauge(Gauge { data_points }),
    };
    Metric {
        name: descriptor.name.to_string(),
        description: descriptor.help.to_string(),
        unit: metric_unit(descriptor).to_string(),
        metadata: Vec::new(),
        data: Some(data),
    }
}

fn metric_unit(descriptor: &MetricDescriptor) -> &'static str {
    descriptor.unit
}

fn string_attribute(name: &str, value: &str) -> KeyValue {
    KeyValue {
        key: name.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
    }
}

fn unix_nanos(unix_ms: i64) -> u64 {
    let clamped_ms = unix_ms.max(0);
    u64::try_from(clamped_ms)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
}

fn truncate_for_log(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    value.chars().take(limit).collect::<String>() + "..."
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

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use moshwatch_core::{
        AppConfig, MetricsDetailTier, ObserverInfo, RetransmitWindowBreakdown, SessionKind,
        SessionMetrics, SessionPeerInfo, SessionSummary,
    };
    use opentelemetry_proto::tonic::{
        collector::metrics::v1::ExportMetricsServiceRequest, metrics::v1::metric,
    };
    use prost::Message;

    use super::{
        MetricCollectionOptions, MetricsTextFormat, OtlpExporterStatsSnapshot, build_otlp_client,
        collect_metric_samples, encode_otlp_metrics, extract_bearer_token,
        metrics_request_is_authorized, otlp_headers, render_metrics, requested_metrics_format,
        unix_nanos,
    };
    use crate::runtime_stats::RuntimeStatsSnapshot;
    use crate::{
        history::HistoryStatsSnapshot,
        state::{ExportedSummaries, SessionHealthCount},
    };

    fn sample_export() -> ExportedSummaries {
        ExportedSummaries {
            total_sessions: 1,
            truncated_session_count: 2,
            instrumented_sessions: 1,
            legacy_sessions: 0,
            health_counts: vec![
                SessionHealthCount {
                    kind: SessionKind::Instrumented,
                    health: moshwatch_core::HealthState::Ok,
                    sessions: 0,
                },
                SessionHealthCount {
                    kind: SessionKind::Instrumented,
                    health: moshwatch_core::HealthState::Degraded,
                    sessions: 1,
                },
                SessionHealthCount {
                    kind: SessionKind::Instrumented,
                    health: moshwatch_core::HealthState::Critical,
                    sessions: 0,
                },
                SessionHealthCount {
                    kind: SessionKind::Instrumented,
                    health: moshwatch_core::HealthState::Legacy,
                    sessions: 0,
                },
                SessionHealthCount {
                    kind: SessionKind::Legacy,
                    health: moshwatch_core::HealthState::Ok,
                    sessions: 0,
                },
                SessionHealthCount {
                    kind: SessionKind::Legacy,
                    health: moshwatch_core::HealthState::Degraded,
                    sessions: 0,
                },
                SessionHealthCount {
                    kind: SessionKind::Legacy,
                    health: moshwatch_core::HealthState::Critical,
                    sessions: 0,
                },
                SessionHealthCount {
                    kind: SessionKind::Legacy,
                    health: moshwatch_core::HealthState::Legacy,
                    sessions: 0,
                },
            ],
            dropped_sessions_total: 7,
            sessions: vec![SessionSummary {
                session_id: "instrumented:1:42".to_string(),
                display_session_id: Some("display".to_string()),
                pid: 42,
                kind: SessionKind::Instrumented,
                health: moshwatch_core::HealthState::Degraded,
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
                counter_reset_unix_ms: None,
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
                    packets_tx_total: Some(250),
                    packets_rx_total: Some(240),
                    retransmits_total: Some(3),
                    ..SessionMetrics::default()
                },
            }],
        }
    }

    fn sample_runtime() -> RuntimeStatsSnapshot {
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
        }
    }

    #[test]
    fn renders_session_metrics_without_volatile_network_labels() {
        let metrics = render_metrics(
            &AppConfig::default(),
            &ObserverInfo {
                node_name: "node-1".to_string(),
                system_id: "system-1".to_string(),
            },
            &sample_export(),
            Some(HistoryStatsSnapshot {
                current_bytes: 1024,
                written_bytes_total: 4096,
                write_failures_total: 2,
                prune_failures_total: 5,
                dropped_samples_total: 3,
            }),
            sample_runtime(),
            OtlpExporterStatsSnapshot::default(),
            MetricsTextFormat::PrometheusText,
        );

        assert!(metrics.contains("moshwatch_build_info"));
        assert!(metrics.contains("moshwatch_sessions_by_health"));
        assert!(metrics.contains("moshwatch_session_srtt_ms"));
        assert!(metrics.contains("display_session_id=\"display\""));
        assert!(metrics.contains("moshwatch_session_retransmit_window_complete"));
        assert!(metrics.contains("window=\"10s\""));
        assert!(metrics.contains("moshwatch_session_retransmit_window_transmissions"));
        assert!(metrics.contains("moshwatch_session_retransmit_window_retransmits"));
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
        assert!(!metrics.contains("bind_addr="));
        assert!(!metrics.contains("udp_port="));
        assert!(!metrics.contains("client_addr="));
        assert!(!metrics.contains(",display_session_id=\"display\",kind=\"instrumented\"} 12.5"));
    }

    #[test]
    fn aggregate_only_detail_hides_session_series() {
        let mut config = AppConfig::default();
        config.metrics.prometheus.detail_tier = moshwatch_core::MetricsDetailTier::AggregateOnly;
        let metrics = render_metrics(
            &config,
            &ObserverInfo {
                node_name: "node-1".to_string(),
                system_id: "system-1".to_string(),
            },
            &sample_export(),
            None,
            sample_runtime(),
            OtlpExporterStatsSnapshot::default(),
            MetricsTextFormat::PrometheusText,
        );

        assert!(metrics.contains("moshwatch_sessions{kind=\"instrumented\"} 1"));
        assert!(metrics.contains("moshwatch_metrics_rendered_sessions 0"));
        assert!(!metrics.contains("moshwatch_session_srtt_ms"));
        assert!(!metrics.contains("moshwatch_session_info"));
    }

    #[test]
    fn openmetrics_accept_negotiation_is_supported() {
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAccept: application/openmetrics-text; version=1.0.0\r\n\r\n";
        assert_eq!(
            requested_metrics_format(request),
            MetricsTextFormat::OpenMetricsText
        );
    }

    #[test]
    fn openmetrics_accept_q_zero_falls_back_to_prometheus_text() {
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAccept: application/openmetrics-text; q=0, text/plain\r\n\r\n";
        assert_eq!(
            requested_metrics_format(request),
            MetricsTextFormat::PrometheusText
        );
    }

    #[test]
    fn openmetrics_render_ends_with_eof_marker() {
        let metrics = render_metrics(
            &AppConfig::default(),
            &ObserverInfo {
                node_name: "node-1".to_string(),
                system_id: "system-1".to_string(),
            },
            &sample_export(),
            None,
            sample_runtime(),
            OtlpExporterStatsSnapshot::default(),
            MetricsTextFormat::OpenMetricsText,
        );
        assert!(metrics.ends_with("# EOF\n"));
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

    #[tokio::test]
    async fn otlp_client_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect test listener");
        let endpoint = format!(
            "http://{}/v1/metrics",
            listener.local_addr().expect("listener addr")
        );
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept redirect request");
            let mut request = vec![0_u8; 4096];
            let _ = socket
                .read(&mut request)
                .await
                .expect("read redirect request");
            socket
                .write_all(
                    b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:9/v1/metrics\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .expect("write redirect response");
        });

        let mut config = AppConfig::default();
        config.metrics.otlp.endpoint = endpoint.clone();
        config.metrics.otlp.timeout_ms = 1_000;

        let response = build_otlp_client(&config)
            .expect("build OTLP client")
            .post(endpoint)
            .body(Vec::new())
            .send()
            .await
            .expect("OTLP request should return redirect response without following");

        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    }

    #[test]
    fn otlp_headers_force_required_protobuf_content_negotiation() {
        let mut config = AppConfig::default();
        config
            .metrics
            .otlp
            .headers
            .insert("authorization".to_string(), "Bearer test".to_string());
        config
            .metrics
            .otlp
            .headers
            .insert("accept".to_string(), "text/plain".to_string());
        config
            .metrics
            .otlp
            .headers
            .insert("content-type".to_string(), "application/json".to_string());

        let headers = otlp_headers(&config).expect("build OTLP headers");
        assert_eq!(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer test")
        );
        assert_eq!(
            headers.get("accept").and_then(|value| value.to_str().ok()),
            Some("application/x-protobuf")
        );
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/x-protobuf")
        );
    }

    #[test]
    fn otlp_session_counters_preserve_session_start_time() {
        let observer = ObserverInfo {
            node_name: "node-1".to_string(),
            system_id: "system-1".to_string(),
        };
        let mut config = AppConfig::default();
        config.metrics.otlp.detail_tier = MetricsDetailTier::PerSession;
        let export = sample_export();
        let samples = collect_metric_samples(
            &config,
            &observer,
            &export,
            None,
            sample_runtime(),
            &OtlpExporterStatsSnapshot::default(),
            MetricCollectionOptions {
                detail_tier: config.metrics.otlp.detail_tier,
                include_observer_info: true,
            },
        );
        let payload = encode_otlp_metrics(&observer, &config, &samples, 10_000, unix_nanos(9_000))
            .expect("encode OTLP metrics");
        let request = ExportMetricsServiceRequest::decode(payload.as_slice())
            .expect("decode OTLP metrics payload");
        let resource_attributes = &request.resource_metrics[0]
            .resource
            .as_ref()
            .expect("resource")
            .attributes;
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;

        assert!(
            resource_attributes
                .iter()
                .any(|attr| attr.key == "moshwatch.observer.node_name")
        );
        assert!(
            resource_attributes
                .iter()
                .any(|attr| attr.key == "moshwatch.observer.system_id")
        );

        let session_packets = metrics
            .iter()
            .find(|metric| metric.name == "moshwatch_session_packets_tx_total")
            .expect("session packets counter metric");
        let history_written = metrics
            .iter()
            .find(|metric| metric.name == "moshwatch_history_written_bytes_total")
            .expect("history counter metric");

        let session_start = match session_packets.data.as_ref().expect("session packets data") {
            metric::Data::Sum(sum) => sum.data_points[0].start_time_unix_nano,
            other => panic!("expected Sum data for session packets, got {other:?}"),
        };
        let exporter_start = match history_written.data.as_ref().expect("history data") {
            metric::Data::Sum(sum) => sum.data_points[0].start_time_unix_nano,
            other => panic!("expected Sum data for history bytes, got {other:?}"),
        };

        assert_eq!(
            session_start,
            unix_nanos(export.sessions[0].started_at_unix_ms)
        );
        assert_eq!(exporter_start, unix_nanos(9_000));
    }

    #[test]
    fn aggregate_only_otlp_omits_built_in_observer_identity() {
        let observer = ObserverInfo {
            node_name: "node-1".to_string(),
            system_id: "system-1".to_string(),
        };
        let mut config = AppConfig::default();
        config.metrics.otlp.detail_tier = MetricsDetailTier::AggregateOnly;
        config.metrics.otlp.resource_attributes.insert(
            "service.instance.id".to_string(),
            "collector-host-a".to_string(),
        );
        let export = sample_export();
        let samples = collect_metric_samples(
            &config,
            &observer,
            &export,
            None,
            sample_runtime(),
            &OtlpExporterStatsSnapshot::default(),
            MetricCollectionOptions {
                detail_tier: config.metrics.otlp.detail_tier,
                include_observer_info: false,
            },
        );
        let payload = encode_otlp_metrics(&observer, &config, &samples, 10_000, unix_nanos(9_000))
            .expect("encode OTLP metrics");
        let request = ExportMetricsServiceRequest::decode(payload.as_slice())
            .expect("decode OTLP metrics payload");
        let resource_attributes = &request.resource_metrics[0]
            .resource
            .as_ref()
            .expect("resource")
            .attributes;

        assert!(
            resource_attributes
                .iter()
                .any(|attr| attr.key == "service.name")
        );
        assert!(
            resource_attributes
                .iter()
                .any(|attr| attr.key == "service.version")
        );
        assert!(
            resource_attributes
                .iter()
                .any(|attr| attr.key == "service.instance.id")
        );
        assert!(
            !resource_attributes
                .iter()
                .any(|attr| attr.key == "moshwatch.observer.node_name")
        );
        assert!(
            !resource_attributes
                .iter()
                .any(|attr| attr.key == "moshwatch.observer.system_id")
        );
    }
}
