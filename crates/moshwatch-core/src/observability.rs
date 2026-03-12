// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared observability contract metadata.
//!
//! The daemon owns transport and runtime collection, but the exported metric
//! contract should still live in `moshwatch-core` so renderer drift is visible
//! to both maintainers and downstream consumers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MetricsDetailTier {
    AggregateOnly,
    #[default]
    PerSession,
}

impl MetricsDetailTier {
    pub const fn includes_sessions(self) -> bool {
        matches!(self, Self::PerSession)
    }
}

pub type MetricsDetailLevel = MetricsDetailTier;
pub type MetricType = MetricKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Gauge,
    Counter,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricCardinality {
    Static,
    Low,
    PerSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricPrivacy {
    FleetSafe,
    OperatorSensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricLabelSchema {
    None,
    BuildVersion,
    Observer,
    Kind,
    KindHealth,
    Loop,
    Severity,
    Result,
    ExporterDetailTier,
    SessionValue,
    SessionInfo,
    SessionWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricId {
    BuildInfo,
    ObserverInfo,
    Sessions,
    SessionsByHealth,
    MetricsRenderedSessions,
    MetricsTruncatedSessions,
    RuntimeDroppedSessionsTotal,
    RuntimeWorkerThreads,
    RuntimeLoopIntervalMs,
    RuntimeLoopLastDurationMs,
    RuntimeLoopOverrunsTotal,
    HistoryCurrentBytes,
    HistoryWrittenBytesTotal,
    HistoryWriteFailuresTotal,
    HistoryPruneFailuresTotal,
    HistoryDroppedSamplesTotal,
    ThresholdRttMs,
    ThresholdRetransmitPct,
    ThresholdSilenceMs,
    OtlpExportEnabled,
    OtlpExportsTotal,
    OtlpExportLastDurationMs,
    OtlpExportLastSuccessUnixMs,
    OtlpExportLastFailureUnixMs,
    OtlpExportLastPayloadBytes,
    SessionInfo,
    SessionHealthLevel,
    SessionSrttMs,
    SessionRttvarMs,
    SessionLastRttMs,
    SessionLastHeardAgeMs,
    SessionRemoteStateAgeMs,
    SessionRetransmitPct10s,
    SessionRetransmitPct60s,
    SessionRetransmitWindowComplete,
    SessionRetransmitWindowTransmissions,
    SessionRetransmitWindowRetransmits,
    SessionRetransmitWindowStateUpdates,
    SessionRetransmitWindowEmptyAcks,
    SessionPacketsTxTotal,
    SessionPacketsRxTotal,
    SessionRetransmitsTotal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricDescriptor {
    pub id: MetricId,
    pub name: &'static str,
    pub help: &'static str,
    pub kind: MetricKind,
    pub unit: &'static str,
    pub cardinality: MetricCardinality,
    pub privacy: MetricPrivacy,
    pub labels: MetricLabelSchema,
    pub minimum_detail_tier: MetricsDetailTier,
}

pub const METRIC_CATALOG: &[MetricDescriptor] = &[
    MetricDescriptor {
        id: MetricId::BuildInfo,
        name: "moshwatch_build_info",
        help: "Build information for moshwatchd.",
        kind: MetricKind::Info,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::BuildVersion,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::ObserverInfo,
        name: "moshwatch_observer_info",
        help: "Host identity for this moshwatchd instance.",
        kind: MetricKind::Info,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::Observer,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::Sessions,
        name: "moshwatch_sessions",
        help: "Number of sessions by kind.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Kind,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::SessionsByHealth,
        name: "moshwatch_sessions_by_health",
        help: "Number of sessions by kind and derived health state.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::KindHealth,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::MetricsRenderedSessions,
        name: "moshwatch_metrics_rendered_sessions",
        help: "Number of session series rendered into the export.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::MetricsTruncatedSessions,
        name: "moshwatch_metrics_truncated_sessions",
        help: "Number of sessions omitted from the export due to render caps.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::RuntimeDroppedSessionsTotal,
        name: "moshwatch_runtime_dropped_sessions_total",
        help: "Number of session tracking admissions or records dropped due to capacity limits.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::RuntimeWorkerThreads,
        name: "moshwatch_runtime_worker_threads",
        help: "Configured Tokio worker threads for moshwatchd.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::RuntimeLoopIntervalMs,
        name: "moshwatch_runtime_loop_interval_ms",
        help: "Configured interval for periodic daemon loops in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Loop,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::RuntimeLoopLastDurationMs,
        name: "moshwatch_runtime_loop_last_duration_ms",
        help: "Last observed runtime for a periodic daemon loop in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Loop,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::RuntimeLoopOverrunsTotal,
        name: "moshwatch_runtime_loop_overruns_total",
        help: "Number of times a periodic daemon loop took longer than its configured interval.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Loop,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::HistoryCurrentBytes,
        name: "moshwatch_history_current_bytes",
        help: "Current on-disk bytes retained in persistent history.",
        kind: MetricKind::Gauge,
        unit: "By",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::HistoryWrittenBytesTotal,
        name: "moshwatch_history_written_bytes_total",
        help: "Total history bytes successfully written to disk.",
        kind: MetricKind::Counter,
        unit: "By",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::HistoryWriteFailuresTotal,
        name: "moshwatch_history_write_failures_total",
        help: "Number of failed persistent history writes.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::HistoryPruneFailuresTotal,
        name: "moshwatch_history_prune_failures_total",
        help: "Number of expired history files that failed to prune.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::HistoryDroppedSamplesTotal,
        name: "moshwatch_history_dropped_samples_total",
        help: "Number of history samples dropped because persistence exceeded its disk budget.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::ThresholdRttMs,
        name: "moshwatch_threshold_rtt_ms",
        help: "Configured RTT threshold in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Severity,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::ThresholdRetransmitPct,
        name: "moshwatch_threshold_retransmit_pct",
        help: "Configured retransmit threshold as a percentage.",
        kind: MetricKind::Gauge,
        unit: "%",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Severity,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::ThresholdSilenceMs,
        name: "moshwatch_threshold_silence_ms",
        help: "Configured silence threshold in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Severity,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::OtlpExportEnabled,
        name: "moshwatch_otlp_export_enabled",
        help: "Whether OTLP metrics export is enabled for the daemon.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::ExporterDetailTier,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::OtlpExportsTotal,
        name: "moshwatch_otlp_exports_total",
        help: "Number of OTLP metrics export attempts by result.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::Low,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::Result,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::OtlpExportLastDurationMs,
        name: "moshwatch_otlp_export_last_duration_ms",
        help: "Duration of the last OTLP metrics export attempt in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::OtlpExportLastSuccessUnixMs,
        name: "moshwatch_otlp_export_last_success_unix_ms",
        help: "Unix timestamp in milliseconds of the most recent successful OTLP metrics export.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::OtlpExportLastFailureUnixMs,
        name: "moshwatch_otlp_export_last_failure_unix_ms",
        help: "Unix timestamp in milliseconds of the most recent failed OTLP metrics export.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::OtlpExportLastPayloadBytes,
        name: "moshwatch_otlp_export_last_payload_bytes",
        help: "Size in bytes of the most recent OTLP metrics export payload.",
        kind: MetricKind::Gauge,
        unit: "By",
        cardinality: MetricCardinality::Static,
        privacy: MetricPrivacy::FleetSafe,
        labels: MetricLabelSchema::None,
        minimum_detail_tier: MetricsDetailTier::AggregateOnly,
    },
    MetricDescriptor {
        id: MetricId::SessionInfo,
        name: "moshwatch_session_info",
        help: "Static session metadata kept intentionally small for metrics joins.",
        kind: MetricKind::Info,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionInfo,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionHealthLevel,
        name: "moshwatch_session_health_level",
        help: "Session health severity: ok=0, degraded=1, critical=2, legacy=3.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionSrttMs,
        name: "moshwatch_session_srtt_ms",
        help: "Smoothed round-trip time in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRttvarMs,
        name: "moshwatch_session_rttvar_ms",
        help: "RTT variance in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionLastRttMs,
        name: "moshwatch_session_last_rtt_ms",
        help: "Latest RTT sample in milliseconds.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionLastHeardAgeMs,
        name: "moshwatch_session_last_heard_age_ms",
        help: "Age in milliseconds since the daemon last heard any packet from the peer.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRemoteStateAgeMs,
        name: "moshwatch_session_remote_state_age_ms",
        help: "Age in milliseconds since the peer last sent a new remote state.",
        kind: MetricKind::Gauge,
        unit: "ms",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitPct10s,
        name: "moshwatch_session_retransmit_pct_10s",
        help: "Retransmit ratio over the last 10 seconds.",
        kind: MetricKind::Gauge,
        unit: "%",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitPct60s,
        name: "moshwatch_session_retransmit_pct_60s",
        help: "Retransmit ratio over the last 60 seconds.",
        kind: MetricKind::Gauge,
        unit: "%",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitWindowComplete,
        name: "moshwatch_session_retransmit_window_complete",
        help: "Whether the retransmit window is fully populated for a given session and window.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionWindow,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitWindowTransmissions,
        name: "moshwatch_session_retransmit_window_transmissions",
        help: "Number of transmissions counted inside the retransmit lookback window.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionWindow,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitWindowRetransmits,
        name: "moshwatch_session_retransmit_window_retransmits",
        help: "Number of retransmits counted inside the retransmit lookback window.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionWindow,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitWindowStateUpdates,
        name: "moshwatch_session_retransmit_window_state_updates",
        help: "Number of state-update transmissions counted inside the retransmit lookback window.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionWindow,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitWindowEmptyAcks,
        name: "moshwatch_session_retransmit_window_empty_acks",
        help: "Number of empty-ack transmissions counted inside the retransmit lookback window.",
        kind: MetricKind::Gauge,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionWindow,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionPacketsTxTotal,
        name: "moshwatch_session_packets_tx_total",
        help: "Total transmitted packets seen by the session.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionPacketsRxTotal,
        name: "moshwatch_session_packets_rx_total",
        help: "Total received packets seen by the session.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
    MetricDescriptor {
        id: MetricId::SessionRetransmitsTotal,
        name: "moshwatch_session_retransmits_total",
        help: "Total retransmits seen by the session.",
        kind: MetricKind::Counter,
        unit: "1",
        cardinality: MetricCardinality::PerSession,
        privacy: MetricPrivacy::OperatorSensitive,
        labels: MetricLabelSchema::SessionValue,
        minimum_detail_tier: MetricsDetailTier::PerSession,
    },
];

impl MetricId {
    pub fn descriptor(self) -> &'static MetricDescriptor {
        metric_descriptor(self)
    }
}

pub fn metric_catalog() -> &'static [MetricDescriptor] {
    METRIC_CATALOG
}

pub fn metric_descriptor(id: MetricId) -> &'static MetricDescriptor {
    METRIC_CATALOG
        .iter()
        .find(|descriptor| descriptor.id == id)
        .expect("metric descriptor missing")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{METRIC_CATALOG, MetricLabelSchema, MetricPrivacy};

    #[test]
    fn metric_catalog_names_are_unique() {
        let mut seen = HashSet::new();
        for descriptor in METRIC_CATALOG {
            assert!(
                seen.insert(descriptor.name),
                "duplicate metric {}",
                descriptor.name
            );
        }
    }

    #[test]
    fn session_value_series_stay_operator_sensitive() {
        for descriptor in METRIC_CATALOG {
            if matches!(
                descriptor.labels,
                MetricLabelSchema::SessionValue
                    | MetricLabelSchema::SessionInfo
                    | MetricLabelSchema::SessionWindow
            ) {
                assert_eq!(descriptor.privacy, MetricPrivacy::OperatorSensitive);
            }
        }
    }
}
