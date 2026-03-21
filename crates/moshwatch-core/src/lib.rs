// SPDX-License-Identifier: GPL-3.0-or-later

pub mod config;
pub mod identity;
pub mod observability;
pub mod protocol;
pub mod time;

pub use config::{
    AppConfig, HealthThresholds, MetricsConfig, OtlpMetricsConfig, PrometheusMetricsConfig,
    RuntimePaths, remove_socket_if_present, set_socket_owner_only,
};
pub use identity::{ObserverInfo, discover_observer_info};
pub use observability::{
    METRIC_CATALOG, MetricCardinality, MetricDescriptor, MetricId, MetricKind, MetricLabelSchema,
    MetricPrivacy, MetricType, MetricsDetailLevel, MetricsDetailTier, metric_catalog,
    metric_descriptor,
};
pub use protocol::{
    API_SCHEMA_VERSION, ApiAppConfig, ApiConfigResponse, ApiHistoryResponse, ApiMetricsConfig,
    ApiSessionControlResponse, ApiSessionResponse, ApiSessionsResponse, EventStreamEvent,
    EventStreamFrame, HealthState, HistorySample, MetricPoint, RetransmitWindowBreakdown,
    SessionControlAction, SessionKind, SessionMetrics, SessionPeerInfo, SessionSnapshot,
    SessionSummary, TelemetryEvent, TelemetryEventKind, classify_health,
};
