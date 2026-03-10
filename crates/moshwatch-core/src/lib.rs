// SPDX-License-Identifier: GPL-3.0-or-later

pub mod config;
pub mod identity;
pub mod protocol;
pub mod time;

pub use config::{
    AppConfig, HealthThresholds, RuntimePaths, remove_socket_if_present, set_socket_owner_only,
};
pub use identity::{ObserverInfo, discover_observer_info};
pub use protocol::{
    API_SCHEMA_VERSION, ApiConfigResponse, ApiHistoryResponse, ApiSessionControlResponse,
    ApiSessionResponse, ApiSessionsResponse, EventStreamEvent, EventStreamFrame, HealthState,
    HistorySample, MetricPoint, RetransmitWindowBreakdown, SessionControlAction, SessionKind,
    SessionMetrics, SessionSnapshot, SessionSummary, TelemetryEvent, TelemetryEventKind,
    classify_health,
};
