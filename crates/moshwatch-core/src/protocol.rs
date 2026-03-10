// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared API, event-stream, and telemetry protocol contracts.
//!
//! ## Rationale
//! `moshwatch-core` is the narrow contract surface shared by the daemon, UI,
//! and any future API consumers. Keeping these types in one place makes schema
//! changes explicit.
//!
//! ## Security Boundaries
//! * These types describe local observability data only; they do not verify
//!   trust by themselves.
//! * `None` on optional metrics generally means "unknown or unavailable", not
//!   zero.
//! * Event-stream frames are latest-state snapshots, not a durable replay log.
//!
//! ## References
//! * `docs/design/modularisation-and-boundaries.md`

use serde::{Deserialize, Serialize};

/// Version number for the exported API and event-stream schema.
///
/// Bump this only when a consumer-visible contract changes.
pub const API_SCHEMA_VERSION: u32 = 2;

/// Session classification used throughout the API and history surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// Session with verified local telemetry from the instrumented server.
    Instrumented,
    /// Session discovered via `/proc` only, without verified telemetry.
    Legacy,
}

/// High-level operator health state derived from configured thresholds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// No configured latency, silence, or retransmit threshold is currently breached.
    Ok,
    /// At least one warning threshold is currently breached.
    Degraded,
    /// At least one critical threshold is currently breached.
    Critical,
    /// Legacy discovery-only session without verified telemetry.
    Legacy,
}

/// Lifecycle event emitted by the instrumented `mosh-server-real` wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    /// Session start/open event.
    SessionOpen,
    /// Periodic metrics update from a live session.
    SessionTick,
    /// Session close/shutdown event.
    SessionClose,
}

/// Raw counter deltas used to explain a retransmit percentage window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct RetransmitWindowBreakdown {
    /// Total transmissions in the window: state updates + retransmits + empty ACKs.
    pub transmissions_total: Option<u64>,
    /// Total retransmit packets observed in the window.
    pub retransmits_total: Option<u64>,
    /// Total state-update packets observed in the window.
    pub state_updates_total: Option<u64>,
    /// Total empty ACK packets observed in the window.
    pub empty_acks_total: Option<u64>,
}

/// Current per-session live metrics and bounded window summaries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SessionMetrics {
    /// Smoothed round-trip time in milliseconds.
    pub srtt_ms: Option<f64>,
    /// RTT variation estimate in milliseconds.
    pub rttvar_ms: Option<f64>,
    /// Most recent raw RTT sample in milliseconds.
    pub last_rtt_ms: Option<f64>,
    /// Time since the daemon last heard session traffic, in milliseconds.
    pub last_heard_age_ms: Option<u64>,
    /// Time since the remote state last advanced, in milliseconds.
    pub remote_state_age_ms: Option<u64>,
    /// Monotonic total transmitted packets reported by telemetry.
    pub packets_tx_total: Option<u64>,
    /// Monotonic total received packets reported by telemetry.
    pub packets_rx_total: Option<u64>,
    /// Monotonic total retransmitted packets reported by telemetry.
    pub retransmits_total: Option<u64>,
    /// Monotonic total transmitted empty ACK packets.
    pub empty_acks_tx_total: Option<u64>,
    /// Monotonic total transmitted state-update packets.
    pub state_updates_tx_total: Option<u64>,
    /// Monotonic total received state-update packets.
    pub state_updates_rx_total: Option<u64>,
    /// Monotonic total duplicate state packets received.
    pub duplicate_states_rx_total: Option<u64>,
    /// Monotonic total out-of-order state packets received.
    pub out_of_order_states_rx_total: Option<u64>,
    /// Retransmit ratio over the trailing 10-second window, or `None` when unknown.
    pub retransmit_pct_10s: Option<f64>,
    /// Retransmit ratio over the trailing 60-second window, or `None` when unknown.
    pub retransmit_pct_60s: Option<f64>,
    /// Whether the daemon has at least 10 seconds of history for the window.
    pub retransmit_window_10s_complete: bool,
    /// Whether the daemon has at least 60 seconds of history for the window.
    pub retransmit_window_60s_complete: bool,
    /// Raw counter math behind the 10-second retransmit window.
    pub retransmit_window_10s_breakdown: RetransmitWindowBreakdown,
    /// Raw counter math behind the 60-second retransmit window.
    pub retransmit_window_60s_breakdown: RetransmitWindowBreakdown,
}

/// Single history point used by session-detail sparklines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    /// Sample timestamp in Unix milliseconds.
    pub unix_ms: i64,
    /// Smoothed RTT sample at this point, if known.
    pub srtt_ms: Option<f64>,
    /// 10-second retransmit percentage at this point, if known.
    pub retransmit_pct_10s: Option<f64>,
    /// Remote-state age at this point, if known.
    pub remote_state_age_ms: Option<u64>,
}

/// Live peer state derived from verified telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SessionPeerInfo {
    /// Current client endpoint reported by the most recent telemetry update.
    pub current_client_addr: Option<String>,
    /// Last known client endpoint seen for this session, even if the client is currently absent.
    pub last_client_addr: Option<String>,
    /// Previous non-null client endpoint when the client roamed to a new address.
    pub previous_client_addr: Option<String>,
    /// Last Unix-millisecond timestamp where telemetry reported a non-null client endpoint.
    pub last_client_seen_at_unix_ms: Option<i64>,
    /// Unix-millisecond timestamp when the session last changed to a different non-null client endpoint.
    pub client_addr_changed_at_unix_ms: Option<i64>,
}

/// Exported live summary for one tracked session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Stable daemon-assigned session identity.
    pub session_id: String,
    /// Human-facing session label reported by telemetry when available.
    pub display_session_id: Option<String>,
    /// Current process id of the tracked `mosh-server`.
    pub pid: i32,
    /// Session classification.
    pub kind: SessionKind,
    /// Current derived health state.
    pub health: HealthState,
    /// Process start time in Unix milliseconds used for PID-reuse protection.
    pub started_at_unix_ms: i64,
    /// Last time this session was observed by telemetry or discovery.
    pub last_observed_unix_ms: i64,
    /// Bound local address when known.
    pub bind_addr: Option<String>,
    /// Bound UDP port when known.
    pub udp_port: Option<u16>,
    /// Last known remote client address when known. Compatibility alias for `peer.last_client_addr`.
    pub client_addr: Option<String>,
    /// Explicit live peer state derived from telemetry.
    #[serde(default)]
    pub peer: SessionPeerInfo,
    /// Sanitized command line used for operator display.
    pub cmdline: String,
    /// Current metrics for the session.
    pub metrics: SessionMetrics,
}

/// Session summary plus bounded history for detail views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    #[serde(flatten)]
    /// Flattened current session summary.
    pub summary: SessionSummary,
    /// Total history points retained internally for this session.
    pub total_history_points: usize,
    /// Number of oldest points omitted from `history` due to export caps.
    pub truncated_history_points: usize,
    /// Exported history slice in chronological order.
    pub history: Vec<MetricPoint>,
}

impl SessionSnapshot {
    /// Discard detail history and keep only the session summary.
    pub fn into_summary(self) -> SessionSummary {
        self.summary
    }
}

impl SessionSummary {
    /// Attach an exported history slice to this summary.
    pub fn with_history(
        self,
        total_history_points: usize,
        truncated_history_points: usize,
        history: Vec<MetricPoint>,
    ) -> SessionSnapshot {
        SessionSnapshot {
            summary: self,
            total_history_points,
            truncated_history_points,
            history,
        }
    }
}

/// Derive operator health from the session kind, live metrics, and thresholds.
///
/// Legacy sessions remain `HealthState::Legacy` because they lack verified
/// telemetry. Instrumented sessions use warning and critical thresholds across
/// latency, silence, and retransmit ratios.
pub fn classify_health(
    kind: &SessionKind,
    metrics: &SessionMetrics,
    thresholds: &crate::config::HealthThresholds,
) -> HealthState {
    if *kind == SessionKind::Legacy {
        return HealthState::Legacy;
    }

    let rtt_critical = metrics
        .srtt_ms
        .is_some_and(|value| value >= thresholds.critical_rtt_ms as f64);
    let rtt_warn = metrics
        .srtt_ms
        .is_some_and(|value| value >= thresholds.warn_rtt_ms as f64);
    let retransmit_critical = metrics
        .retransmit_pct_60s
        .is_some_and(|value| value >= thresholds.critical_retransmit_pct);
    let retransmit_warn = metrics
        .retransmit_pct_10s
        .is_some_and(|value| value >= thresholds.warn_retransmit_pct)
        || metrics
            .retransmit_pct_60s
            .is_some_and(|value| value >= thresholds.warn_retransmit_pct);
    let silence_critical = metrics
        .last_heard_age_ms
        .is_some_and(|value| value >= thresholds.critical_silence_ms);
    let silence_warn = metrics
        .last_heard_age_ms
        .is_some_and(|value| value >= thresholds.warn_silence_ms);

    if rtt_critical || retransmit_critical || silence_critical {
        HealthState::Critical
    } else if rtt_warn || retransmit_warn || silence_warn {
        HealthState::Degraded
    } else {
        HealthState::Ok
    }
}

/// Response body for `GET /v1/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionsResponse {
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Total tracked sessions before truncation.
    pub total_sessions: usize,
    /// Number of sessions omitted from `sessions` due to export caps.
    pub truncated_session_count: usize,
    /// Total sessions dropped or rejected because of tracking caps.
    pub dropped_sessions_total: u64,
    /// Exported live summaries in display order.
    pub sessions: Vec<SessionSummary>,
}

/// Response body for `GET /v1/sessions/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionResponse {
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Detailed snapshot for the requested session.
    pub session: SessionSnapshot,
}

/// Supported control actions for tracked sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionControlAction {
    /// Request graceful termination of the tracked process with `SIGTERM`.
    Terminate,
}

/// Response body for successful session control requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionControlResponse {
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Stable daemon-assigned session identity.
    pub session_id: String,
    /// Process id that received the control action.
    pub pid: i32,
    /// Control action that was requested.
    pub action: SessionControlAction,
}

/// Response body for `GET /v1/config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfigResponse {
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Effective daemon configuration.
    pub config: crate::config::AppConfig,
}

/// Persisted history sample for one session at one recording point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Observer identity recorded with the sample when available.
    pub observer: Option<crate::identity::ObserverInfo>,
    /// Sample recording time in Unix milliseconds.
    pub recorded_at_unix_ms: i64,
    /// Stable daemon-assigned session identity.
    pub session_id: String,
    /// Human-facing session label when available.
    pub display_session_id: Option<String>,
    /// Process id at the time of sampling.
    pub pid: i32,
    /// Session classification at the time of sampling.
    pub kind: SessionKind,
    /// Derived health state at the time of sampling.
    pub health: HealthState,
    /// Process start time in Unix milliseconds.
    pub started_at_unix_ms: i64,
    /// Bound local address when known.
    pub bind_addr: Option<String>,
    /// Bound UDP port when known.
    pub udp_port: Option<u16>,
    /// Remote client address when known.
    pub client_addr: Option<String>,
    /// Metrics snapshot recorded with the sample.
    pub metrics: SessionMetrics,
}

/// Response body for `GET /v1/history/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiHistoryResponse {
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Requested session identity.
    pub session_id: String,
    /// Returned history samples in chronological order.
    pub samples: Vec<HistorySample>,
}

/// Event kind carried by the latest-state NDJSON stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventStreamEvent {
    /// Full latest-state snapshot frame.
    Snapshot,
    /// Heartbeat frame emitted to keep an idle stream fresh.
    Heartbeat,
}

/// Single NDJSON frame emitted by `GET /v1/events/stream`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStreamFrame {
    /// Event-stream schema version.
    pub schema_version: u32,
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Frame kind.
    pub event: EventStreamEvent,
    /// Monotonic sequence for snapshot frames; heartbeats carry `None`.
    pub sequence: Option<u64>,
    /// Frame generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Total tracked sessions before truncation, for snapshot frames only.
    pub total_sessions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Number of omitted sessions, for snapshot frames only.
    pub truncated_session_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Total dropped sessions due to tracking caps, for snapshot frames only.
    pub dropped_sessions_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Latest exported session set, for snapshot frames only.
    pub sessions: Option<Vec<SessionSummary>>,
}

/// Raw telemetry payload sent by the instrumented `mosh-server-real`.
///
/// The daemon validates this against verified local process metadata before
/// trusting it, and may rewrite some fields from the verified peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Session lifecycle event kind.
    pub event: TelemetryEventKind,
    #[serde(default, alias = "session_id")]
    /// Human-facing session label reported by the peer when available.
    pub display_session_id: Option<String>,
    /// Process id reported by the peer before daemon verification.
    pub pid: i32,
    /// Peer-observed event timestamp in Unix milliseconds.
    pub unix_ms: i64,
    /// Peer-reported process start time in Unix milliseconds.
    pub started_at_unix_ms: Option<i64>,
    /// Bound local address when known.
    pub bind_addr: Option<String>,
    /// Bound UDP port when known.
    pub udp_port: Option<u16>,
    /// Remote client address when known.
    pub client_addr: Option<String>,
    /// Time since last heard traffic, in milliseconds.
    pub last_heard_age_ms: Option<u64>,
    /// Time since remote state last advanced, in milliseconds.
    pub remote_state_age_ms: Option<u64>,
    /// Smoothed RTT in milliseconds.
    pub srtt_ms: Option<f64>,
    /// RTT variation estimate in milliseconds.
    pub rttvar_ms: Option<f64>,
    /// Most recent raw RTT sample in milliseconds.
    pub last_rtt_ms: Option<f64>,
    /// Monotonic total transmitted packets.
    pub packets_tx_total: Option<u64>,
    /// Monotonic total received packets.
    pub packets_rx_total: Option<u64>,
    /// Monotonic total retransmitted packets.
    pub retransmits_total: Option<u64>,
    /// Monotonic total transmitted empty ACK packets.
    pub empty_acks_tx_total: Option<u64>,
    /// Monotonic total transmitted state-update packets.
    pub state_updates_tx_total: Option<u64>,
    /// Monotonic total received state-update packets.
    pub state_updates_rx_total: Option<u64>,
    /// Monotonic total duplicate state packets received.
    pub duplicate_states_rx_total: Option<u64>,
    /// Monotonic total out-of-order state packets received.
    pub out_of_order_states_rx_total: Option<u64>,
    /// Sanitized command line of the sending process when available.
    pub cmdline: Option<String>,
    /// Optional shutdown hint from the peer.
    pub shutdown: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::{HealthState, SessionKind, SessionMetrics, classify_health};
    use crate::config::HealthThresholds;

    #[test]
    fn legacy_sessions_stay_legacy() {
        let metrics = SessionMetrics::default();
        assert_eq!(
            classify_health(&SessionKind::Legacy, &metrics, &HealthThresholds::default()),
            HealthState::Legacy
        );
    }

    #[test]
    fn critical_latency_beats_other_signals() {
        let metrics = SessionMetrics {
            srtt_ms: Some(1_500.0),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Critical
        );
    }

    #[test]
    fn degraded_retransmit_ratio_marks_session_degraded() {
        let metrics = SessionMetrics {
            retransmit_pct_10s: Some(4.5),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Degraded
        );
    }

    #[test]
    fn critical_retransmit_requires_sustained_window() {
        let metrics = SessionMetrics {
            retransmit_pct_10s: Some(40.0),
            retransmit_pct_60s: Some(8.0),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Degraded
        );
    }

    #[test]
    fn remote_state_age_does_not_trigger_silence_health() {
        let metrics = SessionMetrics {
            remote_state_age_ms: Some(60_000),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Ok
        );
    }
}
