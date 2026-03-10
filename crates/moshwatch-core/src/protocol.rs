// SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};

pub const API_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Instrumented,
    Legacy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Ok,
    Degraded,
    Critical,
    Legacy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    SessionOpen,
    SessionTick,
    SessionClose,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct RetransmitWindowBreakdown {
    pub transmissions_total: Option<u64>,
    pub retransmits_total: Option<u64>,
    pub state_updates_total: Option<u64>,
    pub empty_acks_total: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SessionMetrics {
    pub srtt_ms: Option<f64>,
    pub rttvar_ms: Option<f64>,
    pub last_rtt_ms: Option<f64>,
    pub last_heard_age_ms: Option<u64>,
    pub remote_state_age_ms: Option<u64>,
    pub packets_tx_total: Option<u64>,
    pub packets_rx_total: Option<u64>,
    pub retransmits_total: Option<u64>,
    pub empty_acks_tx_total: Option<u64>,
    pub state_updates_tx_total: Option<u64>,
    pub state_updates_rx_total: Option<u64>,
    pub duplicate_states_rx_total: Option<u64>,
    pub out_of_order_states_rx_total: Option<u64>,
    pub retransmit_pct_10s: Option<f64>,
    pub retransmit_pct_60s: Option<f64>,
    pub retransmit_window_10s_complete: bool,
    pub retransmit_window_60s_complete: bool,
    pub retransmit_window_10s_breakdown: RetransmitWindowBreakdown,
    pub retransmit_window_60s_breakdown: RetransmitWindowBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub unix_ms: i64,
    pub srtt_ms: Option<f64>,
    pub retransmit_pct_10s: Option<f64>,
    pub remote_state_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub display_session_id: Option<String>,
    pub pid: i32,
    pub kind: SessionKind,
    pub health: HealthState,
    pub started_at_unix_ms: i64,
    pub last_observed_unix_ms: i64,
    pub bind_addr: Option<String>,
    pub udp_port: Option<u16>,
    pub client_addr: Option<String>,
    pub cmdline: String,
    pub metrics: SessionMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    #[serde(flatten)]
    pub summary: SessionSummary,
    pub total_history_points: usize,
    pub truncated_history_points: usize,
    pub history: Vec<MetricPoint>,
}

impl SessionSnapshot {
    pub fn into_summary(self) -> SessionSummary {
        self.summary
    }
}

impl SessionSummary {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionsResponse {
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub total_sessions: usize,
    pub truncated_session_count: usize,
    pub dropped_sessions_total: u64,
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionResponse {
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub session: SessionSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionControlAction {
    Terminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionControlResponse {
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub session_id: String,
    pub pid: i32,
    pub action: SessionControlAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfigResponse {
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub config: crate::config::AppConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer: Option<crate::identity::ObserverInfo>,
    pub recorded_at_unix_ms: i64,
    pub session_id: String,
    pub display_session_id: Option<String>,
    pub pid: i32,
    pub kind: SessionKind,
    pub health: HealthState,
    pub started_at_unix_ms: i64,
    pub bind_addr: Option<String>,
    pub udp_port: Option<u16>,
    pub client_addr: Option<String>,
    pub metrics: SessionMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiHistoryResponse {
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub session_id: String,
    pub samples: Vec<HistorySample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventStreamEvent {
    Snapshot,
    Heartbeat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStreamFrame {
    pub schema_version: u32,
    pub observer: crate::identity::ObserverInfo,
    pub event: EventStreamEvent,
    pub sequence: Option<u64>,
    pub generated_at_unix_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_sessions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_session_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_sessions_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<SessionSummary>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event: TelemetryEventKind,
    #[serde(default, alias = "session_id")]
    pub display_session_id: Option<String>,
    pub pid: i32,
    pub unix_ms: i64,
    pub started_at_unix_ms: Option<i64>,
    pub bind_addr: Option<String>,
    pub udp_port: Option<u16>,
    pub client_addr: Option<String>,
    pub last_heard_age_ms: Option<u64>,
    pub remote_state_age_ms: Option<u64>,
    pub srtt_ms: Option<f64>,
    pub rttvar_ms: Option<f64>,
    pub last_rtt_ms: Option<f64>,
    pub packets_tx_total: Option<u64>,
    pub packets_rx_total: Option<u64>,
    pub retransmits_total: Option<u64>,
    pub empty_acks_tx_total: Option<u64>,
    pub state_updates_tx_total: Option<u64>,
    pub state_updates_rx_total: Option<u64>,
    pub duplicate_states_rx_total: Option<u64>,
    pub out_of_order_states_rx_total: Option<u64>,
    pub cmdline: Option<String>,
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
