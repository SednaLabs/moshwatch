// SPDX-License-Identifier: GPL-3.0-or-later

//! In-memory session registry and merge policy.
//!
//! `ServiceState` is where verified telemetry, `/proc` discovery, export caps,
//! and session-retention policy meet. The implementation stays explicit because
//! the correctness and security edge cases live in those merge rules.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque},
};

use moshwatch_core::{
    AppConfig, HealthState, MetricPoint, RetransmitWindowBreakdown, SessionKind, SessionMetrics,
    SessionSnapshot, SessionSummary, TelemetryEvent, TelemetryEventKind, classify_health,
};

use crate::{
    discovery::DiscoveredSession,
    sanitize::{sanitize_cmdline, sanitize_display_session_id, sanitize_endpoint},
};

#[derive(Debug, Clone)]
struct CounterSample {
    unix_ms: i64,
    state_updates_tx_total: Option<u64>,
    retransmits_total: Option<u64>,
    empty_acks_tx_total: Option<u64>,
}

#[derive(Debug, Clone)]
struct SessionRecord {
    summary: SessionSummary,
    history: VecDeque<MetricPoint>,
    counters: VecDeque<CounterSample>,
    shutdown: bool,
}

#[derive(Debug, Clone)]
pub struct ServiceState {
    config: AppConfig,
    sessions: HashMap<String, SessionRecord>,
    dropped_sessions_total: u64,
}

#[derive(Debug, Clone)]
pub struct ExportedSummaries {
    pub sessions: Vec<SessionSummary>,
    pub total_sessions: usize,
    pub truncated_session_count: usize,
    pub instrumented_sessions: usize,
    pub legacy_sessions: usize,
    pub dropped_sessions_total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct RetransmitWindow {
    pct: Option<f64>,
    complete: bool,
    breakdown: RetransmitWindowBreakdown,
}

impl ServiceState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            dropped_sessions_total: 0,
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn apply_telemetry(&mut self, session_id: String, event: TelemetryEvent) {
        self.apply_telemetry_at(session_id, event, moshwatch_core::time::unix_time_ms());
    }

    fn apply_telemetry_at(
        &mut self,
        session_id: String,
        event: TelemetryEvent,
        received_at_unix_ms: i64,
    ) {
        // Verified telemetry is authoritative for instrumented sessions. If
        // discovery created a legacy placeholder for the same `(pid,
        // started_at)` tuple, upgrade that record in place so callers do not
        // lose accumulated history during the handoff.
        let display_session_id = sanitize_display_session_id(event.display_session_id.clone());
        let bind_addr = sanitize_endpoint(event.bind_addr.clone());
        let client_addr = sanitize_endpoint(event.client_addr.clone());
        let cmdline = event.cmdline.clone().map(sanitize_cmdline);
        let initial_observed_unix_ms = event.unix_ms.min(received_at_unix_ms);
        let started_at = event.started_at_unix_ms.unwrap_or(initial_observed_unix_ms);
        let legacy_session_id = legacy_session_id(event.pid, started_at);
        if session_id != legacy_session_id
            && !self.sessions.contains_key(&session_id)
            && let Some(legacy_record) = self.sessions.remove(&legacy_session_id)
        {
            self.sessions.insert(
                session_id.clone(),
                SessionRecord {
                    summary: SessionSummary {
                        session_id: session_id.clone(),
                        kind: SessionKind::Instrumented,
                        ..legacy_record.summary
                    },
                    history: legacy_record.history,
                    counters: legacy_record.counters,
                    shutdown: legacy_record.shutdown,
                },
            );
        }
        let session_shutdown =
            event.shutdown.unwrap_or(false) || event.event == TelemetryEventKind::SessionClose;
        if !self.sessions.contains_key(&session_id)
            && self.reject_new_active_instrumented_session(session_shutdown)
        {
            return;
        }

        let entry = self
            .sessions
            .entry(session_id.clone())
            .or_insert_with(|| SessionRecord {
                summary: SessionSummary {
                    session_id: session_id.clone(),
                    display_session_id: display_session_id.clone(),
                    pid: event.pid,
                    kind: SessionKind::Instrumented,
                    health: HealthState::Ok,
                    started_at_unix_ms: started_at,
                    last_observed_unix_ms: initial_observed_unix_ms,
                    bind_addr: bind_addr.clone(),
                    udp_port: event.udp_port,
                    client_addr: client_addr.clone(),
                    cmdline: cmdline
                        .clone()
                        .unwrap_or_else(|| "mosh-server-real".to_string()),
                    metrics: SessionMetrics::default(),
                },
                history: VecDeque::new(),
                counters: VecDeque::new(),
                shutdown: false,
            });
        let event_unix_ms =
            normalize_event_unix_ms(&entry.summary, event.unix_ms, received_at_unix_ms);
        if metrics_regressed(&entry.summary.metrics, &event) {
            tracing::warn!(
                session_id = %session_id,
                pid = entry.summary.pid,
                "reset session history after telemetry counter regression"
            );
            entry.history.clear();
            entry.counters.clear();
        } else if entry
            .history
            .back()
            .is_some_and(|point| event_unix_ms < point.unix_ms)
        {
            tracing::warn!(
                session_id = %session_id,
                pid = entry.summary.pid,
                "reset session history after telemetry time regression"
            );
            entry.history.clear();
            entry.counters.clear();
        }

        entry.summary.session_id = session_id;
        entry.summary.pid = event.pid;
        entry.summary.kind = SessionKind::Instrumented;
        entry.summary.started_at_unix_ms = started_at;
        entry.summary.last_observed_unix_ms = event_unix_ms;
        if entry.summary.display_session_id.is_none() {
            entry.summary.display_session_id = display_session_id;
        }
        entry.summary.bind_addr = bind_addr.or(entry.summary.bind_addr.clone());
        entry.summary.udp_port = event.udp_port.or(entry.summary.udp_port);
        entry.summary.client_addr = client_addr.or(entry.summary.client_addr.clone());
        if let Some(cmdline) = cmdline
            && !cmdline.trim().is_empty()
        {
            entry.summary.cmdline = cmdline;
        }

        entry.summary.metrics.srtt_ms = event.srtt_ms;
        entry.summary.metrics.rttvar_ms = event.rttvar_ms;
        entry.summary.metrics.last_rtt_ms = event.last_rtt_ms;
        entry.summary.metrics.last_heard_age_ms = event.last_heard_age_ms;
        entry.summary.metrics.remote_state_age_ms = event.remote_state_age_ms;
        entry.summary.metrics.packets_tx_total = event.packets_tx_total;
        entry.summary.metrics.packets_rx_total = event.packets_rx_total;
        entry.summary.metrics.retransmits_total = event.retransmits_total;
        entry.summary.metrics.empty_acks_tx_total = event.empty_acks_tx_total;
        entry.summary.metrics.state_updates_tx_total = event.state_updates_tx_total;
        entry.summary.metrics.state_updates_rx_total = event.state_updates_rx_total;
        entry.summary.metrics.duplicate_states_rx_total = event.duplicate_states_rx_total;
        entry.summary.metrics.out_of_order_states_rx_total = event.out_of_order_states_rx_total;

        upsert_history_point(
            &mut entry.history,
            MetricPoint {
                unix_ms: event_unix_ms,
                srtt_ms: event.srtt_ms,
                retransmit_pct_10s: None,
                remote_state_age_ms: event.remote_state_age_ms,
            },
        );
        upsert_counter_sample(
            &mut entry.counters,
            CounterSample {
                unix_ms: event_unix_ms,
                state_updates_tx_total: event.state_updates_tx_total,
                retransmits_total: event.retransmits_total,
                empty_acks_tx_total: event.empty_acks_tx_total,
            },
        );
        trim_history(&mut entry.history, self.config.history_secs);
        trim_history(&mut entry.counters, self.config.history_secs);

        let retransmit_10 = retransmit_pct(&entry.counters, 10_000);
        let retransmit_60 = retransmit_pct(&entry.counters, 60_000);
        entry.summary.metrics.retransmit_pct_10s = retransmit_10.pct;
        entry.summary.metrics.retransmit_pct_60s = retransmit_60.pct;
        entry.summary.metrics.retransmit_window_10s_complete = retransmit_10.complete;
        entry.summary.metrics.retransmit_window_60s_complete = retransmit_60.complete;
        entry.summary.metrics.retransmit_window_10s_breakdown = retransmit_10.breakdown;
        entry.summary.metrics.retransmit_window_60s_breakdown = retransmit_60.breakdown;
        if let Some(last_point) = entry.history.back_mut() {
            last_point.retransmit_pct_10s = retransmit_10.pct;
        }

        entry.summary.health = classify_health(
            &entry.summary.kind,
            &entry.summary.metrics,
            &self.config.thresholds,
        );
        if event.event == TelemetryEventKind::SessionClose {
            entry.shutdown = true;
        }
        if let Some(shutdown) = event.shutdown {
            entry.shutdown = shutdown;
        } else {
            entry.shutdown = session_shutdown;
        }
        self.enforce_session_cap();
    }

    pub fn refresh_discovery(&mut self, discovered: Vec<DiscoveredSession>, now_ms: i64) {
        // Discovery is intentionally weaker than verified telemetry: it keeps
        // stock sessions visible and fills endpoint metadata gaps, but it does
        // not get to overwrite instrumented telemetry state that was already
        // tied to a verified local peer.
        let mut seen_ids = HashSet::new();
        for session in discovered {
            let instrumented_id = instrumented_session_id(session.pid, session.started_at_unix_ms);
            let legacy_id = legacy_session_id(session.pid, session.started_at_unix_ms);
            let session_id = if self.sessions.contains_key(&instrumented_id) {
                instrumented_id
            } else {
                legacy_id
            };
            seen_ids.insert(session_id.clone());

            let entry = self
                .sessions
                .entry(session_id.clone())
                .or_insert_with(|| SessionRecord {
                    summary: SessionSummary {
                        session_id,
                        display_session_id: None,
                        pid: session.pid,
                        kind: SessionKind::Legacy,
                        health: HealthState::Legacy,
                        started_at_unix_ms: session.started_at_unix_ms,
                        last_observed_unix_ms: now_ms,
                        bind_addr: session.bind_addr.clone(),
                        udp_port: session.udp_port,
                        client_addr: None,
                        cmdline: session.cmdline.clone(),
                        metrics: SessionMetrics::default(),
                    },
                    history: VecDeque::new(),
                    counters: VecDeque::new(),
                    shutdown: false,
                });

            entry.summary.pid = session.pid;
            if entry.summary.kind == SessionKind::Legacy {
                entry.summary.started_at_unix_ms = session.started_at_unix_ms;
                entry.summary.last_observed_unix_ms = now_ms;
                entry.summary.bind_addr = session.bind_addr.or(entry.summary.bind_addr.clone());
                entry.summary.udp_port = session.udp_port.or(entry.summary.udp_port);
                entry.summary.cmdline = session.cmdline;
                entry.summary.health = HealthState::Legacy;
            } else {
                entry.summary.health = classify_health(
                    &entry.summary.kind,
                    &entry.summary.metrics,
                    &self.config.thresholds,
                );
            }
        }

        let stale_cutoff_ms = (self.config.cleanup_interval_ms * 3).max(30_000) as i64;
        let shutdown_grace_ms = self.config.discovery_interval_ms.max(5_000) as i64;
        let legacy_grace_ms = self.config.discovery_interval_ms.max(5_000) as i64;
        // Session disappearance policy is intentionally asymmetric:
        // * discovery-only legacy sessions age out quickly once `/proc` no
        //   longer shows them
        // * instrumented shutdown sessions get a short grace period so the UI
        //   can observe closure
        // * active instrumented sessions get a longer stale cutoff because
        //   missing discovery does not override verified telemetry immediately
        self.sessions.retain(|session_id, entry| {
            if seen_ids.contains(session_id) {
                return true;
            }
            let age_ms = now_ms - entry.summary.last_observed_unix_ms;
            if entry.summary.kind != SessionKind::Instrumented {
                return age_ms < legacy_grace_ms;
            }
            if entry.shutdown {
                age_ms < shutdown_grace_ms
            } else {
                age_ms < stale_cutoff_ms
            }
        });
        self.enforce_session_cap();
    }

    pub fn summaries(&self, now_ms: i64) -> Vec<SessionSummary> {
        let mut sessions = self
            .sessions
            .values()
            .map(|record| self.materialize_summary(record, now_ms))
            .collect::<Vec<_>>();
        sessions.sort_by(compare_summaries);
        sessions
    }

    pub fn export_summaries(&self, now_ms: i64, limit: usize) -> ExportedSummaries {
        // Export paths are bounded on purpose. Callers still receive full
        // cardinality metadata so truncation is explicit rather than silent.
        let mut sessions = Vec::with_capacity(limit.min(self.sessions.len()));
        let mut instrumented_sessions = 0usize;
        let mut legacy_sessions = 0usize;

        for record in self.sessions.values() {
            let summary = self.materialize_summary(record, now_ms);
            match summary.kind {
                SessionKind::Instrumented => instrumented_sessions += 1,
                SessionKind::Legacy => legacy_sessions += 1,
            }
            if limit == 0 {
                continue;
            }
            sessions.push(summary);
            sessions.sort_by(compare_summaries);
            if sessions.len() > limit {
                sessions.pop();
            }
        }

        let total_sessions = instrumented_sessions + legacy_sessions;
        let truncated_session_count = total_sessions.saturating_sub(sessions.len());
        ExportedSummaries {
            sessions,
            total_sessions,
            truncated_session_count,
            instrumented_sessions,
            legacy_sessions,
            dropped_sessions_total: self.dropped_sessions_total,
        }
    }

    pub fn session_detail(&self, session_id: &str, now_ms: i64) -> Option<SessionSnapshot> {
        self.sessions.get(session_id).map(|record| {
            let total_history_points = record.history.len();
            let kept_history_points =
                total_history_points.min(self.config.max_session_detail_points);
            let truncated_history_points = total_history_points.saturating_sub(kept_history_points);
            let history = record
                .history
                .iter()
                .skip(truncated_history_points)
                .cloned()
                .collect();
            self.materialize_summary(record, now_ms).with_history(
                total_history_points,
                truncated_history_points,
                history,
            )
        })
    }

    pub fn session_summary(&self, session_id: &str, now_ms: i64) -> Option<SessionSummary> {
        self.sessions
            .get(session_id)
            .map(|record| self.materialize_summary(record, now_ms))
    }

    fn enforce_session_cap(&mut self) {
        // When memory pressure or hostile cardinality pushes us over the cap,
        // evict the lowest-priority record and count it so operators can see
        // that exports are incomplete.
        while self.sessions.len() > self.config.max_tracked_sessions {
            let Some(session_id) = self
                .sessions
                .iter()
                .min_by(|(_, left), (_, right)| compare_eviction_priority(left, right))
                .map(|(session_id, _)| session_id.clone())
            else {
                break;
            };
            if self.sessions.remove(&session_id).is_some() {
                self.dropped_sessions_total = self.dropped_sessions_total.saturating_add(1);
            }
        }
    }

    fn reject_new_active_instrumented_session(&mut self, shutdown: bool) -> bool {
        // Refuse a brand-new active instrumented session only when the cap is
        // already saturated with higher-priority records. This prevents churn
        // where an attacker rotates fresh sessions and continuously evicts
        // established instrumented ones.
        //
        // Priority order is `legacy < instrumented shutdown < instrumented
        // active`. `dropped_sessions_total` counts both these rejected
        // admissions and later evictions from the tracked set.
        if shutdown || self.sessions.len() < self.config.max_tracked_sessions {
            return false;
        }
        let Some((_, worst_record)) = self
            .sessions
            .iter()
            .min_by(|(_, left), (_, right)| compare_eviction_priority(left, right))
        else {
            return false;
        };
        if eviction_class(worst_record) == 2 {
            self.dropped_sessions_total = self.dropped_sessions_total.saturating_add(1);
            return true;
        }
        false
    }

    fn materialize_summary(&self, record: &SessionRecord, now_ms: i64) -> SessionSummary {
        let mut summary = record.summary.clone();
        if summary.kind == SessionKind::Instrumented && now_ms > summary.last_observed_unix_ms {
            let elapsed_ms = (now_ms - summary.last_observed_unix_ms) as u64;
            summary.metrics.last_heard_age_ms = Some(
                summary
                    .metrics
                    .last_heard_age_ms
                    .unwrap_or(0)
                    .saturating_add(elapsed_ms),
            );
            summary.metrics.remote_state_age_ms = Some(
                summary
                    .metrics
                    .remote_state_age_ms
                    .unwrap_or(0)
                    .saturating_add(elapsed_ms),
            );
        }
        summary.health = classify_health(&summary.kind, &summary.metrics, &self.config.thresholds);
        summary
    }
}

pub fn instrumented_session_id(pid: i32, started_at_unix_ms: i64) -> String {
    format!("instrumented:{started_at_unix_ms}:{pid}")
}

pub fn legacy_session_id(pid: i32, started_at_unix_ms: i64) -> String {
    format!("legacy:{started_at_unix_ms}:{pid}")
}

fn retransmit_pct(history: &VecDeque<CounterSample>, window_ms: i64) -> RetransmitWindow {
    // The metric is only meaningful once the full lookback window exists; until
    // then the caller gets `complete = false` instead of a misleading partial
    // "60s" number derived from a shorter session lifetime.
    let Some(latest) = history.back() else {
        return RetransmitWindow {
            pct: None,
            complete: false,
            breakdown: RetransmitWindowBreakdown::default(),
        };
    };
    let Some(baseline) = history
        .iter()
        .rev()
        .find(|sample| latest.unix_ms - sample.unix_ms >= window_ms)
    else {
        return RetransmitWindow {
            pct: None,
            complete: false,
            breakdown: RetransmitWindowBreakdown::default(),
        };
    };
    let Some(updates_latest) = latest.state_updates_tx_total else {
        return RetransmitWindow {
            pct: None,
            complete: true,
            breakdown: RetransmitWindowBreakdown::default(),
        };
    };
    let Some(updates_baseline) = baseline.state_updates_tx_total else {
        return RetransmitWindow {
            pct: None,
            complete: true,
            breakdown: RetransmitWindowBreakdown::default(),
        };
    };
    let Some(retransmits_latest) = latest.retransmits_total else {
        return RetransmitWindow {
            pct: None,
            complete: true,
            breakdown: RetransmitWindowBreakdown::default(),
        };
    };
    let Some(retransmits_baseline) = baseline.retransmits_total else {
        return RetransmitWindow {
            pct: None,
            complete: true,
            breakdown: RetransmitWindowBreakdown::default(),
        };
    };
    let empty_acks_latest = latest.empty_acks_tx_total.unwrap_or(0);
    let empty_acks_baseline = baseline.empty_acks_tx_total.unwrap_or(0);

    let updates_delta = updates_latest.saturating_sub(updates_baseline);
    let retransmit_delta = retransmits_latest.saturating_sub(retransmits_baseline);
    let empty_ack_delta = empty_acks_latest.saturating_sub(empty_acks_baseline);
    let transmission_delta = updates_delta
        .saturating_add(retransmit_delta)
        .saturating_add(empty_ack_delta);
    let breakdown = RetransmitWindowBreakdown {
        transmissions_total: Some(transmission_delta),
        retransmits_total: Some(retransmit_delta),
        state_updates_total: Some(updates_delta),
        empty_acks_total: Some(empty_ack_delta),
    };
    if transmission_delta == 0 {
        return RetransmitWindow {
            pct: None,
            complete: true,
            breakdown,
        };
    }

    RetransmitWindow {
        pct: Some((retransmit_delta as f64 * 100.0) / transmission_delta as f64),
        complete: true,
        breakdown,
    }
}

fn normalize_event_unix_ms(
    summary: &SessionSummary,
    event_unix_ms: i64,
    received_at_unix_ms: i64,
) -> i64 {
    // Clamp future or regressing timestamps so a corrupted peer cannot make a
    // session look fresher than the daemon actually observed it.
    let event_unix_ms = if event_unix_ms > received_at_unix_ms {
        tracing::warn!(
            session_id = %summary.session_id,
            pid = summary.pid,
            received_at_unix_ms,
            event_unix_ms,
            "clamp future telemetry timestamp to receive time"
        );
        received_at_unix_ms
    } else {
        event_unix_ms
    };
    if event_unix_ms >= summary.last_observed_unix_ms {
        return event_unix_ms;
    }
    tracing::warn!(
        session_id = %summary.session_id,
        pid = summary.pid,
        previous_unix_ms = summary.last_observed_unix_ms,
        event_unix_ms,
        "clamp regressing telemetry timestamp"
    );
    summary.last_observed_unix_ms
}

fn metrics_regressed(metrics: &SessionMetrics, event: &TelemetryEvent) -> bool {
    monotonic_counter_regressed(metrics.packets_tx_total, event.packets_tx_total)
        || monotonic_counter_regressed(metrics.packets_rx_total, event.packets_rx_total)
        || monotonic_counter_regressed(metrics.retransmits_total, event.retransmits_total)
        || monotonic_counter_regressed(metrics.empty_acks_tx_total, event.empty_acks_tx_total)
        || monotonic_counter_regressed(metrics.state_updates_tx_total, event.state_updates_tx_total)
        || monotonic_counter_regressed(metrics.state_updates_rx_total, event.state_updates_rx_total)
        || monotonic_counter_regressed(
            metrics.duplicate_states_rx_total,
            event.duplicate_states_rx_total,
        )
        || monotonic_counter_regressed(
            metrics.out_of_order_states_rx_total,
            event.out_of_order_states_rx_total,
        )
}

fn monotonic_counter_regressed(previous: Option<u64>, next: Option<u64>) -> bool {
    matches!((previous, next), (Some(previous), Some(next)) if next < previous)
}

fn upsert_history_point(history: &mut VecDeque<MetricPoint>, point: MetricPoint) {
    if history
        .back()
        .is_some_and(|existing| existing.unix_ms == point.unix_ms)
    {
        if let Some(last) = history.back_mut() {
            *last = point;
        }
        return;
    }
    history.push_back(point);
}

fn upsert_counter_sample(history: &mut VecDeque<CounterSample>, point: CounterSample) {
    if history
        .back()
        .is_some_and(|existing| existing.unix_ms == point.unix_ms)
    {
        if let Some(last) = history.back_mut() {
            *last = point;
        }
        return;
    }
    history.push_back(point);
}

fn trim_history<T>(history: &mut VecDeque<T>, history_secs: u64)
where
    T: HasUnixMs,
{
    let Some(latest_ms) = history.back().map(HasUnixMs::unix_ms) else {
        return;
    };
    let cutoff_ms = latest_ms - (history_secs as i64 * 1000);
    while history
        .front()
        .is_some_and(|value| value.unix_ms() < cutoff_ms)
    {
        history.pop_front();
    }
}

trait HasUnixMs {
    fn unix_ms(&self) -> i64;
}

impl HasUnixMs for MetricPoint {
    fn unix_ms(&self) -> i64 {
        self.unix_ms
    }
}

impl HasUnixMs for CounterSample {
    fn unix_ms(&self) -> i64 {
        self.unix_ms
    }
}

fn severity(health: &HealthState) -> u8 {
    match health {
        HealthState::Critical => 3,
        HealthState::Degraded => 2,
        HealthState::Legacy => 1,
        HealthState::Ok => 0,
    }
}

fn compare_summaries(left: &SessionSummary, right: &SessionSummary) -> Ordering {
    severity(&right.health)
        .cmp(&severity(&left.health))
        .then_with(|| {
            right
                .metrics
                .srtt_ms
                .partial_cmp(&left.metrics.srtt_ms)
                .unwrap_or(Ordering::Equal)
        })
        .then_with(|| left.session_id.cmp(&right.session_id))
}

fn compare_eviction_priority(left: &SessionRecord, right: &SessionRecord) -> Ordering {
    // Lower classes lose first, then older observations, then older starts, so
    // the daemon preserves the freshest active instrumented sessions longest.
    eviction_class(left)
        .cmp(&eviction_class(right))
        .then_with(|| {
            left.summary
                .last_observed_unix_ms
                .cmp(&right.summary.last_observed_unix_ms)
        })
        .then_with(|| {
            left.summary
                .started_at_unix_ms
                .cmp(&right.summary.started_at_unix_ms)
        })
        .then_with(|| left.summary.session_id.cmp(&right.summary.session_id))
}

fn eviction_class(record: &SessionRecord) -> u8 {
    // Lower numbers are evicted first.
    match (&record.summary.kind, record.shutdown) {
        (SessionKind::Legacy, _) => 0,
        (SessionKind::Instrumented, true) => 1,
        (SessionKind::Instrumented, false) => 2,
    }
}

#[cfg(test)]
mod tests {
    use moshwatch_core::{
        AppConfig, RetransmitWindowBreakdown, SessionKind, TelemetryEvent, TelemetryEventKind,
    };

    use super::{ServiceState, instrumented_session_id};
    use crate::discovery::DiscoveredSession;

    fn telemetry_event(
        unix_ms: i64,
        last_heard_age_ms: u64,
        remote_state_age_ms: u64,
    ) -> TelemetryEvent {
        TelemetryEvent {
            event: TelemetryEventKind::SessionTick,
            display_session_id: Some("session-1".to_string()),
            pid: 4242,
            unix_ms,
            started_at_unix_ms: Some(1),
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.10:60001".to_string()),
            last_heard_age_ms: Some(last_heard_age_ms),
            remote_state_age_ms: Some(remote_state_age_ms),
            srtt_ms: Some(50.0),
            rttvar_ms: Some(10.0),
            last_rtt_ms: Some(40.0),
            packets_tx_total: Some(10),
            packets_rx_total: Some(10),
            retransmits_total: Some(0),
            empty_acks_tx_total: Some(0),
            state_updates_tx_total: Some(10),
            state_updates_rx_total: Some(10),
            duplicate_states_rx_total: Some(0),
            out_of_order_states_rx_total: Some(0),
            cmdline: Some("mosh-server-real new".to_string()),
            shutdown: Some(false),
        }
    }

    #[test]
    fn instrumented_silence_continues_to_age_after_last_telemetry() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry(session_id.clone(), telemetry_event(1_000, 500, 500));

        let summary = state.summaries(21_000).into_iter().next().expect("summary");

        assert_eq!(summary.kind, SessionKind::Instrumented);
        assert_eq!(summary.session_id, session_id);
        assert_eq!(summary.metrics.last_heard_age_ms, Some(20_500));
        assert_eq!(summary.metrics.remote_state_age_ms, Some(20_500));
        assert_eq!(summary.health, moshwatch_core::HealthState::Critical);
    }

    #[test]
    fn discovery_does_not_refresh_instrumented_telemetry_timestamp() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry(session_id.clone(), telemetry_event(1_000, 500, 500));
        state.refresh_discovery(
            vec![DiscoveredSession {
                pid: 4242,
                started_at_unix_ms: 1,
                bind_addr: Some("127.0.0.1".to_string()),
                udp_port: Some(60001),
                cmdline: "mosh-server-real new".to_string(),
            }],
            20_000,
        );

        let detail = state
            .session_detail(&session_id, 20_000)
            .expect("session detail");
        assert_eq!(detail.summary.last_observed_unix_ms, 1_000);
        assert_eq!(detail.summary.metrics.last_heard_age_ms, Some(19_500));
        assert_eq!(detail.summary.metrics.remote_state_age_ms, Some(19_500));
        assert_eq!(detail.summary.health, moshwatch_core::HealthState::Critical);
    }

    #[test]
    fn display_session_id_freezes_after_first_non_empty_value() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry(session_id.clone(), telemetry_event(1_000, 100, 100));

        let mut conflicting = telemetry_event(2_000, 100, 100);
        conflicting.display_session_id = Some("totally-different".to_string());
        state.apply_telemetry(session_id.clone(), conflicting);

        let detail = state
            .session_detail(&session_id, 2_000)
            .expect("session detail");
        assert_eq!(detail.summary.session_id, session_id);
        assert_eq!(
            detail.summary.display_session_id.as_deref(),
            Some("session-1")
        );
    }

    #[test]
    fn closed_instrumented_sessions_are_dropped_after_shutdown_grace() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry(session_id.clone(), telemetry_event(1_000, 100, 100));

        let mut closed = telemetry_event(2_000, 100, 100);
        closed.event = TelemetryEventKind::SessionClose;
        closed.shutdown = Some(true);
        state.apply_telemetry(session_id.clone(), closed);

        state.refresh_discovery(Vec::new(), 6_000);
        assert!(state.session_detail(&session_id, 6_000).is_some());

        state.refresh_discovery(Vec::new(), 13_000);
        assert!(state.session_detail(&session_id, 13_000).is_none());
    }

    #[test]
    fn discovery_does_not_overwrite_instrumented_endpoint_metadata() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry(session_id.clone(), telemetry_event(1_000, 100, 100));

        state.refresh_discovery(
            vec![DiscoveredSession {
                pid: 4242,
                started_at_unix_ms: 1,
                bind_addr: Some("127.0.0.2".to_string()),
                udp_port: Some(60099),
                cmdline: "mosh-server stale".to_string(),
            }],
            2_000,
        );

        let detail = state
            .session_detail(&session_id, 2_000)
            .expect("session detail");
        assert_eq!(detail.summary.bind_addr.as_deref(), Some("127.0.0.1"));
        assert_eq!(detail.summary.udp_port, Some(60001));
        assert_eq!(detail.summary.cmdline, "mosh-server-real new");
    }

    #[test]
    fn legacy_sessions_survive_one_missed_discovery_scan() {
        let mut state = ServiceState::new(AppConfig::default());
        state.refresh_discovery(
            vec![DiscoveredSession {
                pid: 7,
                started_at_unix_ms: 1,
                bind_addr: Some("127.0.0.1".to_string()),
                udp_port: Some(60001),
                cmdline: "mosh-server".to_string(),
            }],
            1_000,
        );

        state.refresh_discovery(Vec::new(), 2_000);
        assert!(
            state
                .session_detail(&super::legacy_session_id(7, 1), 2_000)
                .is_some()
        );

        state.refresh_discovery(Vec::new(), 8_000);
        assert!(
            state
                .session_detail(&super::legacy_session_id(7, 1), 8_000)
                .is_none()
        );
    }

    #[test]
    fn retransmit_windows_stay_empty_until_fully_covered() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        let mut event = telemetry_event(1_000, 100, 100);
        event.state_updates_tx_total = Some(10);
        event.retransmits_total = Some(0);
        event.empty_acks_tx_total = Some(0);
        state.apply_telemetry(session_id.clone(), event);

        let mut event = telemetry_event(9_000, 100, 100);
        event.state_updates_tx_total = Some(20);
        event.retransmits_total = Some(3);
        event.empty_acks_tx_total = Some(4);
        state.apply_telemetry(session_id.clone(), event);

        let detail = state
            .session_detail(&session_id, 9_000)
            .expect("session detail");
        assert_eq!(detail.summary.metrics.retransmit_pct_10s, None);
        assert!(!detail.summary.metrics.retransmit_window_10s_complete);
        assert_eq!(detail.summary.metrics.retransmit_pct_60s, None);
        assert!(!detail.summary.metrics.retransmit_window_60s_complete);
    }

    #[test]
    fn counter_regression_resets_retransmit_windows() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);

        let mut first = telemetry_event(1_000, 100, 100);
        first.state_updates_tx_total = Some(10);
        first.retransmits_total = Some(1);
        first.empty_acks_tx_total = Some(0);
        state.apply_telemetry(session_id.clone(), first);

        let mut second = telemetry_event(12_000, 100, 100);
        second.state_updates_tx_total = Some(20);
        second.retransmits_total = Some(4);
        second.empty_acks_tx_total = Some(5);
        state.apply_telemetry(session_id.clone(), second);

        let mut regressed = telemetry_event(13_000, 100, 100);
        regressed.state_updates_tx_total = Some(1);
        regressed.retransmits_total = Some(0);
        regressed.empty_acks_tx_total = Some(0);
        state.apply_telemetry(session_id.clone(), regressed);

        let detail = state
            .session_detail(&session_id, 13_000)
            .expect("session detail");
        assert_eq!(detail.history.len(), 1);
        assert_eq!(detail.summary.metrics.retransmit_pct_10s, None);
        assert!(!detail.summary.metrics.retransmit_window_10s_complete);
    }

    #[test]
    fn missing_counter_fields_keep_breakdown_unknown() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);

        let mut first = telemetry_event(1_000, 100, 100);
        first.state_updates_tx_total = Some(10);
        first.retransmits_total = None;
        first.empty_acks_tx_total = Some(0);
        state.apply_telemetry(session_id.clone(), first);

        let mut second = telemetry_event(11_000, 100, 100);
        second.state_updates_tx_total = Some(20);
        second.retransmits_total = None;
        second.empty_acks_tx_total = Some(3);
        state.apply_telemetry(session_id.clone(), second);

        let detail = state
            .session_detail(&session_id, 11_000)
            .expect("session detail");
        assert!(detail.summary.metrics.retransmit_window_10s_complete);
        assert_eq!(detail.summary.metrics.retransmit_pct_10s, None);
        assert_eq!(
            detail.summary.metrics.retransmit_window_10s_breakdown,
            RetransmitWindowBreakdown::default()
        );
    }

    #[test]
    fn zero_transmission_window_keeps_retransmit_pct_unknown() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);

        let mut first = telemetry_event(1_000, 100, 100);
        first.state_updates_tx_total = Some(10);
        first.retransmits_total = Some(2);
        first.empty_acks_tx_total = Some(4);
        state.apply_telemetry(session_id.clone(), first);

        let mut second = telemetry_event(11_000, 100, 100);
        second.state_updates_tx_total = Some(10);
        second.retransmits_total = Some(2);
        second.empty_acks_tx_total = Some(4);
        state.apply_telemetry(session_id.clone(), second);

        let detail = state
            .session_detail(&session_id, 11_000)
            .expect("session detail");
        assert!(detail.summary.metrics.retransmit_window_10s_complete);
        assert_eq!(detail.summary.metrics.retransmit_pct_10s, None);
        assert_eq!(
            detail.summary.metrics.retransmit_window_10s_breakdown,
            RetransmitWindowBreakdown {
                transmissions_total: Some(0),
                retransmits_total: Some(0),
                state_updates_total: Some(0),
                empty_acks_total: Some(0),
            }
        );
    }

    #[test]
    fn time_regression_keeps_history_monotonic() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry(session_id.clone(), telemetry_event(10_000, 100, 100));
        state.apply_telemetry(session_id.clone(), telemetry_event(9_000, 100, 100));

        let detail = state
            .session_detail(&session_id, 10_000)
            .expect("session detail");
        assert_eq!(detail.summary.last_observed_unix_ms, 10_000);
        assert_eq!(detail.history.len(), 1);
        assert_eq!(detail.history[0].unix_ms, 10_000);
    }

    #[test]
    fn future_event_is_clamped_to_receive_time() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry_at(session_id.clone(), telemetry_event(1_000, 100, 100), 1_000);
        state.apply_telemetry_at(session_id.clone(), telemetry_event(50_000, 100, 100), 2_000);

        let detail = state
            .session_detail(&session_id, 2_000)
            .expect("session detail");
        assert_eq!(detail.summary.last_observed_unix_ms, 2_000);
        assert_eq!(detail.history.len(), 2);
        assert_eq!(detail.history[0].unix_ms, 1_000);
        assert_eq!(detail.history[1].unix_ms, 2_000);
    }

    #[test]
    fn retransmit_ratio_counts_empty_acks_in_transmission_volume() {
        let mut state = ServiceState::new(AppConfig::default());
        let session_id = instrumented_session_id(4242, 1);

        let mut first = telemetry_event(1_000, 100, 100);
        first.state_updates_tx_total = Some(10);
        first.retransmits_total = Some(0);
        first.empty_acks_tx_total = Some(0);
        state.apply_telemetry(session_id.clone(), first);

        let mut second = telemetry_event(11_000, 100, 100);
        second.state_updates_tx_total = Some(12);
        second.retransmits_total = Some(2);
        second.empty_acks_tx_total = Some(8);
        state.apply_telemetry(session_id.clone(), second);

        let detail = state
            .session_detail(&session_id, 11_000)
            .expect("session detail");
        assert_eq!(
            detail.summary.metrics.retransmit_pct_10s,
            Some(16.666666666666668)
        );
        assert_eq!(
            detail.summary.metrics.retransmit_window_10s_breakdown,
            RetransmitWindowBreakdown {
                transmissions_total: Some(12),
                retransmits_total: Some(2),
                state_updates_total: Some(2),
                empty_acks_total: Some(8),
            }
        );
    }

    #[test]
    fn export_summaries_caps_output_but_preserves_total_counts() {
        let mut state = ServiceState::new(AppConfig::default());
        for idx in 0..3 {
            let mut event = telemetry_event(1_000 + idx as i64, 100, 100);
            event.pid = 4242 + idx;
            event.started_at_unix_ms = Some(1 + idx as i64);
            event.srtt_ms = Some(50.0 + idx as f64);
            let session_id =
                instrumented_session_id(event.pid, event.started_at_unix_ms.expect("start"));
            state.apply_telemetry(session_id, event);
        }

        let export = state.export_summaries(2_000, 2);
        assert_eq!(export.total_sessions, 3);
        assert_eq!(export.truncated_session_count, 1);
        assert_eq!(export.instrumented_sessions, 3);
        assert_eq!(export.legacy_sessions, 0);
        assert_eq!(export.sessions.len(), 2);
        assert!(
            export.sessions[0].metrics.srtt_ms.expect("srtt first")
                >= export.sessions[1].metrics.srtt_ms.expect("srtt second")
        );
    }

    #[test]
    fn session_detail_caps_history_points() {
        let config = AppConfig {
            max_session_detail_points: 2,
            ..AppConfig::default()
        };
        let mut state = ServiceState::new(config);
        let session_id = instrumented_session_id(4242, 1);
        state.apply_telemetry(session_id.clone(), telemetry_event(1_000, 100, 100));
        state.apply_telemetry(session_id.clone(), telemetry_event(2_000, 100, 100));
        state.apply_telemetry(session_id.clone(), telemetry_event(3_000, 100, 100));

        let detail = state
            .session_detail(&session_id, 3_000)
            .expect("session detail");
        assert_eq!(detail.total_history_points, 3);
        assert_eq!(detail.truncated_history_points, 1);
        assert_eq!(detail.history.len(), 2);
        assert_eq!(detail.history[0].unix_ms, 2_000);
        assert_eq!(detail.history[1].unix_ms, 3_000);
    }

    #[test]
    fn session_cap_drops_oldest_legacy_first() {
        let config = AppConfig {
            max_tracked_sessions: 2,
            ..AppConfig::default()
        };
        let mut state = ServiceState::new(config);
        state.refresh_discovery(
            vec![
                DiscoveredSession {
                    pid: 1,
                    started_at_unix_ms: 1,
                    bind_addr: Some("127.0.0.1".to_string()),
                    udp_port: Some(60001),
                    cmdline: "mosh-server".to_string(),
                },
                DiscoveredSession {
                    pid: 2,
                    started_at_unix_ms: 2,
                    bind_addr: Some("127.0.0.1".to_string()),
                    udp_port: Some(60002),
                    cmdline: "mosh-server".to_string(),
                },
                DiscoveredSession {
                    pid: 3,
                    started_at_unix_ms: 3,
                    bind_addr: Some("127.0.0.1".to_string()),
                    udp_port: Some(60003),
                    cmdline: "mosh-server".to_string(),
                },
            ],
            10_000,
        );

        let export = state.export_summaries(10_000, 10);
        assert_eq!(export.total_sessions, 2);
        assert_eq!(export.dropped_sessions_total, 1);
        assert!(
            !export
                .sessions
                .iter()
                .any(|summary| summary.session_id == super::legacy_session_id(1, 1))
        );
    }

    #[test]
    fn session_cap_preserves_established_instrumented_sessions() {
        let config = AppConfig {
            max_tracked_sessions: 2,
            ..AppConfig::default()
        };
        let mut state = ServiceState::new(config);
        let session_one = instrumented_session_id(11, 1);
        let session_two = instrumented_session_id(22, 2);
        let session_three = instrumented_session_id(33, 3);

        state.apply_telemetry(session_one.clone(), telemetry_event(1_000, 11, 11));
        state.apply_telemetry(session_two.clone(), telemetry_event(2_000, 22, 22));
        state.apply_telemetry(session_three.clone(), telemetry_event(3_000, 33, 33));

        let export = state.export_summaries(3_000, 10);
        assert_eq!(export.total_sessions, 2);
        assert_eq!(export.dropped_sessions_total, 1);
        assert!(
            export
                .sessions
                .iter()
                .any(|summary| summary.session_id == session_one)
        );
        assert!(
            export
                .sessions
                .iter()
                .any(|summary| summary.session_id == session_two)
        );
        assert!(
            !export
                .sessions
                .iter()
                .any(|summary| summary.session_id == session_three)
        );
    }
}
