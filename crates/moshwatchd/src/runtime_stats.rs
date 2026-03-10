// SPDX-License-Identifier: GPL-3.0-or-later

//! Lightweight daemon self-observability.
//!
//! These counters deliberately stay small and cheap: the goal is to expose
//! whether `moshwatchd` itself is becoming expensive without introducing a
//! second layer of heavy instrumentation.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

pub const DAEMON_WORKER_THREADS: u64 = 2;

#[derive(Clone, Default)]
pub struct RuntimeStats {
    inner: Arc<RuntimeStatsInner>,
}

#[derive(Default)]
struct RuntimeStatsInner {
    discovery_interval_ms: AtomicU64,
    discovery_last_duration_ms: AtomicU64,
    discovery_overruns_total: AtomicU64,
    history_interval_ms: AtomicU64,
    history_last_duration_ms: AtomicU64,
    history_overruns_total: AtomicU64,
    snapshot_interval_ms: AtomicU64,
    snapshot_last_duration_ms: AtomicU64,
    snapshot_overruns_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeStatsSnapshot {
    pub discovery_interval_ms: u64,
    pub discovery_last_duration_ms: u64,
    pub discovery_overruns_total: u64,
    pub history_interval_ms: u64,
    pub history_last_duration_ms: u64,
    pub history_overruns_total: u64,
    pub snapshot_interval_ms: u64,
    pub snapshot_last_duration_ms: u64,
    pub snapshot_overruns_total: u64,
}

impl RuntimeStats {
    pub fn new(
        discovery_interval_ms: u64,
        history_interval_ms: Option<u64>,
        snapshot_interval_ms: u64,
    ) -> Self {
        let stats = Self::default();
        stats
            .inner
            .discovery_interval_ms
            .store(discovery_interval_ms, Ordering::Relaxed);
        stats
            .inner
            .history_interval_ms
            .store(history_interval_ms.unwrap_or(0), Ordering::Relaxed);
        stats
            .inner
            .snapshot_interval_ms
            .store(snapshot_interval_ms, Ordering::Relaxed);
        stats
    }

    pub fn record_discovery(&self, elapsed: Duration) {
        record_loop(
            &self.inner.discovery_interval_ms,
            &self.inner.discovery_last_duration_ms,
            &self.inner.discovery_overruns_total,
            elapsed,
        );
    }

    pub fn record_history(&self, elapsed: Duration) {
        record_loop(
            &self.inner.history_interval_ms,
            &self.inner.history_last_duration_ms,
            &self.inner.history_overruns_total,
            elapsed,
        );
    }

    pub fn record_snapshot(&self, elapsed: Duration) {
        record_loop(
            &self.inner.snapshot_interval_ms,
            &self.inner.snapshot_last_duration_ms,
            &self.inner.snapshot_overruns_total,
            elapsed,
        );
    }

    pub fn snapshot(&self) -> RuntimeStatsSnapshot {
        RuntimeStatsSnapshot {
            discovery_interval_ms: self.inner.discovery_interval_ms.load(Ordering::Relaxed),
            discovery_last_duration_ms: self
                .inner
                .discovery_last_duration_ms
                .load(Ordering::Relaxed),
            discovery_overruns_total: self.inner.discovery_overruns_total.load(Ordering::Relaxed),
            history_interval_ms: self.inner.history_interval_ms.load(Ordering::Relaxed),
            history_last_duration_ms: self.inner.history_last_duration_ms.load(Ordering::Relaxed),
            history_overruns_total: self.inner.history_overruns_total.load(Ordering::Relaxed),
            snapshot_interval_ms: self.inner.snapshot_interval_ms.load(Ordering::Relaxed),
            snapshot_last_duration_ms: self.inner.snapshot_last_duration_ms.load(Ordering::Relaxed),
            snapshot_overruns_total: self.inner.snapshot_overruns_total.load(Ordering::Relaxed),
        }
    }
}

fn record_loop(
    interval_ms: &AtomicU64,
    last_duration_ms: &AtomicU64,
    overruns_total: &AtomicU64,
    elapsed: Duration,
) {
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    last_duration_ms.store(elapsed_ms, Ordering::Relaxed);
    let interval_ms = interval_ms.load(Ordering::Relaxed);
    if interval_ms > 0 && elapsed_ms > interval_ms {
        overruns_total.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeStats, RuntimeStatsSnapshot};
    use std::time::Duration;

    #[test]
    fn records_loop_durations_and_overruns() {
        let stats = RuntimeStats::new(5_000, Some(10_000), 1_000);
        stats.record_discovery(Duration::from_millis(5_500));
        stats.record_history(Duration::from_millis(500));
        stats.record_snapshot(Duration::from_millis(1_500));

        let snapshot = stats.snapshot();
        assert_eq!(
            snapshot,
            RuntimeStatsSnapshot {
                discovery_interval_ms: 5_000,
                discovery_last_duration_ms: 5_500,
                discovery_overruns_total: 1,
                history_interval_ms: 10_000,
                history_last_duration_ms: 500,
                history_overruns_total: 0,
                snapshot_interval_ms: 1_000,
                snapshot_last_duration_ms: 1_500,
                snapshot_overruns_total: 1,
            }
        );
    }

    #[test]
    fn disabled_history_interval_does_not_overrun() {
        let stats = RuntimeStats::new(5_000, None, 1_000);
        stats.record_history(Duration::from_secs(60));
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.history_interval_ms, 0);
        assert_eq!(snapshot.history_last_duration_ms, 60_000);
        assert_eq!(snapshot.history_overruns_total, 0);
    }
}
