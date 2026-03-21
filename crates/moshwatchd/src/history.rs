// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded persistent history for instrumented sessions.
//!
//! History is stored as newline-delimited JSON by day bucket. The design is
//! intentionally conservative:
//! - only instrumented sessions are persisted
//! - missing per-sample observer metadata stays missing instead of being
//!   silently relabelled with the current host on read
//! - files are opened with regular-file and no-follow checks
//! - reads are bounded per line so malformed input cannot force large
//!   allocations
//! - writes respect both retention and a hard disk budget

use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result};
use moshwatch_core::{HistorySample, ObserverInfo, SessionKind, SessionSummary};

use crate::sanitize::sanitize_history_sample;

const DAY_MS: i64 = 86_400_000;
const MAX_HISTORY_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct HistoryStatsSnapshot {
    pub current_bytes: u64,
    pub written_bytes_total: u64,
    pub write_failures_total: u64,
    pub prune_failures_total: u64,
    pub dropped_samples_total: u64,
}

#[derive(Debug)]
pub struct HistoryStore {
    observer: ObserverInfo,
    dir: PathBuf,
    retention_days: u64,
    max_query_samples: usize,
    max_disk_bytes: u64,
    current_bytes: AtomicU64,
    written_bytes_total: AtomicU64,
    write_failures_total: AtomicU64,
    prune_failures_total: AtomicU64,
    dropped_samples_total: AtomicU64,
}

impl HistoryStore {
    pub fn new(
        observer: ObserverInfo,
        dir: PathBuf,
        retention_days: u64,
        max_query_samples: usize,
        max_disk_bytes: u64,
    ) -> Self {
        let current_bytes = match history_dir_bytes(&dir) {
            Ok(current_bytes) => current_bytes,
            Err(error) => {
                tracing::warn!(
                    path = %dir.display(),
                    "failed to initialize history byte count: {error:#}"
                );
                0
            }
        };
        Self {
            observer,
            dir,
            retention_days,
            max_query_samples,
            max_disk_bytes,
            current_bytes: AtomicU64::new(current_bytes),
            written_bytes_total: AtomicU64::new(0),
            write_failures_total: AtomicU64::new(0),
            prune_failures_total: AtomicU64::new(0),
            dropped_samples_total: AtomicU64::new(0),
        }
    }

    pub fn stats_snapshot(&self) -> HistoryStatsSnapshot {
        HistoryStatsSnapshot {
            current_bytes: self.current_bytes.load(Ordering::Relaxed),
            written_bytes_total: self.written_bytes_total.load(Ordering::Relaxed),
            write_failures_total: self.write_failures_total.load(Ordering::Relaxed),
            prune_failures_total: self.prune_failures_total.load(Ordering::Relaxed),
            dropped_samples_total: self.dropped_samples_total.load(Ordering::Relaxed),
        }
    }

    pub fn record_summaries(
        &self,
        recorded_at_unix_ms: i64,
        sessions: &[SessionSummary],
    ) -> Result<()> {
        // Persist only instrumented sessions. Legacy discovery is useful for
        // live operator visibility but would just add low-value noise to the
        // long-term recorder.
        let instrumented = sessions
            .iter()
            .filter(|summary| summary.kind == SessionKind::Instrumented)
            .collect::<Vec<_>>();

        if instrumented.is_empty() {
            if let Err(error) = self.prune_old_files(recorded_at_unix_ms) {
                self.write_failures_total.fetch_add(1, Ordering::Relaxed);
                let _ = self.refresh_current_bytes_from_disk();
                return Err(error);
            }
            return Ok(());
        }

        if let Err(error) = fs::create_dir_all(&self.dir)
            .with_context(|| format!("create history dir {}", self.dir.display()))
        {
            self.write_failures_total.fetch_add(1, Ordering::Relaxed);
            let _ = self.refresh_current_bytes_from_disk();
            return Err(error);
        }
        if let Err(error) = self.prune_old_files(recorded_at_unix_ms) {
            self.write_failures_total.fetch_add(1, Ordering::Relaxed);
            let _ = self.refresh_current_bytes_from_disk();
            return Err(error);
        }
        let payload =
            match encode_history_payload(&self.observer, recorded_at_unix_ms, &instrumented) {
                Ok(payload) => payload,
                Err(error) => {
                    self.write_failures_total.fetch_add(1, Ordering::Relaxed);
                    return Err(error);
                }
            };
        let projected_total_bytes =
            match self.ensure_disk_budget(recorded_at_unix_ms, payload.len() as u64) {
                Ok(Some(projected_total_bytes)) => projected_total_bytes,
                Ok(None) => {
                    self.record_dropped_samples(instrumented.len());
                    return Ok(());
                }
                Err(error) => {
                    self.write_failures_total.fetch_add(1, Ordering::Relaxed);
                    let _ = self.refresh_current_bytes_from_disk();
                    return Err(error);
                }
            };

        let path = self.file_path_for(recorded_at_unix_ms);
        let write_result = (|| -> Result<()> {
            let mut file = open_history_file_for_append(&path)?;
            file.write_all(&payload).context("write history payload")?;
            file.flush().context("flush history file")
        })();

        match write_result {
            Ok(()) => {
                self.current_bytes
                    .store(projected_total_bytes, Ordering::Relaxed);
                self.written_bytes_total
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                self.write_failures_total.fetch_add(1, Ordering::Relaxed);
                let _ = self.refresh_current_bytes_from_disk();
                Err(error)
            }
        }
    }

    pub fn query_session(
        &self,
        session_id: &str,
        since_unix_ms: i64,
        limit: usize,
    ) -> Result<Vec<HistorySample>> {
        // Query newest-first so small bounded lookups stop early once they have
        // enough recent data, even if the retention window spans many files.
        let limit = limit.min(self.max_query_samples);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut samples = VecDeque::with_capacity(limit.min(256));
        for path in self.history_files_from(since_unix_ms)?.into_iter().rev() {
            let file = open_history_file_for_read(&path)?;
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            let mut line_number = 0usize;
            let mut file_matches = Vec::new();
            loop {
                match read_bounded_line(&mut reader, &mut line, MAX_HISTORY_LINE_BYTES)
                    .with_context(|| format!("read line from {}", path.display()))?
                {
                    ReadLineOutcome::Eof => break,
                    ReadLineOutcome::Oversized { bytes } => {
                        line_number += 1;
                        tracing::warn!(
                            path = %path.display(),
                            line_number,
                            bytes,
                            "skip oversized history sample"
                        );
                        continue;
                    }
                    ReadLineOutcome::Line => {}
                }
                line_number += 1;
                while line
                    .last()
                    .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
                {
                    line.pop();
                }
                if line.is_empty() {
                    continue;
                }
                let sample: HistorySample = match serde_json::from_slice(&line) {
                    Ok(sample) => sample,
                    Err(error) => {
                        tracing::warn!(
                            path = %path.display(),
                            line_number,
                            "skip malformed history sample: {error}"
                        );
                        continue;
                    }
                };
                let sample = match sanitize_history_sample(sample) {
                    Some(sample) => sample,
                    None => {
                        tracing::warn!(
                            path = %path.display(),
                            line_number,
                            "skip invalid history sample after sanitation"
                        );
                        continue;
                    }
                };
                if sample.session_id != session_id || sample.recorded_at_unix_ms < since_unix_ms {
                    continue;
                }
                if limit == 0 {
                    continue;
                }
                file_matches.push(sample);
            }
            for sample in file_matches.into_iter().rev() {
                samples.push_back(sample);
                if samples.len() > limit {
                    samples.pop_back();
                }
            }
            if samples.len() >= limit {
                break;
            }
        }
        let mut samples = samples.into_iter().collect::<Vec<_>>();
        samples.reverse();
        Ok(samples)
    }

    pub fn retention_window_secs(&self) -> i64 {
        (self.retention_days.saturating_mul(86_400)).min(i64::MAX as u64) as i64
    }

    fn record_dropped_samples(&self, count: usize) {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        self.dropped_samples_total
            .fetch_add(count, Ordering::Relaxed);
    }

    fn refresh_current_bytes_from_disk(&self) -> Result<u64> {
        let bytes = history_dir_bytes(&self.dir)?;
        self.current_bytes.store(bytes, Ordering::Relaxed);
        Ok(bytes)
    }

    fn history_files_from(&self, since_unix_ms: i64) -> Result<Vec<PathBuf>> {
        let min_day = day_bucket(since_unix_ms);
        let mut files: Vec<(i64, PathBuf)> = Vec::new();
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read history dir {}", self.dir.display()));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let Some(day) = file_day_bucket(&path) else {
                continue;
            };
            if !path_is_regular_file(&path) {
                continue;
            }
            if day >= min_day {
                files.push((day, path));
            }
        }
        files.sort_by(|(left_day, left_path), (right_day, right_path)| {
            left_day
                .cmp(right_day)
                .then_with(|| left_path.cmp(right_path))
        });
        Ok(files.into_iter().map(|(_, path)| path).collect())
    }

    fn prune_old_files(&self, recorded_at_unix_ms: i64) -> Result<()> {
        // Day buckets are kept inclusively: with `retention_days = N`, retain
        // the current day plus the previous `N - 1` buckets.
        let oldest_day = day_bucket(recorded_at_unix_ms) - self.retention_days as i64 + 1;
        let mut removed_bytes = 0u64;
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read history dir {}", self.dir.display()));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let Some(day) = file_day_bucket(&path) else {
                continue;
            };
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !metadata.file_type().is_file() {
                continue;
            }
            if day < oldest_day
                && let Err(error) = fs::remove_file(&path)
            {
                self.prune_failures_total.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    path = %path.display(),
                    "failed to prune expired history file: {error}"
                );
            } else if day < oldest_day {
                removed_bytes = removed_bytes.saturating_add(metadata.len());
            }
        }
        if removed_bytes > 0 {
            self.current_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(removed_bytes))
                })
                .ok();
        }
        Ok(())
    }

    fn ensure_disk_budget(
        &self,
        recorded_at_unix_ms: i64,
        incoming_bytes: u64,
    ) -> Result<Option<u64>> {
        // Evict older day buckets first, but never delete the current day's
        // file just to squeeze in one more append. This means disk budget can
        // prune more aggressively than retention, while preserving "today" as
        // the current operator-facing record of activity.
        if incoming_bytes == 0 {
            return Ok(Some(self.current_bytes.load(Ordering::Relaxed)));
        }
        if incoming_bytes > self.max_disk_bytes {
            tracing::warn!(
                incoming_bytes,
                max_disk_bytes = self.max_disk_bytes,
                "drop history payload because it exceeds the configured disk budget"
            );
            return Ok(None);
        }

        let current_day = day_bucket(recorded_at_unix_ms);
        let mut files = self.history_files_with_sizes()?;
        let mut total_bytes = files.iter().map(|file| file.size).sum::<u64>();
        self.current_bytes.store(total_bytes, Ordering::Relaxed);
        if total_bytes.saturating_add(incoming_bytes) <= self.max_disk_bytes {
            return Ok(Some(total_bytes.saturating_add(incoming_bytes)));
        }

        files.sort_by(|left, right| {
            left.day
                .cmp(&right.day)
                .then_with(|| left.path.cmp(&right.path))
        });
        for file in files {
            if file.day >= current_day {
                continue;
            }
            if total_bytes.saturating_add(incoming_bytes) <= self.max_disk_bytes {
                return Ok(Some(total_bytes.saturating_add(incoming_bytes)));
            }
            if let Err(error) = fs::remove_file(&file.path) {
                self.prune_failures_total.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    path = %file.path.display(),
                    "failed to prune history file while enforcing disk budget: {error}"
                );
                self.current_bytes.store(total_bytes, Ordering::Relaxed);
                return Ok(None);
            }
            total_bytes = total_bytes.saturating_sub(file.size);
        }
        self.current_bytes.store(total_bytes, Ordering::Relaxed);

        if total_bytes.saturating_add(incoming_bytes) > self.max_disk_bytes {
            tracing::warn!(
                total_bytes,
                incoming_bytes,
                max_disk_bytes = self.max_disk_bytes,
                "drop history payload because the disk budget is exhausted"
            );
            return Ok(None);
        }
        Ok(Some(total_bytes.saturating_add(incoming_bytes)))
    }

    fn file_path_for(&self, recorded_at_unix_ms: i64) -> PathBuf {
        self.dir
            .join(format!("day-{}.jsonl", day_bucket(recorded_at_unix_ms)))
    }

    fn history_files_with_sizes(&self) -> Result<Vec<HistoryFile>> {
        history_files_with_sizes_in_dir(&self.dir)
    }
}

fn history_dir_bytes(dir: &Path) -> Result<u64> {
    Ok(history_files_with_sizes_in_dir(dir)?
        .into_iter()
        .map(|file| file.size)
        .sum())
}

fn history_files_with_sizes_in_dir(dir: &Path) -> Result<Vec<HistoryFile>> {
    let mut files = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("read history dir {}", dir.display()));
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        let Some(day) = file_day_bucket(&path) else {
            continue;
        };
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        files.push(HistoryFile {
            day,
            path,
            size: metadata.len(),
        });
    }
    Ok(files)
}

#[derive(Debug, Clone)]
struct HistoryFile {
    day: i64,
    path: PathBuf,
    size: u64,
}

fn encode_history_payload(
    observer: &ObserverInfo,
    recorded_at_unix_ms: i64,
    sessions: &[&SessionSummary],
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(sessions.len().saturating_mul(256));
    for summary in sessions {
        let sample = HistorySample {
            observer: Some(observer.clone()),
            recorded_at_unix_ms,
            session_id: summary.session_id.clone(),
            display_session_id: summary.display_session_id.clone(),
            pid: summary.pid,
            kind: summary.kind.clone(),
            health: summary.health.clone(),
            started_at_unix_ms: summary.started_at_unix_ms,
            counter_reset_unix_ms: summary.counter_reset_unix_ms,
            bind_addr: summary.bind_addr.clone(),
            udp_port: summary.udp_port,
            client_addr: summary.peer.last_client_addr.clone(),
            current_client_addr: summary.peer.current_client_addr.clone(),
            metrics: summary.metrics.clone(),
        };
        serde_json::to_writer(&mut payload, &sample).context("encode history sample")?;
        payload.push(b'\n');
    }
    Ok(payload)
}

fn day_bucket(unix_ms: i64) -> i64 {
    unix_ms.div_euclid(DAY_MS)
}

fn file_day_bucket(path: &Path) -> Option<i64> {
    let name = path.file_name()?.to_str()?;
    let day = name.strip_prefix("day-")?.strip_suffix(".jsonl")?;
    day.parse().ok()
}

fn path_is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn open_history_file_for_append(path: &Path) -> Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("open history file {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("stat history file {}", path.display()))?;
        if !metadata.file_type().is_file() {
            anyhow::bail!("history path {} is not a regular file", path.display());
        }
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .with_context(|| format!("chmod 600 {}", path.display()))?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open history file {}", path.display()))
    }
}

fn open_history_file_for_read(path: &Path) -> Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("open history file {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("stat history file {}", path.display()))?;
        if !metadata.file_type().is_file() {
            anyhow::bail!("history path {} is not a regular file", path.display());
        }
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        fs::File::open(path).with_context(|| format!("open history file {}", path.display()))
    }
}

#[derive(Debug, PartialEq)]
enum ReadLineOutcome {
    Eof,
    Line,
    Oversized { bytes: usize },
}

fn read_bounded_line<R>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<ReadLineOutcome>
where
    R: BufRead,
{
    // Consume the full physical line even when it is oversized so one bad
    // entry cannot desynchronize the rest of the file scan.
    line.clear();
    loop {
        let chunk = reader.fill_buf().context("fill buffered line")?;
        if chunk.is_empty() {
            return if line.is_empty() {
                Ok(ReadLineOutcome::Eof)
            } else {
                Ok(ReadLineOutcome::Line)
            };
        }
        if let Some(newline_idx) = chunk.iter().position(|byte| *byte == b'\n') {
            let take = newline_idx + 1;
            let total = line.len().saturating_add(take);
            if total > max_bytes {
                reader.consume(take);
                line.clear();
                return Ok(ReadLineOutcome::Oversized { bytes: total });
            }
            line.extend_from_slice(&chunk[..take]);
            reader.consume(take);
            return Ok(ReadLineOutcome::Line);
        }
        if line.len().saturating_add(chunk.len()) > max_bytes {
            let bytes = drain_line_remainder(reader, line.len())?;
            line.clear();
            return Ok(ReadLineOutcome::Oversized { bytes });
        }
        line.extend_from_slice(chunk);
        let consumed = chunk.len();
        reader.consume(consumed);
    }
}

fn drain_line_remainder<R>(reader: &mut R, mut bytes: usize) -> Result<usize>
where
    R: BufRead,
{
    loop {
        let chunk = reader.fill_buf().context("fill buffered line")?;
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        fs::OpenOptions,
        io::{Cursor, Write},
    };

    use moshwatch_core::{
        HealthState, HistorySample, ObserverInfo, SessionKind, SessionMetrics, SessionPeerInfo,
        SessionSummary,
    };

    use super::{HistoryStore, MAX_HISTORY_LINE_BYTES, ReadLineOutcome, read_bounded_line};

    fn observer() -> ObserverInfo {
        ObserverInfo {
            node_name: "node-1".to_string(),
            system_id: "system-1".to_string(),
        }
    }

    fn summary(session_id: &str, recorded_at_unix_ms: i64) -> SessionSummary {
        SessionSummary {
            session_id: session_id.to_string(),
            display_session_id: Some("display".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: recorded_at_unix_ms - 1_000,
            last_observed_unix_ms: recorded_at_unix_ms,
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001".to_string()),
            peer: SessionPeerInfo {
                current_client_addr: Some("192.0.2.1:60001".to_string()),
                last_client_addr: Some("192.0.2.1:60001".to_string()),
                ..SessionPeerInfo::default()
            },
            cmdline: "mosh-server-real".to_string(),
            metrics: SessionMetrics::default(),
            counter_reset_unix_ms: None,
        }
    }

    #[test]
    fn records_and_queries_recent_samples() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            128,
            1024 * 1024,
        );
        store
            .record_summaries(86_400_000, &[summary("session-1", 86_400_000)])
            .expect("record day one");
        store
            .record_summaries(86_405_000, &[summary("session-1", 86_405_000)])
            .expect("record day one later");

        let samples = store
            .query_session("session-1", 86_400_000, 16)
            .expect("query samples");
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].session_id, "session-1");
        assert_eq!(
            samples[0].observer.as_ref().expect("observer").node_name,
            "node-1"
        );
    }

    #[test]
    fn prunes_files_outside_retention_window() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            2,
            128,
            1024 * 1024,
        );
        store
            .record_summaries(0, &[summary("session-1", 0)])
            .expect("record old day");
        store
            .record_summaries(3 * 86_400_000, &[summary("session-1", 3 * 86_400_000)])
            .expect("record new day");

        let old_file = tempdir.path().join("history/day-0.jsonl");
        assert!(!old_file.exists());
    }

    #[test]
    fn skips_legacy_summaries_when_recording() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            128,
            1024 * 1024,
        );
        let mut legacy = summary("legacy:1", 1_000);
        legacy.kind = SessionKind::Legacy;

        store
            .record_summaries(1_000, &[legacy])
            .expect("record summaries");

        let samples = store
            .query_session("legacy:1", 0, 16)
            .expect("query samples");
        assert!(samples.is_empty());
    }

    #[test]
    fn query_skips_malformed_lines_and_keeps_latest_limit() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            2,
            1024 * 1024,
        );
        store
            .record_summaries(86_400_000, &[summary("session-1", 86_400_000)])
            .expect("record first sample");

        let path = tempdir.path().join("history/day-1.jsonl");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open history file");
        file.write_all(b"{not-json}\n")
            .expect("write malformed line");
        file.flush().expect("flush malformed line");

        store
            .record_summaries(86_405_000, &[summary("session-1", 86_405_000)])
            .expect("record second sample");
        store
            .record_summaries(86_410_000, &[summary("session-1", 86_410_000)])
            .expect("record third sample");

        let samples = store
            .query_session("session-1", 86_400_000, 64)
            .expect("query samples");
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].recorded_at_unix_ms, 86_405_000);
        assert_eq!(samples[1].recorded_at_unix_ms, 86_410_000);
    }

    #[cfg(unix)]
    #[test]
    fn record_rejects_symlink_history_target() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let history_dir = tempdir.path().join("history");
        fs::create_dir_all(&history_dir).expect("create history dir");
        let outside = tempdir.path().join("outside.jsonl");
        fs::write(&outside, "seed").expect("write outside file");
        symlink(&outside, history_dir.join("day-1.jsonl")).expect("create symlink");

        let store = HistoryStore::new(observer(), history_dir, 7, 128, 1024 * 1024);
        let error = store
            .record_summaries(86_400_000, &[summary("session-1", 86_400_000)])
            .expect_err("reject symlink history file");
        assert!(error.to_string().contains("open history file"));
        assert_eq!(store.stats_snapshot().write_failures_total, 1);
    }

    #[test]
    fn bounded_line_reader_rejects_oversized_lines() {
        let oversized = vec![b'x'; MAX_HISTORY_LINE_BYTES + 8];
        let mut payload = oversized;
        payload.push(b'\n');
        let mut reader = Cursor::new(payload);
        let mut line = Vec::new();

        let outcome = read_bounded_line(&mut reader, &mut line, MAX_HISTORY_LINE_BYTES)
            .expect("read oversized line");
        assert!(matches!(outcome, ReadLineOutcome::Oversized { .. }));
        assert!(line.is_empty());
    }

    #[test]
    fn query_orders_latest_samples_across_double_digit_day_buckets() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            30,
            2,
            1024 * 1024,
        );
        store
            .record_summaries(9 * 86_400_000, &[summary("session-1", 9 * 86_400_000)])
            .expect("record day nine");
        store
            .record_summaries(10 * 86_400_000, &[summary("session-1", 10 * 86_400_000)])
            .expect("record day ten");
        store
            .record_summaries(11 * 86_400_000, &[summary("session-1", 11 * 86_400_000)])
            .expect("record day eleven");

        let samples = store
            .query_session("session-1", 0, 2)
            .expect("query latest samples");
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].recorded_at_unix_ms, 10 * 86_400_000);
        assert_eq!(samples[1].recorded_at_unix_ms, 11 * 86_400_000);
    }

    #[test]
    fn record_preserves_last_known_client_addr_and_current_peer_state() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            128,
            1024 * 1024,
        );
        let disconnected = SessionSummary {
            client_addr: None,
            peer: SessionPeerInfo {
                current_client_addr: None,
                last_client_addr: Some("192.0.2.1:60001".to_string()),
                ..SessionPeerInfo::default()
            },
            ..summary("session-1", 86_400_000)
        };

        store
            .record_summaries(86_400_000, &[disconnected])
            .expect("record disconnected sample");

        let samples = store
            .query_session("session-1", 0, 16)
            .expect("query samples");
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].client_addr.as_deref(), Some("192.0.2.1:60001"));
        assert_eq!(samples[0].current_client_addr, None);
    }

    #[test]
    fn record_preserves_counter_reset_marker() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(
            observer(),
            tempdir.path().join("history"),
            7,
            128,
            1024 * 1024,
        );
        let mut summary = summary("session-1", 86_400_000);
        summary.counter_reset_unix_ms = Some(86_399_500);

        store
            .record_summaries(86_400_000, &[summary])
            .expect("record sample");

        let samples = store
            .query_session("session-1", 0, 16)
            .expect("query samples");
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].counter_reset_unix_ms, Some(86_399_500));
    }

    #[test]
    fn drops_samples_when_payload_exceeds_disk_budget() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = HistoryStore::new(observer(), tempdir.path().join("history"), 7, 128, 1);

        store
            .record_summaries(86_400_000, &[summary("session-1", 86_400_000)])
            .expect("drop oversized payload without error");

        let samples = store
            .query_session("session-1", 0, 16)
            .expect("query samples");
        assert!(samples.is_empty());

        let stats = store.stats_snapshot();
        assert_eq!(stats.current_bytes, 0);
        assert_eq!(stats.dropped_samples_total, 1);
        assert_eq!(stats.written_bytes_total, 0);
    }

    #[test]
    fn query_preserves_unknown_observer_for_legacy_history_lines() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let history_dir = tempdir.path().join("history");
        fs::create_dir_all(&history_dir).expect("create history dir");
        let mut encoded = serde_json::to_vec(&HistorySample {
            observer: None,
            recorded_at_unix_ms: 86_400_000,
            session_id: "session-1".to_string(),
            display_session_id: Some("display".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: 86_399_000,
            counter_reset_unix_ms: None,
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001".to_string()),
            current_client_addr: Some("192.0.2.1:60001".to_string()),
            metrics: SessionMetrics::default(),
        })
        .expect("encode legacy history sample");
        encoded.push(b'\n');
        fs::write(history_dir.join("day-1.jsonl"), encoded).expect("write legacy history line");

        let store = HistoryStore::new(observer(), history_dir, 7, 128, 1024 * 1024);
        let samples = store
            .query_session("session-1", 0, 16)
            .expect("query samples");
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].observer, None);
    }

    #[test]
    fn query_skips_history_samples_with_invalid_session_identity() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let history_dir = tempdir.path().join("history");
        fs::create_dir_all(&history_dir).expect("create history dir");
        let mut encoded = serde_json::to_vec(&HistorySample {
            observer: Some(observer()),
            recorded_at_unix_ms: 86_400_000,
            session_id: "instrumented:\n1:42".to_string(),
            display_session_id: Some("display".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: 86_399_000,
            counter_reset_unix_ms: None,
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001".to_string()),
            current_client_addr: None,
            metrics: SessionMetrics::default(),
        })
        .expect("encode invalid history sample");
        encoded.push(b'\n');
        fs::write(history_dir.join("day-1.jsonl"), encoded).expect("write invalid history line");

        let store = HistoryStore::new(observer(), history_dir, 7, 128, 1024 * 1024);
        let samples = store
            .query_session("instrumented:1:42", 0, 16)
            .expect("query samples");
        assert!(samples.is_empty());
    }
}
