// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared configuration and runtime-path helpers.
//!
//! This module is used by both the daemon and installer-facing code, so it
//! carries a few security invariants:
//! - runtime and state directories must remain owner-controlled
//! - metrics auth tokens must stay regular files with `0600` permissions
//! - config and token rewrites must not rely on predictable temporary paths

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use http::header::{ACCEPT, CONTENT_TYPE, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::MetricsDetailTier;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthThresholds {
    /// Warning threshold for smoothed RTT in milliseconds.
    pub warn_rtt_ms: u64,
    /// Critical threshold for smoothed RTT in milliseconds.
    pub critical_rtt_ms: u64,
    /// Warning threshold for retransmit percentage over bounded windows.
    #[serde(alias = "warn_loss_pct")]
    pub warn_retransmit_pct: f64,
    /// Critical threshold for retransmit percentage over bounded windows.
    #[serde(alias = "critical_loss_pct")]
    pub critical_retransmit_pct: f64,
    /// Warning threshold for silence since last heard traffic, in milliseconds.
    pub warn_silence_ms: u64,
    /// Critical threshold for silence since last heard traffic, in milliseconds.
    pub critical_silence_ms: u64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            warn_rtt_ms: 400,
            critical_rtt_ms: 1000,
            warn_retransmit_pct: 2.0,
            critical_retransmit_pct: 10.0,
            warn_silence_ms: 5_000,
            critical_silence_ms: 15_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventStreamConfig {
    /// Heartbeat cadence for the NDJSON snapshot stream.
    pub heartbeat_ms: u64,
}

impl Default for EventStreamConfig {
    fn default() -> Self {
        Self {
            heartbeat_ms: 15_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistenceConfig {
    /// Whether periodic history persistence is enabled.
    pub enabled: bool,
    /// Sampling interval for persisted history snapshots.
    pub sample_interval_ms: u64,
    /// Maximum day-bucket retention window for persisted history.
    pub retention_days: u64,
    /// Hard cap for samples returned by one history query.
    pub max_query_samples: usize,
    /// Total disk budget for persisted history files.
    pub max_disk_bytes: u64,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_interval_ms: 5_000,
            retention_days: 14,
            max_query_samples: 4_096,
            max_disk_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusMetricsConfig {
    /// Optional TCP listen address for Prometheus/OpenMetrics scraping.
    /// Use an empty TOML string to disable the listener entirely.
    #[serde(default, deserialize_with = "deserialize_optional_listen_addr")]
    pub listen_addr: Option<String>,
    /// Explicit opt-in for non-loopback metrics exposure.
    pub allow_non_loopback: bool,
    /// Controls whether per-session series are emitted or the export stays aggregate-only.
    pub detail_tier: MetricsDetailTier,
}

impl Default for PrometheusMetricsConfig {
    fn default() -> Self {
        Self {
            listen_addr: Some("127.0.0.1:9947".to_string()),
            allow_non_loopback: false,
            detail_tier: MetricsDetailTier::PerSession,
        }
    }
}

fn deserialize_optional_listen_addr<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let listen_addr = Option::<String>::deserialize(deserializer)?;
    Ok(listen_addr.and_then(|listen_addr| {
        if listen_addr.trim().is_empty() {
            None
        } else {
            Some(listen_addr)
        }
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtlpMetricsConfig {
    /// Whether OTLP metrics export is enabled.
    pub enabled: bool,
    /// OTLP/HTTP metrics endpoint.
    pub endpoint: String,
    /// OTLP export interval in milliseconds.
    pub export_interval_ms: u64,
    /// OTLP export request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Controls whether OTLP emits only aggregate metrics or per-session detail.
    pub detail_tier: MetricsDetailTier,
    /// Additional HTTP headers to attach to OTLP export requests.
    pub headers: BTreeMap<String, String>,
    /// Additional OTLP resource attributes for this daemon instance.
    pub resource_attributes: BTreeMap<String, String>,
}

impl Default for OtlpMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
            export_interval_ms: 15_000,
            timeout_ms: 5_000,
            detail_tier: MetricsDetailTier::AggregateOnly,
            headers: BTreeMap::new(),
            resource_attributes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Prometheus/OpenMetrics scraping configuration.
    pub prometheus: PrometheusMetricsConfig,
    /// OTLP metrics export configuration.
    pub otlp: OtlpMetricsConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct MetricsConfigCompat {
    prometheus: Option<PrometheusMetricsConfig>,
    otlp: Option<OtlpMetricsConfig>,
    listen_addr: Option<String>,
    allow_non_loopback: Option<bool>,
    detail_tier: Option<MetricsDetailTier>,
}

impl<'de> Deserialize<'de> for MetricsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let compat = MetricsConfigCompat::deserialize(deserializer)?;
        let mut prometheus = compat.prometheus.unwrap_or_default();
        if let Some(listen_addr) = compat.listen_addr {
            prometheus.listen_addr = if listen_addr.trim().is_empty() {
                None
            } else {
                Some(listen_addr)
            };
        }
        if let Some(allow_non_loopback) = compat.allow_non_loopback {
            prometheus.allow_non_loopback = allow_non_loopback;
        }
        if let Some(detail_tier) = compat.detail_tier {
            prometheus.detail_tier = detail_tier;
        }
        Ok(Self {
            prometheus,
            otlp: compat.otlp.unwrap_or_default(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// UI/API snapshot refresh cadence in milliseconds.
    pub refresh_ms: u64,
    /// `/proc` discovery cadence in milliseconds.
    pub discovery_interval_ms: u64,
    /// Cleanup cadence for stale sessions in milliseconds.
    pub cleanup_interval_ms: u64,
    /// In-memory history retention window used for detail exports.
    pub history_secs: u64,
    /// Maximum concurrently tracked sessions before eviction/rejection applies.
    pub max_tracked_sessions: usize,
    /// Maximum history points exported in a single session-detail response.
    pub max_session_detail_points: usize,
    /// Thresholds used for derived health classification.
    pub thresholds: HealthThresholds,
    /// Event-stream heartbeat configuration.
    pub stream: EventStreamConfig,
    /// Persistent history recording configuration.
    pub persistence: PersistenceConfig,
    /// TCP metrics exposure configuration.
    pub metrics: MetricsConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            refresh_ms: 1_000,
            discovery_interval_ms: 5_000,
            cleanup_interval_ms: 10_000,
            history_secs: 15 * 60,
            max_tracked_sessions: 2_048,
            max_session_detail_points: 15 * 60,
            thresholds: HealthThresholds::default(),
            stream: EventStreamConfig::default(),
            persistence: PersistenceConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

impl AppConfig {
    /// Validate operator-provided configuration before it reaches runtime loops.
    ///
    /// The upper bounds here are intentional. They protect against obviously
    /// invalid input and also keep a local observability tool from becoming an
    /// accidental self-DoS through extreme config values.
    pub fn validate(&self) -> Result<()> {
        const MIN_REFRESH_MS: u64 = 100;
        const MIN_DISCOVERY_INTERVAL_MS: u64 = 500;
        const MIN_CLEANUP_INTERVAL_MS: u64 = 1_000;
        const MAX_HISTORY_SECS: u64 = 24 * 60 * 60;
        const MIN_SAMPLE_INTERVAL_MS: u64 = 1_000;
        const MAX_RETENTION_DAYS: u64 = 366;
        const MAX_QUERY_SAMPLES: usize = 20_000;
        const MAX_TRACKED_SESSIONS: usize = 10_000;
        const MAX_SESSION_DETAIL_POINTS: usize = 20_000;
        const MAX_HISTORY_DISK_BYTES: u64 = 64 * 1024 * 1024 * 1024;

        if self.refresh_ms == 0 {
            anyhow::bail!("refresh_ms must be greater than zero");
        }
        if self.refresh_ms < MIN_REFRESH_MS {
            anyhow::bail!("refresh_ms must be at least {MIN_REFRESH_MS}");
        }
        if self.discovery_interval_ms == 0 {
            anyhow::bail!("discovery_interval_ms must be greater than zero");
        }
        if self.discovery_interval_ms < MIN_DISCOVERY_INTERVAL_MS {
            anyhow::bail!("discovery_interval_ms must be at least {MIN_DISCOVERY_INTERVAL_MS}");
        }
        if self.cleanup_interval_ms == 0 {
            anyhow::bail!("cleanup_interval_ms must be greater than zero");
        }
        if self.cleanup_interval_ms < MIN_CLEANUP_INTERVAL_MS {
            anyhow::bail!("cleanup_interval_ms must be at least {MIN_CLEANUP_INTERVAL_MS}");
        }
        if self.history_secs == 0 {
            anyhow::bail!("history_secs must be greater than zero");
        }
        if self.history_secs > MAX_HISTORY_SECS {
            anyhow::bail!("history_secs must be less than or equal to {MAX_HISTORY_SECS}");
        }
        if self.max_tracked_sessions == 0 {
            anyhow::bail!("max_tracked_sessions must be greater than zero");
        }
        if self.max_tracked_sessions > MAX_TRACKED_SESSIONS {
            anyhow::bail!(
                "max_tracked_sessions must be less than or equal to {MAX_TRACKED_SESSIONS}"
            );
        }
        if self.max_session_detail_points == 0 {
            anyhow::bail!("max_session_detail_points must be greater than zero");
        }
        if self.max_session_detail_points > MAX_SESSION_DETAIL_POINTS {
            anyhow::bail!(
                "max_session_detail_points must be less than or equal to {MAX_SESSION_DETAIL_POINTS}"
            );
        }
        if self.stream.heartbeat_ms == 0 {
            anyhow::bail!("stream.heartbeat_ms must be greater than zero");
        }
        if self.persistence.sample_interval_ms == 0 {
            anyhow::bail!("persistence.sample_interval_ms must be greater than zero");
        }
        if self.persistence.sample_interval_ms < MIN_SAMPLE_INTERVAL_MS {
            anyhow::bail!(
                "persistence.sample_interval_ms must be at least {MIN_SAMPLE_INTERVAL_MS}"
            );
        }
        if self.persistence.retention_days == 0 {
            anyhow::bail!("persistence.retention_days must be greater than zero");
        }
        if self.persistence.retention_days > MAX_RETENTION_DAYS {
            anyhow::bail!(
                "persistence.retention_days must be less than or equal to {MAX_RETENTION_DAYS}"
            );
        }
        if self.persistence.max_query_samples == 0 {
            anyhow::bail!("persistence.max_query_samples must be greater than zero");
        }
        if self.persistence.max_query_samples > MAX_QUERY_SAMPLES {
            anyhow::bail!(
                "persistence.max_query_samples must be less than or equal to {MAX_QUERY_SAMPLES}"
            );
        }
        if self.persistence.max_disk_bytes == 0 {
            anyhow::bail!("persistence.max_disk_bytes must be greater than zero");
        }
        if self.persistence.max_disk_bytes > MAX_HISTORY_DISK_BYTES {
            anyhow::bail!(
                "persistence.max_disk_bytes must be less than or equal to {MAX_HISTORY_DISK_BYTES}"
            );
        }
        if self.thresholds.warn_rtt_ms > self.thresholds.critical_rtt_ms {
            anyhow::bail!("warn_rtt_ms must be less than or equal to critical_rtt_ms");
        }
        if !self.thresholds.warn_retransmit_pct.is_finite()
            || self.thresholds.warn_retransmit_pct < 0.0
        {
            anyhow::bail!("warn_retransmit_pct must be a finite non-negative number");
        }
        if !self.thresholds.critical_retransmit_pct.is_finite()
            || self.thresholds.critical_retransmit_pct < 0.0
        {
            anyhow::bail!("critical_retransmit_pct must be a finite non-negative number");
        }
        if self.thresholds.warn_retransmit_pct > self.thresholds.critical_retransmit_pct {
            anyhow::bail!(
                "warn_retransmit_pct must be less than or equal to critical_retransmit_pct"
            );
        }
        if self.thresholds.warn_silence_ms > self.thresholds.critical_silence_ms {
            anyhow::bail!("warn_silence_ms must be less than or equal to critical_silence_ms");
        }
        if let Some(listen_addr) = &self.metrics.prometheus.listen_addr
            && listen_addr.trim().is_empty()
        {
            anyhow::bail!("metrics.prometheus.listen_addr cannot be empty when provided");
        }
        if self.metrics.otlp.enabled {
            if self.metrics.otlp.endpoint.trim().is_empty() {
                anyhow::bail!("metrics.otlp.endpoint cannot be empty when OTLP export is enabled");
            }
            if self.metrics.otlp.export_interval_ms == 0 {
                anyhow::bail!("metrics.otlp.export_interval_ms must be greater than zero");
            }
            if self.metrics.otlp.timeout_ms == 0 {
                anyhow::bail!("metrics.otlp.timeout_ms must be greater than zero");
            }
        }
        for (name, value) in &self.metrics.otlp.headers {
            validate_otlp_header(name, value)?;
        }
        for name in self.metrics.otlp.resource_attributes.keys() {
            if name.trim().is_empty() {
                anyhow::bail!("metrics.otlp.resource_attributes cannot contain an empty key");
            }
            if is_reserved_otlp_resource_attribute_key(name) {
                anyhow::bail!(
                    "metrics.otlp.resource_attributes cannot override reserved OTLP key {name}"
                );
            }
        }
        if self.cleanup_interval_ms < self.discovery_interval_ms {
            anyhow::bail!(
                "cleanup_interval_ms must be greater than or equal to discovery_interval_ms"
            );
        }
        Ok(())
    }
}

fn validate_otlp_header(name: &str, value: &str) -> Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("metrics.otlp.headers cannot contain an empty header name");
    }
    let header_name = HeaderName::try_from(name).with_context(|| {
        format!("metrics.otlp.headers contains invalid HTTP header name {name:?}")
    })?;
    if header_name == ACCEPT || header_name == CONTENT_TYPE {
        anyhow::bail!("metrics.otlp.headers cannot override reserved OTLP header {name:?}");
    }
    HeaderValue::from_str(value).with_context(|| {
        format!("metrics.otlp.headers contains invalid HTTP header value for {name:?}")
    })?;
    Ok(())
}

const OTLP_RESOURCE_ATTRIBUTE_RESERVED_KEYS: &[&str] = &[
    "service.name",
    "service.version",
    "service.instance.id",
    "moshwatch.observer.node_name",
    "moshwatch.observer.system_id",
];

pub fn is_reserved_otlp_resource_attribute_key(key: &str) -> bool {
    OTLP_RESOURCE_ATTRIBUTE_RESERVED_KEYS
        .iter()
        .any(|reserved| key.eq_ignore_ascii_case(reserved))
}

#[derive(Debug, Clone)]
pub struct RuntimePaths {
    /// Owner-controlled runtime directory for sockets and transient state.
    pub runtime_dir: PathBuf,
    /// Owner-controlled persistent state directory.
    pub state_dir: PathBuf,
    /// Directory containing day-bucketed history files.
    pub history_dir: PathBuf,
    /// Bearer token file for TCP metrics authentication.
    pub metrics_token_path: PathBuf,
    /// Unix socket used by the instrumented server to send telemetry.
    pub telemetry_socket: PathBuf,
    /// Unix socket used by the local HTTP API and UI.
    pub api_socket: PathBuf,
    /// Operator configuration file path.
    pub config_path: PathBuf,
}

impl RuntimePaths {
    /// Resolve the filesystem layout from XDG paths first, then conservative
    /// per-user fallbacks that still match the wrapper and service behavior.
    pub fn discover() -> Self {
        let config_root = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".config"))
            })
            .or_else(|| ProjectDirs::from("", "", "moshwatch").map(|dirs| dirs.config_dir().into()))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let runtime_root = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .or_else(default_runtime_root)
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".local/state/moshwatch/runtime"))
            })
            .unwrap_or_else(|| PathBuf::from("/tmp/moshwatch-runtime"));
        let state_root = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".local/state"))
            })
            .or_else(|| {
                ProjectDirs::from("", "", "moshwatch").map(|dirs| dirs.data_local_dir().into())
            })
            .unwrap_or_else(|| PathBuf::from("/tmp"));

        let runtime_dir = if runtime_root.ends_with("runtime") {
            runtime_root
        } else {
            runtime_root.join("moshwatch")
        };
        let state_dir = if state_root.ends_with("moshwatch") {
            state_root
        } else {
            state_root.join("moshwatch")
        };
        let history_dir = state_dir.join("history");
        let metrics_token_path = state_dir.join("metrics.token");

        Self {
            telemetry_socket: runtime_dir.join("telemetry.sock"),
            api_socket: runtime_dir.join("api.sock"),
            runtime_dir,
            state_dir,
            history_dir,
            metrics_token_path,
            config_path: config_root.join("moshwatch").join("moshwatch.toml"),
        }
    }

    pub fn ensure_runtime_dir(&self) -> Result<()> {
        create_secure_dir(&self.runtime_dir)
            .with_context(|| format!("create runtime dir {}", self.runtime_dir.display()))
    }

    /// Ensure the persistent state and history directories exist with
    /// owner-controlled permissions.
    pub fn ensure_state_dir(&self) -> Result<()> {
        create_secure_dir(&self.state_dir)
            .with_context(|| format!("create state dir {}", self.state_dir.display()))?;
        create_secure_dir(&self.history_dir)
            .with_context(|| format!("create history dir {}", self.history_dir.display()))
    }

    pub fn load_config(&self) -> Result<AppConfig> {
        if !path_exists(&self.config_path)? {
            return Ok(AppConfig::default());
        }

        let raw = read_text_file_securely(&self.config_path, 1024 * 1024)
            .with_context(|| format!("read config {}", self.config_path.display()))?;
        let parsed = toml::from_str::<AppConfig>(&raw)
            .with_context(|| format!("parse config {}", self.config_path.display()))?;
        parsed
            .validate()
            .with_context(|| format!("validate config {}", self.config_path.display()))?;
        Ok(parsed)
    }

    /// Ensure the parent directory for the config file exists securely.
    pub fn ensure_config_parent(&self) -> Result<()> {
        if let Some(parent) = self.config_path.parent() {
            create_secure_dir(parent)
                .with_context(|| format!("create config dir {}", parent.display()))?;
        }
        Ok(())
    }

    /// Write a default config file only when one does not already exist.
    pub fn maybe_write_default_config(&self) -> Result<()> {
        self.ensure_config_parent()?;
        if path_exists(&self.config_path)? {
            return Ok(());
        }

        let default_config =
            toml::to_string_pretty(&AppConfig::default()).context("serialize default config")?;
        write_new_text_file_securely(&self.config_path, default_config.as_bytes())
            .with_context(|| format!("write default config {}", self.config_path.display()))
    }

    /// Load the bearer token used for TCP `/metrics` scraping.
    ///
    /// Existing tokens are normalized back to owner-only regular files. Invalid
    /// or corrupted contents are treated as recoverable local state and rotated
    /// in place rather than leaving the daemon permanently wedged.
    pub fn load_or_create_metrics_auth_token(&self) -> Result<String> {
        self.ensure_state_dir()?;
        if path_exists(&self.metrics_token_path)? {
            normalize_owner_only_regular_file(&self.metrics_token_path).with_context(|| {
                format!(
                    "normalize metrics token {}",
                    self.metrics_token_path.display()
                )
            })?;
            let token =
                read_text_file_securely(&self.metrics_token_path, 256).with_context(|| {
                    format!("read metrics token {}", self.metrics_token_path.display())
                })?;
            match validate_metrics_auth_token(token.trim()) {
                Ok(token) => return Ok(token),
                Err(error) => {
                    warn!(
                        path = %self.metrics_token_path.display(),
                        error = %error,
                        "rotating invalid metrics auth token"
                    );
                    return replace_text_file_securely(
                        &self.metrics_token_path,
                        generate_metrics_auth_token,
                    )
                    .with_context(|| {
                        format!(
                            "replace metrics token {}",
                            self.metrics_token_path.display()
                        )
                    });
                }
            }
        }

        create_metrics_auth_token_file(&self.metrics_token_path)
    }

    /// Reconcile the on-disk metrics token back to the daemon's active token.
    ///
    /// This is used by the background drift-repair loop so operators and local
    /// scrapers do not silently diverge if the token file is deleted, replaced,
    /// or permission-drifted after startup.
    pub fn ensure_metrics_auth_token_file_matches(&self, expected_token: &str) -> Result<bool> {
        self.ensure_state_dir()?;
        let expected_token = validate_metrics_auth_token(expected_token)?;
        if path_exists(&self.metrics_token_path)? {
            normalize_owner_only_regular_file(&self.metrics_token_path).with_context(|| {
                format!(
                    "normalize metrics token {}",
                    self.metrics_token_path.display()
                )
            })?;
            let on_disk =
                read_text_file_securely(&self.metrics_token_path, 256).with_context(|| {
                    format!("read metrics token {}", self.metrics_token_path.display())
                })?;
            if let Ok(current) = validate_metrics_auth_token(on_disk.trim())
                && current == expected_token
            {
                return Ok(false);
            }
            warn!(
                path = %self.metrics_token_path.display(),
                "restoring metrics auth token file to match the active daemon token"
            );
            write_text_file_securely_replace(
                &self.metrics_token_path,
                expected_token.as_bytes(),
                "rewrite metrics token",
            )?;
            return Ok(true);
        }

        warn!(
            path = %self.metrics_token_path.display(),
            "recreating missing metrics auth token file from the active daemon token"
        );
        write_new_text_file_securely(&self.metrics_token_path, expected_token.as_bytes())
            .with_context(|| {
                format!("write metrics token {}", self.metrics_token_path.display())
            })?;
        Ok(true)
    }
}

fn validate_metrics_auth_token(token: &str) -> Result<String> {
    if token.len() != 64 {
        anyhow::bail!("metrics auth token must be exactly 64 hex characters");
    }
    if !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("metrics auth token must contain only hex characters");
    }
    Ok(token.to_ascii_lowercase())
}

fn generate_metrics_auth_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    fill_random_bytes(&mut bytes)?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(token, "{byte:02x}");
    }
    Ok(token)
}

#[cfg(unix)]
fn fill_random_bytes(buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let read = unsafe {
            libc::getrandom(
                buffer[filled..].as_mut_ptr() as *mut libc::c_void,
                buffer.len() - filled,
                0,
            )
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("read random bytes");
        }
        filled += read as usize;
    }
    Ok(())
}

#[cfg(not(unix))]
fn fill_random_bytes(_buffer: &mut [u8]) -> Result<()> {
    anyhow::bail!("metrics auth token generation requires unix support")
}

fn create_secure_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        anyhow::bail!("refusing to use symlinked directory {}", current.display());
                    }
                    if !metadata.is_dir() {
                        anyhow::bail!("refusing to use non-directory path {}", current.display());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .with_context(|| format!("create directory {}", current.display()))?;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("stat directory {}", current.display()));
                }
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", path.display()))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
        Ok(())
    }
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("stat path {}", path.display())),
    }
}

#[cfg(unix)]
fn open_text_file_for_read(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("refusing to read non-file path {}", path.display());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_text_file_for_read(path: &Path) -> Result<fs::File> {
    fs::File::open(path).with_context(|| format!("open {}", path.display()))
}

fn read_text_file_securely(path: &Path, max_bytes: usize) -> Result<String> {
    let file = open_text_file_for_read(path)?;
    let mut buffer = Vec::with_capacity(1024);
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut buffer)
        .with_context(|| format!("read {}", path.display()))?;
    if buffer.len() > max_bytes {
        anyhow::bail!("refusing to read oversized file {}", path.display());
    }
    String::from_utf8(buffer).with_context(|| format!("decode {}", path.display()))
}

#[cfg(unix)]
fn write_new_text_file_securely(path: &Path, contents: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush {}", path.display()))?;
    let mut permissions = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .with_context(|| format!("chmod 600 {}", path.display()))
}

#[cfg(not(unix))]
fn write_new_text_file_securely(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("write {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush {}", path.display()))
}

fn create_metrics_auth_token_file(path: &Path) -> Result<String> {
    let token = generate_metrics_auth_token()?;
    write_new_text_file_securely(path, token.as_bytes())
        .with_context(|| format!("write metrics token {}", path.display()))?;
    validate_metrics_auth_token(&token)
}

#[cfg(unix)]
fn normalize_owner_only_regular_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symlinked file {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("refusing to use non-file path {}", path.display());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", path.display()))
}

#[cfg(not(unix))]
fn normalize_owner_only_regular_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn replace_text_file_securely<F>(path: &Path, generate_contents: F) -> Result<String>
where
    F: FnOnce() -> Result<String>,
{
    #[cfg(unix)]
    {
        let metadata =
            fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("refusing to replace symlinked file {}", path.display());
        }
        if !metadata.is_file() {
            anyhow::bail!("refusing to replace non-file path {}", path.display());
        }
    }

    let contents = generate_contents()?;
    let validated = validate_metrics_auth_token(&contents)?;
    write_text_file_securely_replace(path, contents.as_bytes(), "rewrite")?;
    Ok(validated)
}

fn write_text_file_securely_replace(path: &Path, contents: &[u8], operation: &str) -> Result<()> {
    let temporary = unique_temporary_path_in_same_dir(path)?;
    let result = (|| {
        write_new_text_file_securely(&temporary, contents)
            .with_context(|| format!("{operation} {}", temporary.display()))?;
        fs::rename(&temporary, path)
            .with_context(|| format!("{operation} {} to {}", temporary.display(), path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn unique_temporary_path_in_same_dir(path: &Path) -> Result<PathBuf> {
    const MAX_ATTEMPTS: usize = 32;

    let parent = path
        .parent()
        .context("determine temporary file parent directory")?;
    let file_name = path
        .file_name()
        .context("determine temporary file name")?
        .to_string_lossy();

    // Keep replacement files in the destination directory so `rename(2)` stays
    // atomic, but do not reuse legacy predictable `*.tmp` names that a
    // same-user process could pre-stage as a symlink or collision.
    for _ in 0..MAX_ATTEMPTS {
        let mut random = [0u8; 6];
        fill_random_bytes(&mut random)?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = parent.join(format!(".{file_name}.{suffix}.tmp"));
        if !path_exists(&candidate)? {
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "failed to allocate unique temporary path alongside {}",
        path.display()
    );
}

fn default_runtime_root() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let candidate = PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

pub fn remove_socket_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;

                if !metadata.file_type().is_socket() {
                    anyhow::bail!("refusing to remove non-socket path {}", path.display());
                }
            }
            fs::remove_file(path).with_context(|| format!("remove socket file {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("stat socket path {}", path.display())),
    }
}

pub fn set_socket_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("stat socket path {}", path.display()))?;
        if !metadata.file_type().is_socket() {
            anyhow::bail!("refusing to chmod non-socket path {}", path.display());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{
            fs::{PermissionsExt, symlink},
            net::UnixListener,
        },
    };

    use super::{
        AppConfig, PersistenceConfig, RuntimePaths, remove_socket_if_present, set_socket_owner_only,
    };
    use crate::MetricsDetailTier;

    #[test]
    fn partial_config_uses_defaults() {
        let parsed: AppConfig =
            toml::from_str("refresh_ms = 2000").expect("parse partial config with defaults");
        assert_eq!(parsed.refresh_ms, 2000);
        assert_eq!(
            parsed.discovery_interval_ms,
            AppConfig::default().discovery_interval_ms
        );
        assert_eq!(parsed.thresholds.warn_rtt_ms, 400);
        assert_eq!(parsed.persistence.retention_days, 14);
        assert_eq!(
            parsed.persistence.max_disk_bytes,
            PersistenceConfig::default().max_disk_bytes
        );
        assert_eq!(
            parsed.max_tracked_sessions,
            AppConfig::default().max_tracked_sessions
        );
        assert_eq!(
            parsed.max_session_detail_points,
            AppConfig::default().max_session_detail_points
        );
        assert!(!parsed.metrics.prometheus.allow_non_loopback);
        assert_eq!(
            parsed.metrics.prometheus.listen_addr.as_deref(),
            Some("127.0.0.1:9947")
        );
        assert_eq!(
            parsed.metrics.prometheus.detail_tier,
            MetricsDetailTier::PerSession
        );
        assert!(!parsed.metrics.otlp.enabled);
        assert_eq!(
            parsed.metrics.otlp.detail_tier,
            MetricsDetailTier::AggregateOnly
        );
    }

    #[test]
    fn nested_metrics_config_overrides_defaults() {
        let parsed: AppConfig = toml::from_str(
            r#"
[metrics.prometheus]
listen_addr = "127.0.0.1:1234"
allow_non_loopback = true
detail_tier = "aggregate_only"

[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/metrics"
export_interval_ms = 30000
timeout_ms = 10000
detail_tier = "per_session"

[metrics.otlp.headers]
authorization = "Bearer test"

[metrics.otlp.resource_attributes]
deployment_environment = "lab"
"#,
        )
        .expect("parse nested metrics config");
        assert_eq!(
            parsed.metrics.prometheus.listen_addr.as_deref(),
            Some("127.0.0.1:1234")
        );
        assert!(parsed.metrics.prometheus.allow_non_loopback);
        assert_eq!(
            parsed.metrics.prometheus.detail_tier,
            MetricsDetailTier::AggregateOnly
        );
        assert!(parsed.metrics.otlp.enabled);
        assert_eq!(parsed.metrics.otlp.export_interval_ms, 30_000);
        assert_eq!(parsed.metrics.otlp.timeout_ms, 10_000);
        assert_eq!(
            parsed.metrics.otlp.detail_tier,
            MetricsDetailTier::PerSession
        );
        assert_eq!(
            parsed
                .metrics
                .otlp
                .headers
                .get("authorization")
                .map(String::as_str),
            Some("Bearer test")
        );
        assert_eq!(
            parsed
                .metrics
                .otlp
                .resource_attributes
                .get("deployment_environment")
                .map(String::as_str),
            Some("lab")
        );
    }

    #[test]
    fn legacy_metrics_config_still_parses() {
        let parsed: AppConfig = toml::from_str(
            r#"
[metrics]
listen_addr = "127.0.0.1:2233"
allow_non_loopback = true
detail_tier = "aggregate_only"
"#,
        )
        .expect("parse legacy metrics config");
        assert_eq!(
            parsed.metrics.prometheus.listen_addr.as_deref(),
            Some("127.0.0.1:2233")
        );
        assert!(parsed.metrics.prometheus.allow_non_loopback);
        assert_eq!(
            parsed.metrics.prometheus.detail_tier,
            MetricsDetailTier::AggregateOnly
        );
    }

    #[test]
    fn metrics_prometheus_listen_addr_can_be_disabled_in_toml() {
        let parsed: AppConfig = toml::from_str(
            r#"
[metrics.prometheus]
listen_addr = ""
"#,
        )
        .expect("parse config with disabled metrics listener");

        assert_eq!(parsed.metrics.prometheus.listen_addr, None);
        parsed
            .validate()
            .expect("disabled metrics listener should validate");
    }

    #[test]
    fn otlp_headers_reject_invalid_http_syntax() {
        let parsed: AppConfig = toml::from_str(
            r#"
[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/metrics"

[metrics.otlp.headers]
"X Foo" = "bar"
"#,
        )
        .expect("parse config with invalid OTLP header syntax");

        let error = parsed
            .validate()
            .expect_err("reject invalid OTLP header syntax");
        assert!(error.to_string().contains("invalid HTTP header name"));
    }

    #[test]
    fn otlp_headers_reject_reserved_protobuf_headers() {
        let parsed: AppConfig = toml::from_str(
            r#"
[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/metrics"

[metrics.otlp.headers]
accept = "text/plain"
"#,
        )
        .expect("parse config with reserved OTLP header");

        let error = parsed
            .validate()
            .expect_err("reject reserved OTLP header override");
        assert!(
            error
                .to_string()
                .contains("cannot override reserved OTLP header")
        );
    }

    #[test]
    fn remove_socket_rejects_regular_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("not-a-socket");
        fs::write(&path, "x").expect("write temp file");
        let error = remove_socket_if_present(&path).expect_err("reject regular file");
        assert!(error.to_string().contains("refusing to remove non-socket"));
    }

    #[test]
    fn remove_socket_accepts_unix_socket() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("test.sock");
        let _listener = UnixListener::bind(&path).expect("bind unix socket");
        remove_socket_if_present(&path).expect("remove unix socket");
        assert!(!path.exists());
    }

    #[test]
    fn socket_permissions_are_owner_only() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("test.sock");
        let _listener = UnixListener::bind(&path).expect("bind unix socket");

        set_socket_owner_only(&path).expect("chmod unix socket");

        let mode = fs::metadata(&path)
            .expect("stat socket")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn runtime_paths_match_wrapper_convention() {
        let paths = RuntimePaths::discover();
        let display = paths.telemetry_socket.display().to_string();
        assert!(display.ends_with("telemetry.sock"));
        assert!(
            paths
                .history_dir
                .display()
                .to_string()
                .ends_with("/history")
        );
        assert!(
            paths
                .metrics_token_path
                .display()
                .to_string()
                .ends_with("/metrics.token")
        );
    }

    #[test]
    fn config_validation_rejects_dangerous_extremes() {
        let config = AppConfig {
            refresh_ms: 50,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());

        let config = AppConfig {
            persistence: super::PersistenceConfig {
                max_query_samples: 50_000,
                ..super::PersistenceConfig::default()
            },
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());

        let config = AppConfig {
            persistence: super::PersistenceConfig {
                max_disk_bytes: 0,
                ..super::PersistenceConfig::default()
            },
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());

        let config = AppConfig {
            max_tracked_sessions: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_reserved_otlp_resource_attributes() {
        for reserved_key in [
            "service.name",
            "service.version",
            "service.instance.id",
            "moshwatch.observer.node_name",
            "moshwatch.observer.system_id",
        ] {
            let config: AppConfig = toml::from_str(&format!(
                r#"
[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/metrics"

[metrics.otlp.resource_attributes]
"{reserved_key}" = "value"
"#
            ))
            .expect("parse config with reserved OTLP resource key");

            let err = config
                .validate()
                .expect_err("reserved OTLP resource key should be rejected");
            assert!(
                err.to_string().contains(reserved_key),
                "error should mention reserved key {reserved_key}: {err}"
            );
        }
    }

    #[test]
    fn metrics_auth_token_is_stable_and_secure() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: tempdir.path().join("state"),
            history_dir: tempdir.path().join("state/history"),
            metrics_token_path: tempdir.path().join("state/metrics.token"),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path: tempdir.path().join("config/moshwatch.toml"),
        };

        let token_one = paths
            .load_or_create_metrics_auth_token()
            .expect("create metrics token");
        let token_two = paths
            .load_or_create_metrics_auth_token()
            .expect("reload metrics token");

        assert_eq!(token_one, token_two);
        assert_eq!(token_one.len(), 64);
        assert!(token_one.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let mode = fs::metadata(&paths.metrics_token_path)
            .expect("stat metrics token")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn metrics_auth_token_rotates_invalid_regular_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let state_dir = tempdir.path().join("state");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let original = "not-a-token";
        let token_path = state_dir.join("metrics.token");
        fs::write(&token_path, original).expect("write invalid token");

        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: state_dir.clone(),
            history_dir: state_dir.join("history"),
            metrics_token_path: token_path.clone(),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path: tempdir.path().join("config/moshwatch.toml"),
        };

        let token = paths
            .load_or_create_metrics_auth_token()
            .expect("rotate invalid token");

        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let on_disk = fs::read_to_string(&token_path).expect("read rotated token");
        assert_eq!(on_disk, token);
        assert_ne!(on_disk, original);
    }

    #[test]
    fn metrics_auth_token_load_normalizes_file_mode() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let state_dir = tempdir.path().join("state");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let token_path = state_dir.join("metrics.token");
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(&token_path, token).expect("write token");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644))
            .expect("set relaxed mode");

        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: state_dir.clone(),
            history_dir: state_dir.join("history"),
            metrics_token_path: token_path.clone(),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path: tempdir.path().join("config/moshwatch.toml"),
        };

        let loaded = paths
            .load_or_create_metrics_auth_token()
            .expect("load valid token");

        assert_eq!(loaded, token);
        let mode = fs::metadata(&token_path)
            .expect("stat normalized token")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn metrics_auth_token_reconcile_restores_missing_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let state_dir = tempdir.path().join("state");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let token_path = state_dir.join("metrics.token");
        let expected_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: state_dir.clone(),
            history_dir: state_dir.join("history"),
            metrics_token_path: token_path.clone(),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path: tempdir.path().join("config/moshwatch.toml"),
        };

        let repaired = paths
            .ensure_metrics_auth_token_file_matches(expected_token)
            .expect("restore missing token file");

        assert!(repaired);
        assert_eq!(
            fs::read_to_string(&token_path).expect("read restored token"),
            expected_token
        );
    }

    #[test]
    fn metrics_auth_token_reconcile_restores_drifted_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let state_dir = tempdir.path().join("state");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let token_path = state_dir.join("metrics.token");
        let expected_token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let stale_token = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        fs::write(&token_path, stale_token).expect("write stale token");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644))
            .expect("set stale mode");

        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: state_dir.clone(),
            history_dir: state_dir.join("history"),
            metrics_token_path: token_path.clone(),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path: tempdir.path().join("config/moshwatch.toml"),
        };

        let repaired = paths
            .ensure_metrics_auth_token_file_matches(expected_token)
            .expect("repair drifted token file");

        assert!(repaired);
        assert_eq!(
            fs::read_to_string(&token_path).expect("read repaired token"),
            expected_token
        );
        let mode = fs::metadata(&token_path)
            .expect("stat repaired token")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn metrics_auth_token_reconcile_ignores_staged_legacy_tmp_symlink() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let state_dir = tempdir.path().join("state");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let token_path = state_dir.join("metrics.token");
        let victim = tempdir.path().join("victim.txt");
        fs::write(&victim, "keep").expect("write victim");
        fs::write(
            &token_path,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .expect("write stale token");
        symlink(&victim, token_path.with_extension("tmp")).expect("create staged tmp symlink");

        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: state_dir.clone(),
            history_dir: state_dir.join("history"),
            metrics_token_path: token_path.clone(),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path: tempdir.path().join("config/moshwatch.toml"),
        };

        paths
            .ensure_metrics_auth_token_file_matches(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            )
            .expect("repair token without following staged tmp symlink");

        assert_eq!(fs::read_to_string(&victim).expect("read victim"), "keep");
        assert_eq!(
            fs::read_to_string(&token_path).expect("read repaired token"),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
    }

    #[test]
    fn ensure_runtime_dir_rejects_symlink_path() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let real_dir = tempdir.path().join("real");
        fs::create_dir_all(&real_dir).expect("create real dir");
        let link_dir = tempdir.path().join("runtime-link");
        symlink(&real_dir, &link_dir).expect("create runtime symlink");

        let paths = RuntimePaths {
            runtime_dir: link_dir.join("nested"),
            state_dir: tempdir.path().join("state"),
            history_dir: tempdir.path().join("state/history"),
            metrics_token_path: tempdir.path().join("state/metrics.token"),
            telemetry_socket: tempdir.path().join("runtime-link/nested/telemetry.sock"),
            api_socket: tempdir.path().join("runtime-link/nested/api.sock"),
            config_path: tempdir.path().join("config/moshwatch.toml"),
        };
        let error = paths
            .ensure_runtime_dir()
            .expect_err("reject symlink runtime dir");
        assert!(format!("{error:#}").contains("symlinked directory"));
    }

    #[test]
    fn load_config_rejects_symlink_target() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let outside = tempdir.path().join("outside.toml");
        fs::write(&outside, "refresh_ms = 2000").expect("write config target");
        let config_root = tempdir.path().join("config");
        fs::create_dir_all(&config_root).expect("create config root");
        let config_path = config_root.join("moshwatch.toml");
        symlink(&outside, &config_path).expect("create config symlink");

        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: tempdir.path().join("state"),
            history_dir: tempdir.path().join("state/history"),
            metrics_token_path: tempdir.path().join("state/metrics.token"),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path,
        };
        let error = paths.load_config().expect_err("reject symlink config");
        assert!(format!("{error:#}").contains("open"));
    }

    #[test]
    fn load_config_rejects_oversized_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config_path = tempdir.path().join("moshwatch.toml");
        fs::write(&config_path, "x".repeat(1024 * 1024 + 1)).expect("write oversized config");

        let paths = RuntimePaths {
            runtime_dir: tempdir.path().join("runtime"),
            state_dir: tempdir.path().join("state"),
            history_dir: tempdir.path().join("state/history"),
            metrics_token_path: tempdir.path().join("state/metrics.token"),
            telemetry_socket: tempdir.path().join("runtime/telemetry.sock"),
            api_socket: tempdir.path().join("runtime/api.sock"),
            config_path,
        };
        let error = paths.load_config().expect_err("reject oversized config");
        assert!(format!("{error:#}").contains("oversized file"));
    }
}
