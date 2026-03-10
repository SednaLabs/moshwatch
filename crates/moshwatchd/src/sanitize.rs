// SPDX-License-Identifier: GPL-3.0-or-later

//! Sanitizers for operator-facing text and persisted history samples.
//!
//! ## Rationale
//! Keep display surfaces and on-disk history resilient against malformed or
//! hostile text without silently turning obviously invalid records into
//! trustworthy-looking data.
//!
//! ## Security Boundaries
//! * Sanitization is a stability and presentation guard, not an authentication
//!   boundary.
//! * Some values are normalized for display, while others are rejected
//!   entirely when exact identity matters.
//! * Persisted history is treated as untrusted input on read.

use moshwatch_core::{HistorySample, ObserverInfo, SessionKind};

const ELLIPSIS: &str = "...";

pub fn sanitize_display_session_id(value: Option<String>) -> Option<String> {
    sanitize_optional_text(value, 128)
}

pub fn sanitize_endpoint(value: Option<String>) -> Option<String> {
    sanitize_optional_text(value, 128)
}

pub fn sanitize_cmdline(value: String) -> String {
    sanitize_text(&value, 1024).unwrap_or_else(|| "unknown".to_string())
}

pub fn sanitize_history_sample(mut sample: HistorySample) -> Option<HistorySample> {
    // Reject identity-bearing fields that do not survive exact bounded
    // sanitation. Persisted history must not be "fixed up" into a different
    // session identifier on read.
    if sample.kind != SessionKind::Instrumented {
        return None;
    }
    if sample.pid <= 0 {
        return None;
    }
    if !text_is_exact_and_bounded(&sample.session_id, 128) {
        return None;
    }

    sample.display_session_id = sanitize_display_session_id(sample.display_session_id);
    sample.bind_addr = sanitize_endpoint(sample.bind_addr);
    sample.client_addr = sanitize_endpoint(sample.client_addr);
    sample.observer = sample.observer.and_then(sanitize_observer_info);
    sample.metrics.srtt_ms = sanitize_nonnegative_metric(sample.metrics.srtt_ms);
    sample.metrics.rttvar_ms = sanitize_nonnegative_metric(sample.metrics.rttvar_ms);
    sample.metrics.last_rtt_ms = sanitize_nonnegative_metric(sample.metrics.last_rtt_ms);
    sample.metrics.retransmit_pct_10s = sanitize_percentage(sample.metrics.retransmit_pct_10s);
    sample.metrics.retransmit_pct_60s = sanitize_percentage(sample.metrics.retransmit_pct_60s);
    Some(sample)
}

fn sanitize_optional_text(value: Option<String>, max_chars: usize) -> Option<String> {
    value.and_then(|value| sanitize_text(&value, max_chars))
}

fn sanitize_text(value: &str, max_chars: usize) -> Option<String> {
    let mut sanitized = String::new();
    let mut emitted = 0usize;
    let mut truncated = false;
    let mut previous_was_whitespace = false;

    for ch in value.chars() {
        let replacement = if ch.is_control() {
            if ch.is_whitespace() { ' ' } else { '?' }
        } else {
            ch
        };

        let replacement = if replacement.is_whitespace() {
            if previous_was_whitespace {
                continue;
            }
            previous_was_whitespace = true;
            ' '
        } else {
            previous_was_whitespace = false;
            replacement
        };

        if emitted >= max_chars {
            truncated = true;
            break;
        }

        sanitized.push(replacement);
        emitted += 1;
    }

    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        return None;
    }

    if truncated && max_chars > ELLIPSIS.len() {
        let keep = max_chars - ELLIPSIS.len();
        let truncated_value = sanitized.chars().take(keep).collect::<String>() + ELLIPSIS;
        return Some(truncated_value);
    }

    Some(sanitized.to_string())
}

fn sanitize_observer_info(observer: ObserverInfo) -> Option<ObserverInfo> {
    Some(ObserverInfo {
        node_name: sanitize_text(&observer.node_name, 255)?,
        system_id: sanitize_text(&observer.system_id, 255)?,
    })
}

fn sanitize_nonnegative_metric(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && *value >= 0.0)
}

fn sanitize_percentage(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
}

fn text_is_exact_and_bounded(value: &str, max_chars: usize) -> bool {
    sanitize_text(value, max_chars).is_some_and(|sanitized| sanitized == value)
}

#[cfg(test)]
mod tests {
    use moshwatch_core::{HealthState, HistorySample, ObserverInfo, SessionKind, SessionMetrics};

    use super::{
        sanitize_cmdline, sanitize_display_session_id, sanitize_endpoint, sanitize_history_sample,
    };

    #[test]
    fn strips_control_sequences_and_collapses_whitespace() {
        assert_eq!(
            sanitize_display_session_id(Some("abc\x1b[31m\r\nxyz".to_string())).as_deref(),
            Some("abc?[31m xyz")
        );
    }

    #[test]
    fn truncates_long_fields() {
        let value = "x".repeat(150);
        let sanitized = sanitize_endpoint(Some(value)).expect("sanitized endpoint");
        assert_eq!(sanitized.len(), 128);
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn empty_or_control_only_values_are_dropped() {
        assert!(sanitize_display_session_id(Some("\r\n\t".to_string())).is_none());
    }

    #[test]
    fn cmdline_falls_back_when_sanitized_empty() {
        assert_eq!(sanitize_cmdline("\x00\x01".to_string()), "??");
    }

    #[test]
    fn history_sample_sanitizer_drops_invalid_identity_fields() {
        let sample = HistorySample {
            observer: Some(ObserverInfo {
                node_name: "node-1".to_string(),
                system_id: "system-1".to_string(),
            }),
            recorded_at_unix_ms: 1,
            session_id: "instrumented:\n1:42".to_string(),
            display_session_id: Some("display".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: 1,
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001".to_string()),
            metrics: SessionMetrics::default(),
        };
        assert!(sanitize_history_sample(sample).is_none());
    }

    #[test]
    fn history_sample_sanitizer_normalizes_optional_fields_and_metrics() {
        let sample = HistorySample {
            observer: Some(ObserverInfo {
                node_name: "node-\n1".to_string(),
                system_id: "system-1".to_string(),
            }),
            recorded_at_unix_ms: 1,
            session_id: "instrumented:1:42".to_string(),
            display_session_id: Some("display\r\nid".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: 1,
            bind_addr: Some("127.0.0.1\r\n".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001\t".to_string()),
            metrics: SessionMetrics {
                srtt_ms: Some(f64::INFINITY),
                rttvar_ms: Some(-1.0),
                last_rtt_ms: Some(5.0),
                retransmit_pct_10s: Some(120.0),
                retransmit_pct_60s: Some(2.0),
                ..SessionMetrics::default()
            },
        };
        let sanitized = sanitize_history_sample(sample).expect("sanitize sample");
        assert_eq!(sanitized.display_session_id.as_deref(), Some("display id"));
        assert_eq!(sanitized.bind_addr.as_deref(), Some("127.0.0.1"));
        assert_eq!(sanitized.client_addr.as_deref(), Some("192.0.2.1:60001"));
        assert_eq!(
            sanitized.observer,
            Some(ObserverInfo {
                node_name: "node- 1".to_string(),
                system_id: "system-1".to_string(),
            })
        );
        assert_eq!(sanitized.metrics.srtt_ms, None);
        assert_eq!(sanitized.metrics.rttvar_ms, None);
        assert_eq!(sanitized.metrics.last_rtt_ms, Some(5.0));
        assert_eq!(sanitized.metrics.retransmit_pct_10s, None);
        assert_eq!(sanitized.metrics.retransmit_pct_60s, Some(2.0));
    }
}
