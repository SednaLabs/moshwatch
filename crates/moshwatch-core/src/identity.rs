// SPDX-License-Identifier: GPL-3.0-or-later

//! Host observer identity discovery.
//!
//! `observer.node_name` stays human-readable for operators, while
//! `observer.system_id` is intentionally opaque. That keeps host attribution
//! stable for joins without exposing the raw host `machine-id` through every
//! API, history sample, and Prometheus scrape.

use std::{env, fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObserverInfo {
    pub node_name: String,
    pub system_id: String,
}

pub fn discover_observer_info() -> ObserverInfo {
    let node_name = read_node_name().unwrap_or_else(|error| {
        warn!("failed to discover node name: {error:#}");
        "unknown-node".to_string()
    });
    let system_id = read_system_id()
        .map(|raw| derive_stable_system_id(&raw))
        .unwrap_or_else(|error| {
            warn!("failed to discover stable system id: {error:#}");
            derive_stable_system_id(&format!("node-fallback:{node_name}"))
        });
    ObserverInfo {
        node_name,
        system_id,
    }
}

fn read_node_name() -> Result<String> {
    #[cfg(unix)]
    {
        let mut buffer = [0u8; 256];
        let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("gethostname");
        }
        let end = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        return sanitize_identity_value(
            String::from_utf8_lossy(&buffer[..end]).as_ref(),
            "node name",
        );
    }

    #[allow(unreachable_code)]
    env::var("HOSTNAME")
        .context("read HOSTNAME")
        .and_then(|value| sanitize_identity_value(&value, "node name"))
}

fn read_system_id() -> Result<String> {
    for path in [
        Path::new("/etc/machine-id"),
        Path::new("/var/lib/dbus/machine-id"),
    ] {
        match fs::read_to_string(path) {
            Ok(raw) => {
                return sanitize_identity_value(&raw, "system id")
                    .with_context(|| format!("parse {}", path.display()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", path.display()));
            }
        }
    }
    anyhow::bail!("no machine-id file found")
}

fn sanitize_identity_value(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    if trimmed.len() > 255 {
        anyhow::bail!("{label} exceeds 255 bytes");
    }
    if trimmed
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        anyhow::bail!("{label} contains invalid whitespace or control characters");
    }
    Ok(trimmed.to_string())
}

fn derive_stable_system_id(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity("sha256:".len() + 32);
    encoded.push_str("sha256:");
    for byte in digest.iter().take(16) {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{derive_stable_system_id, sanitize_identity_value};

    #[test]
    fn sanitize_identity_rejects_whitespace() {
        let error = sanitize_identity_value("bad value", "node name").expect_err("reject value");
        assert!(error.to_string().contains("invalid whitespace"));
    }

    #[test]
    fn sanitize_identity_trims_and_accepts_valid_values() {
        assert_eq!(
            sanitize_identity_value("  node-1.example  ", "node name").expect("sanitize value"),
            "node-1.example"
        );
    }

    #[test]
    fn stable_system_id_is_deterministic_and_opaque() {
        let machine_id = "ad530da65cb846fa83d1715f71118084";
        let derived = derive_stable_system_id(machine_id);
        assert_eq!(derived, derive_stable_system_id(machine_id));
        assert!(derived.starts_with("sha256:"));
        assert!(!derived.contains(machine_id));
        assert_eq!(derived.len(), "sha256:".len() + 32);
    }
}
