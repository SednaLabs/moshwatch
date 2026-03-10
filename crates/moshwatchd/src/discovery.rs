// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort `/proc` discovery for live Mosh server processes.
//!
//! ## Rationale
//! Discovery keeps stock `mosh-server` sessions visible and fills endpoint
//! metadata gaps even when verified telemetry is unavailable or delayed.
//!
//! ## Security Boundaries
//! * Discovery is advisory; it does not outrank verified telemetry.
//! * Executable path matching is part of the trust decision, not just display
//!   filtering.
//! * `/proc/<pid>/exe` paths may carry a ` (deleted)` suffix after in-place
//!   upgrades and are normalized before validation.

use std::{
    collections::HashMap,
    fs, io,
    io::Read,
    net::{Ipv6Addr, SocketAddrV6},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::sanitize::sanitize_cmdline;

#[derive(Debug, Clone)]
pub struct DiscoveredSession {
    pub pid: i32,
    pub started_at_unix_ms: i64,
    pub bind_addr: Option<String>,
    pub udp_port: Option<u16>,
    pub cmdline: String,
}

#[derive(Debug, Clone)]
pub struct ProcessMetadata {
    pub started_at_unix_ms: i64,
    pub cmdline: String,
    pub exe_name: String,
    pub exe_path: PathBuf,
}

#[derive(Debug, Clone)]
struct UdpSocketInfo {
    bind_addr: String,
    udp_port: u16,
}

pub fn discover_mosh_sessions() -> Result<Vec<DiscoveredSession>> {
    let sockets = load_udp_sockets()?;
    let boot_time_seconds = read_boot_time_seconds()?;
    let ticks_per_second = read_clock_ticks_per_second()?;
    let mut sessions = Vec::new();

    for entry in fs::read_dir("/proc").context("read /proc")? {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };

        let metadata =
            match read_process_metadata_with_clock(pid, boot_time_seconds, ticks_per_second) {
                Ok(value) => value,
                Err(_) => continue,
            };
        if !is_supported_mosh_server_metadata(&metadata) {
            continue;
        }

        let socket = read_process_socket(pid, &sockets);
        sessions.push(DiscoveredSession {
            pid,
            started_at_unix_ms: metadata.started_at_unix_ms,
            bind_addr: socket.as_ref().map(|value| value.bind_addr.clone()),
            udp_port: socket.as_ref().map(|value| value.udp_port),
            cmdline: metadata.cmdline,
        });
    }

    sessions.sort_by_key(|session| session.pid);
    Ok(sessions)
}

pub fn read_process_metadata(pid: i32) -> Result<ProcessMetadata> {
    let boot_time_seconds = read_boot_time_seconds()?;
    let ticks_per_second = read_clock_ticks_per_second()?;
    read_process_metadata_with_clock(pid, boot_time_seconds, ticks_per_second)
}

fn read_process_metadata_with_clock(
    pid: i32,
    boot_time_seconds: i64,
    ticks_per_second: u64,
) -> Result<ProcessMetadata> {
    let exe_path = read_exe_path(pid)?;
    let exe_name = exe_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .context("missing executable basename")?
        .to_string();
    Ok(ProcessMetadata {
        started_at_unix_ms: read_started_at_unix_ms(pid, boot_time_seconds, ticks_per_second)?,
        cmdline: sanitize_cmdline(read_cmdline(pid)?),
        exe_name,
        exe_path,
    })
}

pub fn is_supported_mosh_server_exe(exe_name: &str) -> bool {
    matches!(exe_name, "mosh-server" | "mosh-server-real")
}

pub fn is_supported_mosh_server_metadata(metadata: &ProcessMetadata) -> bool {
    is_supported_mosh_server_path(&metadata.exe_path)
}

pub fn is_supported_mosh_server_path(exe_path: &Path) -> bool {
    let Some(exe_name) = exe_path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !is_supported_mosh_server_exe(exe_name) {
        return false;
    }
    match exe_name {
        "mosh-server-real" => expected_instrumented_server_path()
            .map(|expected| exe_path == expected)
            .unwrap_or(false),
        "mosh-server" => is_supported_stock_mosh_server_path(exe_path),
        _ => false,
    }
}

pub fn expected_instrumented_server_path() -> Result<PathBuf> {
    let daemon_path = std::env::current_exe().context("resolve current executable path")?;
    let bin_dir = daemon_path
        .parent()
        .context("resolve current executable directory")?;
    Ok(bin_dir.join("mosh-server-real"))
}

fn is_supported_stock_mosh_server_path(exe_path: &Path) -> bool {
    matches!(
        exe_path,
        path if path == Path::new("/usr/bin/mosh-server")
            || path == Path::new("/usr/local/bin/mosh-server")
            || path == Path::new("/bin/mosh-server")
    ) || is_nix_store_mosh_server_path(exe_path)
}

fn is_nix_store_mosh_server_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(std::path::Component::RootDir))
        && matches!(components.next(), Some(component) if component.as_os_str() == "nix")
        && matches!(components.next(), Some(component) if component.as_os_str() == "store")
        && components.next().is_some()
        && matches!(components.next(), Some(component) if component.as_os_str() == "bin")
        && matches!(components.next(), Some(component) if component.as_os_str() == "mosh-server")
        && components.next().is_none()
}

fn read_cmdline(pid: i32) -> Result<String> {
    const MAX_CMDLINE_BYTES: usize = 8 * 1024;

    let path = format!("/proc/{pid}/cmdline");
    let file = fs::File::open(&path).with_context(|| format!("open {path}"))?;
    let mut raw = Vec::with_capacity(256);
    file.take((MAX_CMDLINE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .with_context(|| format!("read {path}"))?;
    if raw.is_empty() {
        let comm_path = format!("/proc/{pid}/comm");
        return fs::read_to_string(&comm_path)
            .map(|value| value.trim().to_owned())
            .with_context(|| format!("read {comm_path}"));
    }
    let truncated = raw.len() > MAX_CMDLINE_BYTES;
    if truncated {
        raw.truncate(MAX_CMDLINE_BYTES);
    }

    let pieces = raw
        .split(|byte| *byte == 0)
        .filter(|piece| !piece.is_empty())
        .map(|piece| String::from_utf8_lossy(piece).to_string())
        .collect::<Vec<_>>();
    let mut cmdline = pieces.join(" ");
    if truncated {
        cmdline.push_str(" ...");
    }
    Ok(cmdline)
}

fn read_exe_path(pid: i32) -> Result<PathBuf> {
    let path = format!("/proc/{pid}/exe");
    fs::read_link(&path)
        .map(normalize_proc_exe_path)
        .with_context(|| format!("read {path}"))
}

fn normalize_proc_exe_path(path: PathBuf) -> PathBuf {
    const DELETED_SUFFIX: &str = " (deleted)";
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return path;
    };
    let Some(stripped) = file_name.strip_suffix(DELETED_SUFFIX) else {
        return path;
    };
    path.with_file_name(stripped)
}

fn read_process_socket(pid: i32, sockets: &HashMap<u64, UdpSocketInfo>) -> Option<UdpSocketInfo> {
    let fd_dir = format!("/proc/{pid}/fd");
    let entries = fs::read_dir(fd_dir).ok()?;
    for entry in entries.flatten() {
        let target = match fs::read_link(entry.path()) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let target = target.to_string_lossy();
        let Some(inode) = socket_inode_from_fd_target(&target) else {
            continue;
        };
        if let Some(socket) = sockets.get(&inode) {
            return Some(socket.clone());
        }
    }
    None
}

fn socket_inode_from_fd_target(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse::<u64>()
        .ok()
}

fn load_udp_sockets() -> Result<HashMap<u64, UdpSocketInfo>> {
    let mut sockets = HashMap::new();
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        let raw = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        for line in raw.lines().skip(1) {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 10 {
                continue;
            }
            let local = parts[1];
            let inode = match parts[9].parse::<u64>() {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some((bind_addr, udp_port)) = parse_local_endpoint(local) else {
                continue;
            };
            sockets.insert(
                inode,
                UdpSocketInfo {
                    bind_addr,
                    udp_port,
                },
            );
        }
    }
    Ok(sockets)
}

fn parse_local_endpoint(value: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = value.split_once(':')?;
    let udp_port = u16::from_str_radix(port_hex, 16).ok()?;
    let bind_addr = match addr_hex.len() {
        8 => decode_ipv4(addr_hex)?,
        32 => decode_ipv6(addr_hex)?,
        _ => return None,
    };
    Some((bind_addr, udp_port))
}

fn decode_ipv4(value: &str) -> Option<String> {
    let bytes = (0..4)
        .map(|idx| u8::from_str_radix(&value[idx * 2..idx * 2 + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(format!(
        "{}.{}.{}.{}",
        bytes[3], bytes[2], bytes[1], bytes[0]
    ))
}

fn decode_ipv6(value: &str) -> Option<String> {
    let mut bytes = [0u8; 16];
    for chunk in 0..4 {
        let word = &value[chunk * 8..chunk * 8 + 8];
        bytes[chunk * 4] = u8::from_str_radix(&word[6..8], 16).ok()?;
        bytes[chunk * 4 + 1] = u8::from_str_radix(&word[4..6], 16).ok()?;
        bytes[chunk * 4 + 2] = u8::from_str_radix(&word[2..4], 16).ok()?;
        bytes[chunk * 4 + 3] = u8::from_str_radix(&word[0..2], 16).ok()?;
    }
    Some(
        SocketAddrV6::new(Ipv6Addr::from(bytes), 0, 0, 0)
            .ip()
            .to_string(),
    )
}

fn read_started_at_unix_ms(pid: i32, boot_time_seconds: i64, ticks_per_second: u64) -> Result<i64> {
    let path = format!("/proc/{pid}/stat");
    let raw = fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    // The command field in `/proc/<pid>/stat` is wrapped in parentheses and
    // may itself contain spaces. Find the closing `)` first so field 22
    // (`starttime`) keeps its stable position; this timestamp underpins session
    // IDs, PID-reuse protection, and verified-telemetry matching.
    let end = raw
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing comm terminator"))?;
    let fields = raw[end + 2..].split_whitespace().collect::<Vec<_>>();
    let start_ticks = fields
        .get(19)
        .context("missing starttime field")?
        .parse::<u64>()
        .context("parse process starttime")?;
    Ok(boot_time_seconds * 1000 + (start_ticks * 1000 / ticks_per_second) as i64)
}

fn read_boot_time_seconds() -> Result<i64> {
    let raw = fs::read_to_string("/proc/stat").context("read /proc/stat")?;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("btime ") {
            return value
                .trim()
                .parse::<i64>()
                .context("parse btime from /proc/stat");
        }
    }
    anyhow::bail!("missing btime in /proc/stat")
}

fn read_clock_ticks_per_second() -> Result<u64> {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value <= 0 {
        anyhow::bail!("sysconf(_SC_CLK_TCK) failed");
    }
    Ok(value as u64)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        decode_ipv4, decode_ipv6, expected_instrumented_server_path, is_supported_mosh_server_exe,
        is_supported_mosh_server_path, normalize_proc_exe_path, parse_local_endpoint,
        socket_inode_from_fd_target,
    };

    #[test]
    fn parses_ipv4_proc_socket() {
        let (addr, port) = parse_local_endpoint("D201A8C0:EA61").expect("parse endpoint");
        assert_eq!(addr, "192.168.1.210");
        assert_eq!(port, 60001);
    }

    #[test]
    fn parses_ipv6_proc_socket() {
        let addr = decode_ipv6("00000000000000000000000001000000").expect("parse ipv6");
        assert_eq!(addr, "::1");
    }

    #[test]
    fn parses_ipv4_bytes() {
        assert_eq!(decode_ipv4("0100007F").as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn parses_socket_inode_target() {
        assert_eq!(socket_inode_from_fd_target("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode_from_fd_target("/tmp/not-a-socket"), None);
    }

    #[test]
    fn matches_supported_mosh_server_names() {
        assert!(is_supported_mosh_server_exe("mosh-server"));
        assert!(is_supported_mosh_server_exe("mosh-server-real"));
        assert!(!is_supported_mosh_server_exe("bash"));
    }

    #[test]
    fn supported_paths_require_vetted_locations() {
        assert!(is_supported_mosh_server_path(Path::new(
            "/usr/bin/mosh-server"
        )));
        assert!(is_supported_mosh_server_path(Path::new(
            "/nix/store/hash123/bin/mosh-server"
        )));
        let instrumented = expected_instrumented_server_path().expect("instrumented server path");
        assert!(is_supported_mosh_server_path(&instrumented));
        assert!(!is_supported_mosh_server_path(Path::new(
            "/tmp/mosh-server"
        )));
    }

    #[test]
    fn normalize_proc_exe_path_strips_deleted_suffix() {
        assert_eq!(
            normalize_proc_exe_path(PathBuf::from(
                "/home/grant/.local/share/moshwatch/bin/mosh-server-real (deleted)"
            )),
            PathBuf::from("/home/grant/.local/share/moshwatch/bin/mosh-server-real")
        );
        assert_eq!(
            normalize_proc_exe_path(PathBuf::from("/usr/bin/mosh-server (deleted)")),
            PathBuf::from("/usr/bin/mosh-server")
        );
    }

    #[test]
    fn supported_paths_accept_deleted_proc_exe_targets_after_normalization() {
        let instrumented = expected_instrumented_server_path().expect("instrumented server path");
        let deleted_instrumented_name = format!(
            "{} (deleted)",
            instrumented
                .file_name()
                .and_then(|value| value.to_str())
                .expect("instrumented basename")
        );
        let deleted_instrumented =
            normalize_proc_exe_path(instrumented.with_file_name(deleted_instrumented_name));
        let deleted_stock =
            normalize_proc_exe_path(PathBuf::from("/usr/bin/mosh-server (deleted)"));
        assert!(is_supported_mosh_server_path(&deleted_instrumented));
        assert!(is_supported_mosh_server_path(&deleted_stock));
    }
}
