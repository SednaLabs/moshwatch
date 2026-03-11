<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# moshwatch

`moshwatch` is a host-local observability tool for active `mosh-server` sessions.
It is designed for a single Unix user account on a single host and focuses on
three jobs:

- show live health for newly instrumented Mosh sessions
- keep legacy pre-instrumentation sessions visible enough to identify them
- persist bounded session history so the host can act like a simple
  SmokePing-style recorder for real Mosh traffic

`moshwatch` is not a replacement for upstream Mosh. This repository vendors
upstream Mosh in `vendor/mosh/` only to build the instrumented
`mosh-server-real` used by the local observer.

`moshwatch` is not a fleet product, packet sniffer, or public monitoring service.
It is a local operator tool.

## Components

The repo builds and installs four operator-facing pieces:

- `mosh-server-real`
  A vendored, instrumented Mosh 1.4.0 server that emits verified
  per-session telemetry over a Unix stream.
- `moshwatchd`
  A local daemon that ingests telemetry, discovers legacy sessions, keeps
  bounded in-memory state, persists bounded history, serves a local API,
  and exports Prometheus metrics.
- `moshwatch`
  A terminal UI for live inspection and same-user session actions.
- `mosh-server` wrapper
  Installed in `~/.local/bin` so new SSH-launched Mosh sessions resolve the
  wrapper first and start the instrumented server instead of stock
  `mosh-server`.

## What It Measures

For sessions launched through the wrapper, `moshwatch` can report:

- smoothed RTT
- RTT variance
- last RTT sample
- last-heard age from the peer
- remote-state age
- cumulative transmit, receive, and retransmit counters
- 10-second and 60-second retransmit ratios

The `RTX10` and `RTX60` fields are protocol-level retransmit ratios inferred
from Mosh resend behavior. `RTX10` is the fast warning window, while critical
retransmit health is based on the sustained `RTX60` window. They are a
practical host-local loss proxy, not raw IP-layer packet capture.

`last_heard_age_ms` is the liveness signal used for health. By contrast,
`remote_state_age_ms` is the age of the last new remote state from the peer, so
it can grow during an idle but healthy session and should not be interpreted as
packet silence on its own.

Existing sessions that were started before the wrapper became active still
appear as `legacy`. Those sessions only expose process and socket metadata,
not live RTT or retransmit telemetry.

## Session Identity Model

The daemon keys instrumented sessions by verified process identity, not by the
wrapper UUID.

- `session_id`
  Canonical daemon identity. For instrumented sessions it is derived from
  verified process identity and start time.
- `display_session_id`
  Wrapper-provided UUID shown to the operator when available.

This avoids PID-reuse mistakes and prevents a verified peer from renaming an
existing session record arbitrarily.

## Observer Identity Model

Every API response, event-stream frame, and persisted history sample is tagged
with the identity of the machine that produced it.

- `observer.node_name`
  Human-friendly node name from the local host.
- `observer.system_id`
  Stable opaque identifier derived from local host identity. When
  `machine-id` is available, `moshwatch` exposes a one-way digest rather than
  the raw machine-id itself.

This is intentionally separate from `session_id`. `session_id` identifies the
Mosh session on a host; `observer` identifies which host observed that session.

## Security Model Summary

`moshwatch` treats these as the primary security boundaries:

- telemetry must come from a verified local peer, not arbitrary JSON on a socket
- local control sockets must stay private to the current user
- persisted history must stay bounded so valid-but-hostile load cannot grow disk
  without limit
- TCP metrics scraping must be authenticated because loopback is not a
  multi-user security boundary

Important non-goals:

- preventing the same Unix user from executing the legitimate installed
  `mosh-server-real`
- host-wide policy enforcement
- raw packet capture or network forensics

The deeper threat model and operator guidance live in [SECURITY.md](SECURITY.md).

## Requirements

The supported operating model is:

- Linux or another Unix-like host with Unix domain sockets
- `systemd --user` for the installed service flow
- `cargo`, a C toolchain, `make`, and `protoc` available for builds
- OpenSSH or another environment where `mosh-server` is started remotely over SSH

The wrapper and default runtime paths assume a normal per-user environment with
`HOME` set. The install flow also assumes `~/.local/bin` is acceptable for user
binaries.

## Host Impact

`moshwatch` is intentionally biased toward "small local service" rather than
"always-on monitor with fleet-style appetite". The default runtime already uses
several guardrails to keep host impact low:

- bounded in-memory session cardinality and bounded per-session detail history
- bounded API, event-stream, and Prometheus export surfaces
- bounded persistent history retention and disk budget
- periodic loops with `MissedTickBehavior::Skip`, so stalls do not cause
  catch-up bursts
- vendored Mosh telemetry that stays at a 30-second wakeup cadence until the
  daemon is actually consuming telemetry
- a Tokio runtime fixed to 2 worker threads instead of scaling to all host CPUs
- a low-priority `systemd --user` unit with cgroup accounting and explicit
  `Nice=10`, `CPUWeight=20`, `MemoryHigh=128M`, `MemoryMax=256M`, and
  `TasksMax=64`

If you want a stricter or looser policy on a given host, prefer a `systemd`
drop-in rather than editing the unit template in place.

## Build

Build everything from the repo root:

```bash
cargo run --locked -p xtask -- build
```

That:

- builds the vendored instrumented `mosh-server`
- builds the Rust binaries in release mode
- writes runnable artifacts into `dist/bin/`

The main outputs are:

- `dist/bin/mosh-server-real`
- `dist/bin/moshwatchd`
- `dist/bin/moshwatch`

## Install

Install locally with:

```bash
cargo run --locked -p xtask -- install
```

That will:

- copy stable runtime binaries into `~/.local/share/moshwatch/bin/`
- install `~/.local/bin/mosh-server` as the fail-open wrapper
- install `~/.local/bin/moshwatch`
- install and restart `moshwatchd.service` as a `systemd --user` unit
- install a managed PATH snippet so SSH-launched non-interactive Bash shells
  resolve `~/.local/bin/mosh-server`

The installed runtime is not pinned to the checkout path. You can move the repo
after install without breaking the wrapper or service.

### Installed Paths

Default installed paths:

- binaries
  `~/.local/share/moshwatch/bin/`
- user-facing wrapper
  `~/.local/bin/mosh-server`
- user-facing TUI launcher
  `~/.local/bin/moshwatch`
- service unit
  `~/.config/systemd/user/moshwatchd.service`
- managed PATH snippet
  `~/.config/moshwatch/path.sh`

## Quick Start

1. Build and install:

   ```bash
   cargo run --locked -p xtask -- install
   ```

2. Confirm the service is active:

   ```bash
   systemctl --user status moshwatchd.service
   ```

3. Confirm your remote shell resolves the wrapper:

   ```bash
   bash -c '. "$HOME/.bashrc"; command -v mosh-server'
   ```

   Expected result:

   ```text
   /home/<user>/.local/bin/mosh-server
   ```

4. Start a new Mosh session.

5. Watch it live:

   ```bash
   moshwatch
   ```

### TUI Controls

- `j` / `k` or arrow keys move the selection
- `g` / `G` jump to the first or last visible session
- `x` arms a terminate request for the selected session
- `y` or `Enter` confirms the pending terminate request
- `n` or `Esc` cancels the pending terminate request
- `r` refreshes immediately
- `q` quits

Important: existing sessions do not become instrumented in place. If you
installed `moshwatch` while old Mosh sessions were already alive, those older
sessions remain `legacy` until they terminate. Start a fresh session after
install to see live RTT and retransmit telemetry.

## Operator Checks

Useful local checks:

```bash
systemctl --user status moshwatchd.service
curl --unix-socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/moshwatch/api.sock" http://localhost/v1/sessions
curl --unix-socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/moshwatch/api.sock" http://localhost/metrics
```

Inspect the installed metrics token:

```bash
stat -c '%a %n' "${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token"
```

Expected mode:

```text
600 ...
```

## Runtime Paths

By default, `moshwatch` uses:

- config file
  `${XDG_CONFIG_HOME:-$HOME/.config}/moshwatch/moshwatch.toml`
- runtime directory
  `${XDG_RUNTIME_DIR:-/run/user/$UID}/moshwatch`
  with a fallback to `$HOME/.local/state/moshwatch/runtime` if no per-user
  runtime dir is available
- API socket
  `${XDG_RUNTIME_DIR:-/run/user/$UID}/moshwatch/api.sock`
- telemetry socket
  `${XDG_RUNTIME_DIR:-/run/user/$UID}/moshwatch/telemetry.sock`
- persistent state directory
  `${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch`
- history directory
  `${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/history`
- TCP metrics token
  `${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token`

All local state directories are created with owner-only permissions where the
host allows it.

## Local API

The daemon serves a read-only HTTP-over-UDS API on:

```text
${XDG_RUNTIME_DIR:-/run/user/$UID}/moshwatch/api.sock
```

Available endpoints:

- `GET /v1/sessions`
  Bounded session summary list for the UI and local tooling.
- `GET /v1/sessions/{session_id}`
  Detailed session view with bounded sparkline history.
- `GET /v1/history/{session_id}?since_seconds=3600&limit=1000`
  Persisted instrumented history samples.
- `GET /v1/config`
  Current daemon config.
- `GET /v1/events/stream`
  Stable NDJSON event stream.
- `GET /metrics`
  Local Prometheus exposition over the Unix socket.

All JSON API responses include an `observer` object describing the host that
produced the data and, on current daemons, a `schema_version` field for the
exported REST/event contract. Clients should treat a missing REST
`schema_version` as legacy schema `2` during staged upgrades.

### `/v1/sessions` Notes

The response includes:

- `observer`
  The host identity for the daemon that produced the response.

- `total_sessions`
  Full number of sessions currently tracked in memory.
- `truncated_session_count`
  Number of sessions omitted from the response because the export is bounded.
- `dropped_sessions_total`
  Number of session records refused or evicted due to tracking capacity limits.

That means a large host can still be observed honestly even when the API and
metrics endpoints intentionally publish a bounded subset.

Instrumented session metrics include both:

- `last_heard_age_ms`
  Age since any packet was last heard from the peer. This is the health
  liveness signal shown in the TUI as `Heard`.
- `remote_state_age_ms`
  Age since the peer last sent a new remote state. This is useful context for
  idleness, but it is not the same as connectivity silence.

Instrumented session summaries now also expose explicit peer state:

- `client_addr`
  Compatibility alias for the last known remote client address.
- `peer.current_client_addr`
  Current peer endpoint from the most recent telemetry update, when one is
  presently attached.
- `peer.last_client_addr`
  Last known peer endpoint even if the client is currently absent.
- `peer.previous_client_addr`
  Previous non-null peer endpoint when the client roamed to a different IP.
- `peer.last_client_seen_at_unix_ms`
  Last time telemetry reported a non-null current peer.
- `peer.client_addr_changed_at_unix_ms`
  Last time telemetry observed the session move to a different non-null peer.

Persisted history samples keep `client_addr` as the last-known peer for
compatibility and add `current_client_addr` when a client is actively attached
at that recording point.

Persisted history samples also carry the same `observer` object so exported or
copied history remains attributable to the host that wrote it.

Older on-disk history written before host attribution existed is still
readable. If a legacy sample predates per-sample observer metadata, it is
returned with `observer = null` rather than being silently relabelled with the
current daemon host.

If a persisted history line is malformed or contains corrupted fields outside
normal runtime bounds, `moshwatch` skips that sample rather than replaying it
back through the API unchanged.

### `/v1/events/stream` Notes

The event stream is NDJSON, not Server-Sent Events. Each line is a full JSON
frame with:

- `schema_version`
- `observer`
- `event`
- `sequence`
- `generated_at_unix_ms`
- `sessions` on snapshot frames

The stream sends full snapshot frames plus heartbeat frames. Consumers should
treat the snapshot as authoritative state, not as an incremental patch stream.

The current event-stream `schema_version` is `3`.

### Historical Persistence Notes

Only instrumented sessions are written to persistent history.
Legacy sessions are intentionally excluded because they do not have exact live
telemetry.

History is bounded in two ways:

- age-based retention using `persistence.retention_days`
- hard disk budget using `persistence.max_disk_bytes`

If the disk budget is exhausted, the daemon drops new history samples rather
than growing the state directory without limit.

## Prometheus Metrics

By default, `moshwatchd` listens on:

```text
127.0.0.1:9947
```

and serves Prometheus exposition text at:

```text
http://127.0.0.1:9947/metrics
```

The same metrics payload is also available without HTTP auth on the Unix-socket
API endpoint:

```text
GET /metrics
```

### TCP Metrics Authentication

The TCP listener requires:

```text
Authorization: Bearer <token>
```

The token is stored at:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token
```

with mode `0600`.

Example manual scrape:

```bash
curl -H "Authorization: Bearer $(cat "${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token")" \
  http://127.0.0.1:9947/metrics
```

Example Prometheus config:

```yaml
scrape_configs:
  - job_name: moshwatch
    metrics_path: /metrics
    static_configs:
      - targets: ['127.0.0.1:9947']
    bearer_token_file: /home/<user>/.local/state/moshwatch/metrics.token
```

If you intentionally bind metrics off loopback, `moshwatchd` will reject that
configuration unless you also set `metrics.allow_non_loopback = true` or start
the daemon with `--allow-public-metrics`.

### Prometheus-Specific Signals

Useful `moshwatch`-specific series include:

Session info series use `client_addr` for the current peer when attached and
`last_client_addr` for the most recent known peer.

- `moshwatch_observer_info`
  Stable machine attribution for the daemon emitting the metric stream.

- `moshwatch_session_retransmit_window_complete{window="10s"|"60s"}`
  Distinguishes a warming window from a missing retransmit ratio.
- `moshwatch_runtime_dropped_sessions_total`
  Shows when tracking capacity caused refusal or eviction.
- `moshwatch_history_current_bytes`
  Current on-disk history size.
- `moshwatch_history_written_bytes_total`
  Successful history writes over time.
- `moshwatch_history_write_failures_total`
  Persistent history write-path failures.
- `moshwatch_history_prune_failures_total`
  Expired history files that failed to prune.
- `moshwatch_history_dropped_samples_total`
  History samples dropped because the disk budget was exhausted.
- `moshwatch_runtime_worker_threads`
  Fixed Tokio worker thread count for the daemon.
- `moshwatch_runtime_loop_interval_ms{loop=...}`
  Configured interval for `discovery`, `history`, and `snapshot` loops.
- `moshwatch_runtime_loop_last_duration_ms{loop=...}`
  Last observed runtime for each periodic loop.
- `moshwatch_runtime_loop_overruns_total{loop=...}`
  Number of times a periodic loop took longer than its configured interval.

Use `moshwatch_observer_info` for machine attribution in Prometheus joins or
multi-host dashboards rather than repeating host labels across every
session-level series.

## Configuration

On first start, `moshwatchd` writes a default config file unless started with
`--no-write-config`:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/moshwatch/moshwatch.toml
```

Current config schema:

```toml
refresh_ms = 1000
discovery_interval_ms = 5000
cleanup_interval_ms = 10000
history_secs = 900
max_tracked_sessions = 2048
max_session_detail_points = 900

[thresholds]
warn_rtt_ms = 400
critical_rtt_ms = 1000
warn_retransmit_pct = 2.0
critical_retransmit_pct = 10.0
warn_silence_ms = 5000
critical_silence_ms = 15000

[stream]
heartbeat_ms = 15000

[persistence]
enabled = true
sample_interval_ms = 5000
retention_days = 14
max_query_samples = 4096
max_disk_bytes = 536870912

[metrics]
listen_addr = "127.0.0.1:9947"
allow_non_loopback = false
```

Notes:

- `warn_loss_pct` and `critical_loss_pct` are accepted as compatibility aliases
  for `warn_retransmit_pct` and `critical_retransmit_pct`.
- `history_secs` controls only in-memory sparkline history.
- `persistence.max_disk_bytes` is the hard on-disk history budget.
- `RTX10` and `RTX60` stay in a warming state until the full observation window
  exists.
- `warn_silence_ms` and `critical_silence_ms` apply to `last_heard_age_ms`, not
  to remote-state idleness.

## Daemon Flags

`moshwatchd` supports:

- `--api-socket <path>`
  Override the Unix API socket path.
- `--telemetry-socket <path>`
  Override the Unix telemetry socket path.
- `--metrics-listen <host:port>`
  Override the TCP Prometheus listener address.
- `--allow-public-metrics`
  Explicitly allow a non-loopback TCP metrics bind.
- `--no-write-config`
  Do not write a default config file on startup.

## Troubleshooting

### I want to verify `moshwatch` is staying cheap

Check the service-level limits and accounting:

```bash
systemctl --user show moshwatchd.service \
  -p Nice -p CPUWeight -p MemoryHigh -p MemoryMax -p TasksMax
```

Check the daemon's own periodic loop cost:

```bash
curl --unix-socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/moshwatch/api.sock" \
  http://localhost/metrics | rg 'moshwatch_runtime_(worker_threads|loop_)'
```

Healthy output should show small `moshwatch_runtime_loop_last_duration_ms`
values relative to their configured intervals, and
`moshwatch_runtime_loop_overruns_total` should stay near zero on a normal host.

### A newly reconnected session still shows as `legacy`

Most likely cause: the remote shell still resolved `/usr/bin/mosh-server`
instead of the wrapper in `~/.local/bin`.

Check:

```bash
bash -c '. "$HOME/.bashrc"; command -v mosh-server'
```

Expected result:

```text
/home/<user>/.local/bin/mosh-server
```

If not, reinstall shell integration:

```bash
cargo run --locked -p xtask -- install-shell-integration
```

and start a fresh Mosh session.

### TCP metrics return `401 Unauthorized`

That is expected unless you send the bearer token from
`${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token`.

### Metrics are intentionally bound off loopback but the daemon refuses to start

Set:

```toml
[metrics]
allow_non_loopback = true
```

or pass:

```bash
moshwatchd --allow-public-metrics
```

You still need to decide how that listener is protected on the network.

### History is not growing

Check:

- `moshwatch_history_dropped_samples_total`
- `moshwatch_history_write_failures_total`
- `moshwatch_history_current_bytes`

If the disk budget is exhausted, `moshwatchd` will shed new samples instead of
allowing unbounded growth.

### You want to rotate the TCP metrics token

Stop the user service before deleting the token file so the running daemon does
not restore the active token back to disk:

```bash
systemctl --user stop moshwatchd.service
rm -f "${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token"
systemctl --user start moshwatchd.service
```

Prometheus or any other scraper must then reload the new token.

### You need to attribute exported data to the host that observed it

Use one of:

- the top-level `observer` object in JSON API responses
- the top-level `observer` object in NDJSON event-stream frames
- the per-sample `observer` object in persisted history results
- the `moshwatch_observer_info` Prometheus series

`observer.node_name` is the human-friendly host label.
`observer.system_id` is the stable identifier intended for joins,
deduplication, and cross-host analysis. It is intentionally opaque and should
not be treated as the raw host `machine-id`.

## Development And Validation

Run the standard validation set:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash -n scripts/mosh-server-wrapper.sh
cargo run --locked -p xtask -- build
git diff --check
```

For a full local install verification pass:

```bash
cargo run --locked -p xtask -- install
systemctl --user is-active moshwatchd.service
curl --unix-socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/moshwatch/api.sock" http://localhost/v1/sessions
curl --unix-socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/moshwatch/api.sock" http://localhost/metrics
```

The same validation set is encoded in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for CI use when the
repository is hosted on a compatible platform.

## Repository Layout

- `crates/moshwatch-core`
  Shared config, protocol types, path discovery, and health logic.
- `crates/moshwatchd`
  Daemon, discovery, telemetry ingestion, history, API, and metrics.
- `crates/moshwatch-ui`
  Terminal UI client.
- `xtask`
  Build, install, wrapper, shell-integration, and service orchestration.
- `vendor/mosh`
  Vendored upstream Mosh source with the local telemetry patch.
- `systemd/`
  Installed user-service template.
- `scripts/`
  Wrapper template and install-time helper inputs.

## Licensing And Releases

First-party `moshwatch` code is licensed under GPL-3.0-or-later unless a file
states otherwise. The repository also vendors upstream Mosh in `vendor/mosh/`,
which keeps its upstream licenses and notices.

If you publish artifacts that include `mosh-server-real`, publish complete
corresponding source for the exact binaries and preserve both the repository
license texts and the upstream Mosh notices shipped in `vendor/mosh/`.

Maintainers publish releases manually; there is no automated release pipeline
from this working tree.

See:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [LICENSE](LICENSE)
- [NOTICE](NOTICE)
- [LICENSES.md](LICENSES.md)
