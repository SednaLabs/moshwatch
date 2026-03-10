<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Security Policy

`moshwatch` is a host-local observability tool. It is not designed to be a
general remote service and should be operated with that assumption in mind.

It also emits explicit host identity metadata for attribution. Treat that as
operator-sensitive context when sharing logs, API samples, history exports, or
Prometheus output outside the host.

## Supported Threat Model

`moshwatch` is designed to defend these boundaries:

- untrusted local data should not be able to inject arbitrary telemetry
- local operator sockets should remain private to the current Unix user
- long-lived history should remain bounded under hostile but valid load
- TCP metrics should not be readable by other local users without an auth token
- public network exposure should require an explicit operator decision
- host attribution should be explicit for observability consumers, but easy to
  redact before public sharing

In practice that means:

- telemetry comes from a verified Unix stream peer
- peer credentials are checked with `SO_PEERCRED`
- the peer process is reconciled with `/proc` metadata and the expected
  installed `mosh-server-real`
- API and telemetry sockets are created with owner-only permissions
- TCP metrics require `Authorization: Bearer <token>`
- non-loopback TCP metrics binds are rejected by default
- persistent history is constrained by retention and a hard disk budget

## Non-Goals

`moshwatch` does not try to solve:

- same-user execution control
- full host compromise
- raw network forensics or packet capture
- multi-tenant policy enforcement beyond its own local files and sockets

The most important residual limitation is this:

- a process running as the same Unix user can still execute the legitimate
  installed `mosh-server-real` and generate real telemetry load

That is an execution-policy problem, not an observability parsing problem.

## Local Interfaces

### Unix API and telemetry sockets

The daemon uses owner-only Unix sockets under:

```text
${XDG_RUNTIME_DIR:-/run/user/$UID}/moshwatch/
```

These sockets are intended for the current Unix user only.

Treat them as sensitive local operator state. Do not proxy them into shared or
less-trusted contexts without an explicit access-control plan.

### TCP Prometheus listener

By default the daemon listens on:

```text
127.0.0.1:9947
```

Loopback is not considered a per-user security boundary on a multi-user host.
For that reason, TCP metrics scraping requires a bearer token even on loopback.

The token lives at:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token
```

and is created with mode `0600`.

The daemon also exposes host attribution through:

- JSON `observer` objects in API responses and event-stream frames
- `observer` objects on persisted history samples
- `moshwatch_observer_info` in Prometheus output

That metadata is useful for multi-host aggregation, but it also means raw
output can reveal stable machine identity unless redacted. `observer.system_id`
is an opaque stable identifier, not the raw host `machine-id`, but it is still
sensitive enough to redact in public reports.

Persisted history is treated as untrusted local input on read. Malformed lines
and samples with invalid identity or metric fields are skipped or normalized
before they can be replayed through the API.

If you intentionally bind metrics off loopback, you must opt in with either:

- `metrics.allow_non_loopback = true`
- `--allow-public-metrics`

That opt-in does not replace normal network controls. If you expose the TCP
listener beyond the host, you still need to decide how the bearer token is
protected in transit and where that listener is reachable.

## Operator Guidance

### Protect the metrics token

- keep `${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token` readable
  only by the intended Unix user
- do not check it into version control
- do not paste it into issue trackers, public gists, or shared chats
- if the token is exposed, stop the service, delete the token file, and start
  the service again to rotate it

Rotation example:

```bash
systemctl --user stop moshwatchd.service
rm -f "${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token"
systemctl --user start moshwatchd.service
```

### Keep the wrapper active

If SSH-launched sessions are resolving stock `/usr/bin/mosh-server`, they will
show up as `legacy` and will not emit live telemetry. After install, verify that
your shell resolves `~/.local/bin/mosh-server`.

### Watch the pressure metrics

The daemon exposes explicit signals for persistence stress and bounded-export
stress, including:

- `moshwatch_runtime_dropped_sessions_total`
- `moshwatch_history_current_bytes`
- `moshwatch_history_write_failures_total`
- `moshwatch_history_prune_failures_total`
- `moshwatch_history_dropped_samples_total`

If these rise unexpectedly, treat that as an operational signal rather than
assuming history or metrics are complete.

### Redact observer identity in public reports

Before posting output publicly, remove or replace:

- `observer.node_name`
- `observer.system_id`
- `moshwatch_observer_info{...}`

If a report still needs host differentiation, prefer placeholders like
`node-a`, `node-b`, or `<redacted-system-id>` rather than publishing the live
machine identity.

## Reporting

If you find a vulnerability:

- use GitHub's private vulnerability reporting or Security Advisories flow for
  this repository when it is enabled
- if that private GitHub flow is not enabled yet, contact the maintainer
  privately before opening an issue
- do not open a public GitHub issue for a security-sensitive report before
  maintainers have had a chance to assess it
- do not include local tokens, usernames, hostnames, or internal paths in any
  report or reproduction

If the problem is not security-sensitive, use GitHub Issues for the repository.

Please include:

- affected version or commit
- reproduction steps and expected impact
- any redactions you applied to logs, metrics, or API output
