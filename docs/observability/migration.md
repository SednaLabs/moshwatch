# Observability Migration Notes

This document covers the observability-surface changes introduced by the
observability foundation refresh.

## Config Migration

Legacy flat Prometheus settings under `[metrics]` still parse:

```toml
[metrics]
listen_addr = "127.0.0.1:9947"
allow_non_loopback = false
detail_tier = "aggregate_only"
```

The preferred long-term layout is explicit nested exporters:

```toml
[metrics.prometheus]
listen_addr = "127.0.0.1:9947"
allow_non_loopback = false
detail_tier = "per_session"

[metrics.otlp]
enabled = false
endpoint = "http://127.0.0.1:4318/v1/metrics"
export_interval_ms = 15000
timeout_ms = 5000
detail_tier = "aggregate_only"
```

## Label Changes

Per-session value series intentionally no longer repeat volatile network
metadata. In the refreshed contract:

- session value series use `session_id` and `kind`
- session info series keep `display_session_id`, `pid`, and `started_at_unix_ms`
- bind address, UDP port, and client address are API/history concerns, not
  value-series labels

This keeps the Prometheus and OTLP surfaces lower-cardinality and easier to
aggregate safely.

## New Metrics Contract Areas

The refreshed contract adds or formalizes:

- `moshwatch_sessions_by_health`
- threshold metrics under `moshwatch_threshold_*`
- OTLP exporter health metrics under `moshwatch_otlp_*`
- a generated metric catalog under `docs/observability/metric-catalog.md`

## Transport Behavior

The following behavior is unchanged but now documented as part of the contract:

- the TCP listener still requires `Authorization: Bearer <token>`
- the owner-only Unix socket still exposes `/metrics` without bearer auth
- non-loopback TCP binds still require explicit opt-in via
  `metrics.prometheus.allow_non_loopback = true` or `--allow-public-metrics`

## Recommended Upgrade Path

1. Move config to nested `[metrics.prometheus]` and `[metrics.otlp]` tables.
2. Update Prometheus dashboards or alert rules to use
   `moshwatch_sessions_by_health` and the OTLP exporter metrics.
3. If you aggregate across hosts, use `moshwatch_observer_info` for Prometheus
   attribution. Aggregate-only OTLP omits the built-in observer identity; add
   your own backend-specific attribution with `metrics.otlp.resource_attributes`
   if you need it, but built-in OTLP keys are reserved and rejected during
   configuration validation.
4. Re-run `cargo run --locked -p xtask -- validate-observability-assets` after
   changing repo-owned examples or docs.
