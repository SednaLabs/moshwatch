# Observability Operator Guide

`moshwatch` is local-first at runtime, but its observability outputs are designed
to aggregate cleanly across hosts. This guide covers the three supported paths:

- Prometheus only
- Prometheus plus Grafana
- OTLP metrics via a local collector

The canonical generated defaults live in:

- `examples/observability/config/moshwatch.toml`
- `docs/observability/metric-catalog.md`

## Detail Tiers

`moshwatch` exposes two metrics detail tiers:

- `aggregate_only`
  Fleet-safe aggregate metrics only.
- `per_session`
  Aggregate metrics plus per-session series.

Prometheus defaults to `per_session` because it is usually scraped by the local
operator. OTLP defaults to `aggregate_only` so a collector can forward metrics
without accidentally publishing per-session cardinality.

## Prometheus Only

1. Keep the daemon on the default loopback listener or another loopback address.
2. Scrape `http://127.0.0.1:9947/metrics` with the bearer token stored in
   `${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token`.
3. Use `examples/observability/prometheus/prometheus.yml` as the starting point,
   then replace the placeholder bearer-token path with the real path for the
   user that runs Prometheus.
4. Load `examples/observability/prometheus/rules/moshwatch.rules.yml` if you
   want first-party alerts.

The owner-only Unix socket also exposes `/metrics` without bearer auth, but
that route is intended for local tools and ad hoc inspection rather than normal
Prometheus scraping.

### OpenMetrics Negotiation

Both the Unix-socket `/metrics` route and the TCP listener support HTTP content
negotiation. Send `Accept: application/openmetrics-text; version=1.0.0` if you
want OpenMetrics text, otherwise the daemon falls back to Prometheus text.

## Prometheus Plus Grafana

1. Start with the Prometheus setup above.
2. Provision Grafana with the example datasource and dashboard providers:
   - `examples/observability/grafana/provisioning/datasources/moshwatch.yml`
   - `examples/observability/grafana/provisioning/dashboards/moshwatch.yml`
3. Import or provision `examples/observability/grafana/dashboards/moshwatch-overview.json`.

The example dashboard intentionally stays small and durable. It focuses on:

- session totals and health distribution
- session RTT and retransmit behavior
- daemon loop overruns
- persistent history usage
- OTLP exporter failures when OTLP is enabled

## OTLP Via Collector

Enable OTLP metrics export under `[metrics.otlp]` and point it at a collector.
The recommended default is a collector listening on loopback.

Use `examples/observability/otel-collector/otelcol.yaml` as the starting point.
That example exposes an OTLP/HTTP receiver on `127.0.0.1:4318` and exports the
received metrics to the collector's debug exporter.

Recommended posture:

- keep OTLP disabled until you need it
- default to `aggregate_only` detail for OTLP
- aggregate-only OTLP omits built-in observer identity; add explicit
  `metrics.otlp.resource_attributes` only if you want downstream host attribution
- prefer HTTPS for remote collectors
- prefer mTLS or a private network when collector traffic leaves the host
- treat OTLP headers as secrets and inject them from the environment or your
  secret manager rather than committing live values
- keep `accept` and `content-type` out of `[metrics.otlp.headers]`; the exporter
  owns those protobuf headers and rejects explicit overrides

## Validation

Repo-owned validation commands:

```bash
cargo run --locked -p xtask -- sync-observability-docs
cargo run --locked -p xtask -- check-observability-docs
cargo run --locked -p xtask -- validate-observability-assets
```

The first command regenerates machine-owned observability reference files. The
second and third commands are the CI-oriented verification path.

## Related Docs

- `docs/observability/metric-catalog.md`
- `docs/observability/migration.md`
- `README.md`
- `SECURITY.md`
