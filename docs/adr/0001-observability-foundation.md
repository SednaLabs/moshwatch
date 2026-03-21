# ADR 0001: Observability Foundation

## Status

Accepted

## Context

`moshwatch` already exposes a local JSON API, an event stream, bounded history,
and a Prometheus scrape surface. What it lacked was a deliberate long-term
observability contract:

- the metrics contract lived inline in `moshwatchd`
- Prometheus/OpenMetrics exposition and OTLP export would have drifted easily
- per-session metrics mixed low-value aggregate signals with volatile metadata
- there was no first-party foundation for dashboards, alerts, or collector use
- the configuration model only described a single Prometheus listener

This is the right point to correct that because `moshwatch` is still early in
its public lifecycle.

## Decision

We standardize on these rules:

1. `moshwatch-core` owns the shared observability contract metadata.
2. Prometheus/OpenMetrics remains the canonical local scrape contract.
3. OTLP metrics export is supported as an optional parallel export path.
4. Metrics are split into two detail tiers:
   - `aggregate_only`: fleet-safe aggregate metrics only
   - `per_session`: aggregate metrics plus per-session series
5. Prometheus defaults to `per_session` detail for local operators.
6. OTLP defaults to `aggregate_only` detail for fleet-safe collection.
7. Volatile network metadata does not appear in per-session value-series labels.
8. The repo ships first-party dashboards, rules, and integration examples, but
   does not install Prometheus, Grafana, or collectors.

## Consequences

### Positive

- Prometheus and OTLP share one metric contract instead of diverging.
- The fleet-safe default is explicit rather than accidental.
- Thresholds and exporter-health data become part of the observable contract.
- Future maintainers have a durable design record for why the surfaces look the
  way they do.

### Negative

- The config model is more explicit and therefore more verbose.
- Some Prometheus label combinations from the early implementation are no
  longer present because they were too volatile or too privacy-sensitive.
- OTLP export adds another supported operational surface that must be tested.

## Implementation Notes

- Legacy flat `[metrics]` Prometheus settings remain parse-compatible.
- New configuration lives under `[metrics.prometheus]` and `[metrics.otlp]`.
- The owner-only Unix socket and bearer-protected TCP listener remain intact.
- OTLP export is implemented as a separate background task so collector issues
  do not block discovery, ingestion, history, or API behavior.

## References

- `README.md`
- `SECURITY.md`
- `docs/design/modularisation-and-boundaries.md`
- `crates/moshwatch-core/src/observability.rs`
