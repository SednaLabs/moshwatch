# Observability Examples

This directory contains the first-party observability asset pack shipped with
`moshwatch`.

It is intentionally small and focuses on durable operator surfaces:

- `config/`
  Generated default `moshwatch` metrics config example.
- `prometheus/`
  Scrape config, alert rules, and rule tests.
- `grafana/`
  Provisioning examples and a small overview dashboard.
- `otel-collector/`
  A collector-side OTLP metrics example.

Validate the entire pack with:

```bash
cargo run --locked -p xtask -- validate-observability-assets
```
