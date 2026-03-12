# Grafana Examples

This directory contains a small, first-party Grafana setup for `moshwatch`.

- `provisioning/datasources/moshwatch.yml`
  Prometheus datasource example using the `moshwatch-prometheus` UID.
- `provisioning/dashboards/moshwatch.yml`
  File-based dashboard provider example.
- `dashboards/moshwatch-overview.json`
  A compact dashboard for sessions, daemon health, history, and OTLP exporter
  state.

Adjust paths and datasource URLs to match your deployment before provisioning.
