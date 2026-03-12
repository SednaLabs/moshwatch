# Prometheus Examples

Use `prometheus.yml` as the starting point for local scraping. It assumes the
default bearer token location and loads the shipped alert rules.

The checked-in config uses a placeholder path:

```text
/home/<user>/.local/state/moshwatch/metrics.token
```

Replace it with the real token file path for the user that runs Prometheus.
Because the committed file is an example template rather than a host-specific
deployment file, repo validation checks it with `promtool --syntax-only`.

The rules and tests are designed to be validated with `promtool`:

```bash
promtool check config --syntax-only examples/observability/prometheus/prometheus.yml
promtool check rules examples/observability/prometheus/rules/moshwatch.rules.yml
promtool test rules examples/observability/prometheus/tests/moshwatch.rules.test.yml
```
