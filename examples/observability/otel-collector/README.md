# OTLP Collector Example

This collector example is intentionally local-first. It listens on loopback for
OTLP/HTTP metrics and writes them to the debug exporter.

Recommended practice:

- keep collector endpoints on loopback unless you have a clear network design
- inject OTLP headers from secrets, not committed files
- prefer HTTPS and mTLS if the collector is remote

Update the daemon config under `[metrics.otlp]` to point at this collector.
