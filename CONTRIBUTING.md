<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Contributing

## Project Goals

`moshwatch` is intentionally narrow:

- local per-user observability for active Mosh sessions
- secure-by-default local interfaces
- bounded persistence and bounded export surfaces
- minimal moving parts and a straightforward install story

When contributing, prefer small, reviewable, reversible changes that preserve
those constraints. Avoid turning the project into a fleet monitor, remote agent,
or general packet-analysis tool unless that expansion is explicitly requested.

## Pull Requests

- target `main`
- keep changes small, focused, and easy to review
- use short imperative commit subjects, matching the existing history
- explain behavior changes, operator-visible output changes, and any new
  security or licensing implications in the PR description

## Keep Documentation In Sync

Update documentation whenever a change affects:

- install or upgrade behavior
- runtime paths
- socket locations or permissions
- API endpoints or response fields
- observer identity fields, schema versions, or attribution behavior
- Prometheus metrics or auth requirements
- config fields, defaults, validation, or security posture
- wrapper behavior or shell integration
- service resource limits or daemon self-observability metrics
- licensing, release posture, or disclosure guidance

At minimum, check whether the change also needs edits in:

- [README.md](README.md)
- [SECURITY.md](SECURITY.md)
- [LICENSES.md](LICENSES.md)
- [AGENTS.md](AGENTS.md)

## Build

Build everything with:

```bash
cargo run --locked -p xtask -- build
```

That builds the vendored instrumented `mosh-server` and the Rust binaries and
copies runnable outputs into `dist/bin/`.

## Install Locally

Install the local runtime with:

```bash
cargo run --locked -p xtask -- install
```

That performs all of the following:

- installs `~/.local/share/moshwatch/bin/mosh-server-real`
- installs `~/.local/share/moshwatch/bin/moshwatchd`
- installs `~/.local/share/moshwatch/bin/moshwatch`
- installs `~/.local/bin/mosh-server`
- installs `~/.local/bin/moshwatch`
- installs and restarts the `systemd --user` service
- installs shell integration so SSH-launched non-interactive Bash sessions
  resolve `~/.local/bin/mosh-server`

If you only need part of that workflow, `xtask` also supports:

- `install-artifacts`
- `install-wrapper`
- `install-service`
- `install-shell-integration`

## Validation

Run the standard validation set:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash -n scripts/mosh-server-wrapper.sh
cargo run --locked -p xtask -- build
git diff --check
```

For install, service, wrapper, metrics, API, or runtime-path changes, also run:

```bash
cargo run --locked -p xtask -- install
systemctl --user is-active moshwatchd.service
curl --unix-socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/moshwatch/api.sock" http://localhost/v1/sessions
curl --unix-socket "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/moshwatch/api.sock" http://localhost/metrics
```

If your change touches TCP metrics behavior, also verify both:

- unauthenticated scrape fails as expected
- authenticated scrape succeeds with the token in
  `${XDG_STATE_HOME:-$HOME/.local/state}/moshwatch/metrics.token`

## Security Expectations

Preserve these invariants unless a maintainer explicitly requests a design
change:

- telemetry must be tied to verified local peers
- API and telemetry sockets must remain owner-only
- TCP metrics must not become unauthenticated
- non-loopback TCP metrics exposure must remain explicit opt-in
- persistent history must remain bounded by both retention and disk budget
- bounded API, stream, and metrics exports must surface truncation honestly

If a change weakens one of those properties, call that out explicitly in the
diff and update [SECURITY.md](SECURITY.md).

## Releases And Licensing

First-party `moshwatch` source is GPL-3.0-or-later unless a file states
otherwise. The vendored `vendor/mosh/` subtree keeps upstream Mosh licenses and
notices.

Releases that include `mosh-server-real` must be treated as GPLv3+ distributions
for compliance purposes and must include corresponding source for the exact
released binaries (including local instrumentation changes and build inputs).

Maintainers handle release tags and published artifacts.

Before proposing release-facing changes, check:

- [LICENSE](LICENSE)
- [NOTICE](NOTICE)
- [LICENSES.md](LICENSES.md)

If a change affects the vendored Mosh boundary, document that clearly.
