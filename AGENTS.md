# Repository Guidelines

## Project Structure & Module Organization

`moshwatch` is a small Rust workspace. Core shared types and config live in
`crates/moshwatch-core`, daemon/runtime logic in `crates/moshwatchd`, and the
terminal UI in `crates/moshwatch-ui`. Build and install orchestration lives in
`xtask`, shell/service assets live in `scripts/` and `systemd/`, and vendored
upstream Mosh code stays in `vendor/mosh/`.

## Build, Test, and Development Commands

Build everything with `cargo run --locked -p xtask -- build`. Run the main
validation set with:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash -n scripts/mosh-server-wrapper.sh
cargo run --locked -p xtask -- build
git diff --check
```

For install or runtime-path changes, also run `cargo run --locked -p xtask --
install`, then verify the user service and local API socket.

## Coding Style & Naming Conventions

Follow existing Rust style and keep files GPL SPDX-tagged where the repo already
does so. Prefer small, reviewable diffs, descriptive type and function names,
and straightforward control flow over clever abstraction. Keep shared contracts
in `moshwatch-core`; daemon-only policy stays in `moshwatchd`; UI-only behavior
stays in `moshwatch-ui`.

## Testing Guidelines

Add or update tests when behavior changes. Favor contract-oriented tests around
config parsing, API output, telemetry handling, and install/runtime behavior.
If a change alters docs, security posture, install paths, or exported fields,
update the relevant documentation in the same patch.

## Commit & Pull Request Guidelines

Target `main`. Use short imperative commit subjects, matching the existing
history. PRs should describe user-visible behavior changes, validation run, and
any security or licensing impact. For security-sensitive issues, use private
reporting rather than public discussion.
