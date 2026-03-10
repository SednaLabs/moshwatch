# Modularisation and Boundaries (Documentation-Only Policy)

## Context

This repository contains:

- shared first-party Rust code in `crates/`
- install, wrapper, and service orchestration in `xtask/`, `scripts/`, and
  `systemd/`
- a vendored upstream Mosh subtree in `vendor/mosh/`

`moshwatch` is intentionally narrow: a host-local observability tool for active
Mosh sessions running under a single Unix user account on a single host. To
keep that scope clear, we prefer modularization that reduces coupling,
preserves auditability, and supports incremental refactors without weakening
security invariants.

## Status and enforcement

This is a **documentation-only policy** at the time of writing: guidance, not a
hard CI gate. Structural changes should be incremental, reversible, and tied to
real delivery work.

## Definitions

### Monolith (what we mean here)

A monolith is not just a large file. It is a unit (module/crate/workflow) that:

- mixes unrelated responsibilities such as verified telemetry ingestion,
  persistence, UI rendering, install orchestration, and security policy, or
- becomes a widely imported "god module" with hidden coupling across crates.

### Large cohesive rulebook (acceptable when deliberate)

Some modules are intentionally large because they are a rulebook. In this repo,
that can include config validation, health classification, API schema shaping,
or install-path rules. This is acceptable when:

- there is one clear domain and reason to change,
- the public facade stays small and stable,
- sections are clearly structured, and
- tests validate the external contract.

### Distributed monolith (anti-pattern)

A distributed monolith is many small modules with tight coupling:

- deep import chains across crates,
- stateful behavior split across files without a real ownership seam, or
- file-count splits that move code around without clarifying responsibility.

Split by cohesive seams, not by line count.

## Dependency direction (boundaries)

Prefer one simple rule: **dependencies point from orchestration toward shared
contracts and primitives**.

High-level guidance:

- `crates/moshwatch-core` owns shared types, config, path discovery, and logic
  that must stay consistent between the daemon and UI.
- `crates/moshwatchd` orchestrates runtime behavior: verified telemetry
  ingestion, legacy-session discovery, bounded history, local API, and
  Prometheus export.
- `crates/moshwatch-ui` renders operator state and should consume daemon-facing
  contracts rather than re-implementing daemon policy.
- `xtask/`, `scripts/`, and `systemd/` own build/install/runtime integration;
  they should not become a second home for daemon business logic.
- `vendor/mosh/` remains a narrow upstream boundary. Local instrumentation there
  should stay focused on telemetry emission and upstream-compatible patching,
  not first-party daemon or UI behavior.
- test helpers and fixtures should not leak into production paths.

Practical implications:

- if a type or rule must be shared between the daemon and UI, prefer a stable
  home in `moshwatch-core`
- if logic depends on daemon-owned runtime state, persistence, or verified-peer
  trust decisions, keep it in `moshwatchd`
- if code only exists to render or navigate terminal UX, keep it in
  `moshwatch-ui`
- if a change mostly affects how artifacts are built, installed, wrapped, or
  launched under `systemd --user`, keep it in `xtask/`, `scripts/`, or
  `systemd/`

## Blessed homes (where new code goes)

To reduce ambiguity:

- shared config, protocol types, observer/session identity helpers, path
  discovery, and cross-crate health logic:
  `crates/moshwatch-core/src/`
- daemon runtime, telemetry ingestion, session discovery, bounded history, API,
  metrics, and persistence policy:
  `crates/moshwatchd/src/`
- terminal rendering, client-side polling/stream handling, and operator
  interaction flow:
  `crates/moshwatch-ui/src/`
- build, install, wrapper, shell-integration, and service orchestration:
  `xtask/src/`, `scripts/`, and `systemd/`
- vendored upstream Mosh source and the local telemetry patch boundary:
  `vendor/mosh/`
- end-to-end and crate-local tests:
  `tests/` and `crates/*/tests/`

## Refactor posture (how to apply this policy safely)

1. **Forward-first.** New work should follow the current best structure even if
   nearby legacy code is less clean.
2. **Opportunistic retrofit.** Refactor when touching behavior, not as
   churn-only PRs.
3. **Facade first.** When untangling code, prefer introducing a small stable
   seam before extracting internals.
4. **Prefer contract tests over internals.** Validate behavior through daemon
   APIs, telemetry contracts, config parsing, install outputs, and UI-visible
   results.
5. **Preserve security invariants explicitly.** Boundary changes must not
   weaken the repo's core guarantees around verified telemetry, owner-only
   local sockets, authenticated TCP metrics, and bounded persistence/export
   surfaces.

## References

- `AGENTS.md`
- `CONTRIBUTING.md`
- `README.md`
- `SECURITY.md`
- `LICENSES.md`
