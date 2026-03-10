<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Licensing

`moshwatch` is a mixed-license repository.

## First-party code

The original code in these paths is licensed under GPL-3.0-or-later unless a
file explicitly states otherwise:

- `crates/`
- `xtask/`
- `scripts/`
- `systemd/`
- root documentation files, unless they say otherwise

The GPL-3.0-or-later license text is in [LICENSE](LICENSE).

## Vendored upstream code

The vendored Mosh source tree in `vendor/mosh/` is not relicensed by the
top-level repository license. It keeps the upstream notices and licenses
shipped with Mosh.

Relevant upstream files:

- [vendor/mosh/COPYING](vendor/mosh/COPYING)
- [vendor/mosh/debian/copyright](vendor/mosh/debian/copyright)
- [vendor/mosh/ocb-license.html](vendor/mosh/ocb-license.html)

## Practical release boundary (GPL-oriented artifacts)

Any packaged artifact that includes `mosh-server-real` also includes upstream
Mosh code. Those artifacts should be released with GPLv3-or-later compliance
as the controlling distribution posture for the bundle, while still preserving
all upstream notices and exceptions.

For each binary release that includes `mosh-server-real`:

- provide corresponding source for the exact released binaries, including local
  Mosh instrumentation changes and build scripts
- include upstream Mosh license texts and notices from `vendor/mosh/`
- keep first-party GPL notices (`LICENSE`, `NOTICE`) with the source tree and
  release metadata
- document modified upstream files and release commit references

This policy is about release packaging obligations, not automatic relicensing
of all source files in this repository.
