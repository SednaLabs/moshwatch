#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

REAL_SERVER="@INSTALL_BIN_DIR@/mosh-server-real"
STOCK_SERVER="/usr/bin/mosh-server"

if [[ ! -x "$REAL_SERVER" ]]; then
  exec "$STOCK_SERVER" "$@"
fi

if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
  RUNTIME_DIR="$XDG_RUNTIME_DIR/moshwatch"
elif [[ -d "/run/user/$(id -u)" ]]; then
  RUNTIME_DIR="/run/user/$(id -u)/moshwatch"
else
  RUNTIME_DIR="$HOME/.local/state/moshwatch/runtime"
fi

umask 077
mkdir -p "$RUNTIME_DIR" >/dev/null 2>&1 || true

MOSHWATCH_SESSION_ID="$(< /proc/sys/kernel/random/uuid)"
MOSHWATCH_TELEMETRY_SOCK="$RUNTIME_DIR/telemetry.sock"
export MOSHWATCH_SESSION_ID MOSHWATCH_TELEMETRY_SOCK

if ! exec "$REAL_SERVER" "$@"; then
  printf 'moshwatch wrapper: falling back to stock mosh-server\n' >&2
  exec "$STOCK_SERVER" "$@"
fi
