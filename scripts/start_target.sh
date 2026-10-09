#!/usr/bin/env bash
#
# start_target.sh — launch the bundled intentionally-vulnerable demo target.
# Binds to 127.0.0.1:5000 only. Ctrl-C to stop.
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

exec python3 targets/vulnerable_app.py
