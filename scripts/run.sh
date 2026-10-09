#!/usr/bin/env bash
#
# run.sh — thin wrapper around attack_loop.py that auto-activates the venv.
# All arguments are passed straight through, e.g.:
#   ./scripts/run.sh --scenario sqli-login --strategist claude
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

exec python3 attack_loop.py "$@"
