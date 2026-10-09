#!/usr/bin/env bash
#
# install.sh — one-shot setup on Ubuntu.
#   creates a venv, installs deps, fetches the headed browser binary.
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

PY="${PYTHON:-python3}"

echo "[*] project: $here"
echo "[*] python : $($PY --version 2>&1)"

echo "[*] creating virtualenv (.venv)"
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] upgrading pip"
pip install --upgrade pip >/dev/null

echo "[*] installing python dependencies"
pip install -r requirements.txt

echo "[*] installing Playwright Chromium (for the headed browser)"
if ! python -m playwright install chromium; then
  echo "[!] 'playwright install chromium' failed — the --driver http probe still works."
fi

# System libraries the headed browser needs (best-effort; requires sudo).
if command -v sudo >/dev/null 2>&1; then
  echo "[*] installing browser system dependencies (sudo; best-effort)"
  python -m playwright install-deps chromium 2>/dev/null \
    || echo "[!] could not install system deps — if the browser won't launch, run: sudo python -m playwright install-deps chromium"
fi

chmod +x scripts/*.sh attack_loop.py 2>/dev/null || true

cat <<'EOF'

[OK] setup complete.

Next:
  source .venv/bin/activate
  source scripts/aliases.sh          # optional: handy aliases
  ./scripts/start_target.sh &        # launch the demo target on 127.0.0.1:5000
  ./scripts/run.sh --scenario reflected-xss

Verify optional deps any time with:
  ./scripts/run.sh --selfcheck
EOF
