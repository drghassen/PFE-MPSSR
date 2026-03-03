#!/usr/bin/env bash
set -euo pipefail

# Thin compatibility wrapper kept for existing scripts/tests.
# normalize.py is the canonical implementation.

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
NORMALIZER_PY="${ROOT}/shift-left/normalizer/normalize.py"

if [[ ! -f "$NORMALIZER_PY" ]]; then
  echo "[CloudSentinel][Normalizer][ERROR] normalize.py not found: $NORMALIZER_PY" >&2
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  exec python3 "$NORMALIZER_PY"
fi

if command -v python >/dev/null 2>&1; then
  exec python "$NORMALIZER_PY"
fi

echo "[CloudSentinel][Normalizer][ERROR] python3/python not installed." >&2
exit 1
