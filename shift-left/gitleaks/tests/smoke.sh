#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
OUT_FILE="$REPO_ROOT/.cloudsentinel/gitleaks_raw.json"

export SCAN_MODE="local"
export SCAN_TARGET="repo"
export USE_BASELINE="false"
export CLOUDSENTINEL_TIMEOUT="${CLOUDSENTINEL_TIMEOUT:-120}"

bash "$REPO_ROOT/shift-left/gitleaks/run-gitleaks.sh"

test -f "$OUT_FILE"
jq -e 'type == "array"' "$OUT_FILE" >/dev/null

echo "[smoke][gitleaks] PASS"
