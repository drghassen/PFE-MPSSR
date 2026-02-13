#!/usr/bin/env bash
set -euo pipefail

############################################
# CloudSentinel Pre-Commit Hook v5.0 (PFE)
# Advisory mode: warns developer, never blocks.
# Enforcement is delegated to OPA in CI/CD.
############################################

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
REPORT="$REPO_ROOT/.cloudsentinel/gitleaks_opa.json"

echo "[CloudSentinel][pre-commit] Scanning staged files..."

# Force local behavior; no baseline in pre-commit
export USE_BASELINE="false"
export SCAN_TARGET="staged"
unset CI

bash "$REPO_ROOT/shift-left/gitleaks/run-gitleaks.sh"

[[ -f "$REPORT" ]] || { echo "[CloudSentinel][pre-commit][ERROR] Missing report: $REPORT"; exit 2; }

CRITICAL="$(jq -r '.stats.CRITICAL // 0' "$REPORT")"
HIGH="$(jq -r '.stats.HIGH // 0' "$REPORT")"
TOTAL="$(jq -r '.stats.TOTAL // 0' "$REPORT")"

if [[ "$TOTAL" -gt 0 ]]; then
  echo ""
  echo "⚠️  [CloudSentinel][pre-commit][ADVISORY] $TOTAL finding(s) detected (CRITICAL=$CRITICAL, HIGH=$HIGH)"
  echo "---"
  jq -r '
    .findings[]
    | "[\(.severity)] \(.file):\(.start_line) | \(.description)"
  ' "$REPORT"
  echo "---"
  echo "ℹ️  Commit allowed. OPA policy in CI/CD will enforce the final decision."
  echo ""
fi

echo "[CloudSentinel][pre-commit] Done. Report: $REPORT"
exit 0