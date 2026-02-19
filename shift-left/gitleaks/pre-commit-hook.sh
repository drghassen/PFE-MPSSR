#!/usr/bin/env bash
set -euo pipefail

############################################
# CloudSentinel Pre-Commit Hook v5.0 (PFE)
############################################

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
REPORT="$REPO_ROOT/.cloudsentinel/gitleaks_opa.json"
SCRIPT_SCAN="$REPO_ROOT/shift-left/gitleaks/run-gitleaks.sh"

echo "[CloudSentinel][pre-commit] Scanning staged files..."

# Configuration locale forcée
export USE_BASELINE="false"
export SCAN_TARGET="staged"
unset CI

# Execution du scan
bash "$SCRIPT_SCAN"

[[ -f "$REPORT" ]] || { echo "[Error] Report not found"; exit 0; }

# Extraction performante des variables en une seule lecture JQ
read -r CRITICAL HIGH TOTAL < <(jq -r '[.stats.CRITICAL // 0, .stats.HIGH // 0, .stats.TOTAL // 0] | @tsv' "$REPORT")

if [[ "$TOTAL" -gt 0 ]]; then
  echo -e "\n⚠️  [CloudSentinel] $TOTAL finding(s) detected (CRITICAL=$CRITICAL, HIGH=$HIGH)"
  echo "-------------------------------------------------------"
  jq -r '.findings[] | "[\(.severity)] \(.file):\(.start_line) | \(.description)"' "$REPORT"
  echo "-------------------------------------------------------"
  echo "Advisory: Please review secrets. OPA will enforce rules in CI/CD."
  echo ""
fi

exit 0