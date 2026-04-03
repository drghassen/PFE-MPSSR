#!/usr/bin/env bash
set -euo pipefail

REPORT_PATH="${1:-.cloudsentinel/golden_report.json}"

if [[ ! -f "$REPORT_PATH" ]]; then
  echo "[gate][ERROR] golden report missing: $REPORT_PATH" >&2
  exit 2
fi

jq -e '.scanners | type == "object"' "$REPORT_PATH" >/dev/null

if ! jq -e '.scanners | to_entries | all((.value.status == "OK") or (.value.status == "PASSED"))' "$REPORT_PATH" >/dev/null; then
  echo "[gate][ERROR] at least one scanner is NOT_RUN or invalid." >&2
  jq -r '.scanners | to_entries[] | "\(.key)=\(.value.status)"' "$REPORT_PATH" >&2
  exit 1
fi

if ! jq -e '.summary.global.FAILED == 0' "$REPORT_PATH" >/dev/null; then
  echo "[gate][ERROR] security findings are present. Deployment blocked." >&2
  jq -r '.summary.global' "$REPORT_PATH" >&2
  exit 1
fi

if ! jq -e '[.findings[] | select(.status == "FAILED")] | length == 0' "$REPORT_PATH" >/dev/null; then
  echo "[gate][ERROR] found FAILED findings in normalized report." >&2
  jq -r '[.findings[] | select(.status == "FAILED") | {id:.id,tool:.source.tool,severity:.severity.level,path:.resource.path}]' "$REPORT_PATH" >&2
  exit 1
fi

echo "[gate] zero findings and all scanners OK."
