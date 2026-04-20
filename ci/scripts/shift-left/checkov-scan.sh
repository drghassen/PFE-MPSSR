#!/usr/bin/env bash
set -euo pipefail

# =========================
# checkov-scan.sh
# =========================

checkov --version
mkdir -p .cloudsentinel

# Default target is repository root for full-repo IaC coverage.
# Override with CHECKOV_SCAN_TARGET=<path> only for an explicit targeted run.
readonly DEFAULT_SCAN_TARGET="."
SCAN_TARGET_EFF="${CHECKOV_SCAN_TARGET:-${DEFAULT_SCAN_TARGET}}"

TF_FILE_COUNT=$(find "${SCAN_TARGET_EFF}" -name "*.tf" 2>/dev/null | wc -l)
echo "[checkov] scan target=${SCAN_TARGET_EFF} tf_files=${TF_FILE_COUNT}"
if [[ "$TF_FILE_COUNT" -eq 0 ]]; then
  echo "[checkov][WARN] No .tf files found under ${SCAN_TARGET_EFF} — verify CHECKOV_SCAN_TARGET or repository layout." >&2
fi

bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET_EFF}"

chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_scan.log 2>/dev/null || true

jq -r '"[scan-summary] checkov_raw_failed_checks=" + (((.results.failed_checks // []) | length) | tostring)' \
  .cloudsentinel/checkov_raw.json
