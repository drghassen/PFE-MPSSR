#!/usr/bin/env bash
set -euo pipefail

# =========================
# checkov-scan.sh
# =========================

checkov --version
mkdir -p .cloudsentinel
chmod +x shift-left/checkov/run-checkov.sh

# Default target is the infra/ root so all Terraform modules are discovered
# automatically — adding infra/azure/prod-secure or any sibling never requires
# a manual script update. Override with CHECKOV_SCAN_TARGET=<path> when a
# targeted scan is needed (e.g. local dev on a single module).
readonly DEFAULT_SCAN_TARGET="infra"
SCAN_TARGET_EFF="${CHECKOV_SCAN_TARGET:-${DEFAULT_SCAN_TARGET}}"

TF_FILE_COUNT=$(find "${SCAN_TARGET_EFF}" -name "*.tf" 2>/dev/null | wc -l)
echo "[checkov] scan target=${SCAN_TARGET_EFF} tf_files=${TF_FILE_COUNT}"
if [[ "$TF_FILE_COUNT" -eq 0 ]]; then
  echo "[checkov][WARN] No .tf files found under ${SCAN_TARGET_EFF} — verify CHECKOV_SCAN_TARGET or infra layout." >&2
fi

bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET_EFF}"

chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_scan.log 2>/dev/null || true

jq -r '"[scan-summary] checkov_raw_failed_checks=" + (((.results.failed_checks // []) | length) | tostring)' \
  .cloudsentinel/checkov_raw.json
