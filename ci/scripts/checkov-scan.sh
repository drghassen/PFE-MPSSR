#!/usr/bin/env bash
set -euo pipefail

# =========================
# checkov-scan.sh
# =========================

checkov --version
mkdir -p .cloudsentinel
chmod +x shift-left/checkov/run-checkov.sh

# Hardcoded scan target / skip paths
readonly DEFAULT_SCAN_TARGET="infra/azure/student-secure"
SCAN_TARGET_EFF="${DEFAULT_SCAN_TARGET}"

bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET_EFF}"

chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_scan.log 2>/dev/null || true

jq -r '"[scan-summary] checkov_raw_failed_checks=" + (((.results.failed_checks // []) | length) | tostring)' \
  .cloudsentinel/checkov_raw.json
