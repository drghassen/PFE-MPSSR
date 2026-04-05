#!/usr/bin/env bash
set -euo pipefail

checkov --version
mkdir -p .cloudsentinel
chmod +x shift-left/checkov/run-checkov.sh
DEFAULT_SCAN_TARGET="infra/azure/student-secure"
DEFAULT_SKIP_PATHS="infra/azure/student-secure/tests,infra/azure/test/tests,tests/fixtures"
if [ -n "${CI:-}" ]; then
  export CHECKOV_SKIP_PATHS="${DEFAULT_SKIP_PATHS}"
  SCAN_TARGET_EFF="${DEFAULT_SCAN_TARGET}"
else
  export CHECKOV_SKIP_PATHS="${CHECKOV_SKIP_PATHS:-${DEFAULT_SKIP_PATHS}}"
  SCAN_TARGET_EFF="${SCAN_TARGET:-${DEFAULT_SCAN_TARGET}}"
fi
bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET_EFF}"
chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_opa.json .cloudsentinel/checkov_scan.log 2>/dev/null || true
jq -r '"[scan-summary] checkov=" + ((.stats.TOTAL // 0) | tostring) + " has_findings=" + ((.has_findings // false) | tostring) + " state=" + (if (.status // "") == "NOT_RUN" then "NOT_RUN" else "OK" end)' .cloudsentinel/checkov_opa.json
