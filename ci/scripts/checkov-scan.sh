#!/usr/bin/env bash
checkov --version
mkdir -p .cloudsentinel
chmod +x shift-left/checkov/run-checkov.sh
<<<<<<< HEAD
DEFAULT_SCAN_TARGET="infra/azure/student-secure"
DEFAULT_SKIP_PATHS="infra/azure/student-secure/tests,infra/azure/test/tests,tests/fixtures"

# [Hardening] Enforce hardcoded targets regardless of environment variables
export CHECKOV_SKIP_PATHS="${DEFAULT_SKIP_PATHS}"
SCAN_TARGET_EFF="${DEFAULT_SCAN_TARGET}"
bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET_EFF}"
=======
bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET}"
>>>>>>> parent of a110374 (shift left)
chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_opa.json .cloudsentinel/checkov_scan.log 2>/dev/null || true
jq -r '"[scan-summary] checkov=" + ((.stats.TOTAL // 0) | tostring) + " has_findings=" + ((.has_findings // false) | tostring) + " state=" + (if (.status // "") == "NOT_RUN" then "NOT_RUN" else "OK" end)' .cloudsentinel/checkov_opa.json
