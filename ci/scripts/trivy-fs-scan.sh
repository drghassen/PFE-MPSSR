#!/usr/bin/env bash
set -euo pipefail

trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh
DEFAULT_TRIVY_TARGET="infra/azure/student-secure"
DEFAULT_TRIVY_SKIP_DIRS="infra/azure/student-secure/tests,infra/azure/test/tests,tests/fixtures"

# [Hardening] Enforce hardcoded targets regardless of environment variables
export TRIVY_SKIP_DIRS="${DEFAULT_TRIVY_SKIP_DIRS}"
TRIVY_TARGET_EFF="${DEFAULT_TRIVY_TARGET}"
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "fs"
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_fs_opa.json
chmod -R a+r shift-left/trivy/reports/raw .cloudsentinel/trivy_fs_opa.json 2>/dev/null || true
jq -r '"[scan-summary] trivy-fs=" + ((.stats.TOTAL // 0) | tostring) + " state=" + (.status // "unknown")' .cloudsentinel/trivy_fs_opa.json
