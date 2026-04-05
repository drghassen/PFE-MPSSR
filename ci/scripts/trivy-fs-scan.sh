#!/usr/bin/env bash
set -euo pipefail

# =========================
# trivy-fs-scan.sh
# =========================

trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh

readonly DEFAULT_TRIVY_TARGET="infra/azure/student-secure"
readonly DEFAULT_TRIVY_SKIP_DIRS="infra/azure/student-secure/tests,infra/azure/test/tests,tests/fixtures"

export TRIVY_SKIP_DIRS="${DEFAULT_TRIVY_SKIP_DIRS}"
TRIVY_TARGET_EFF="${DEFAULT_TRIVY_TARGET}"

bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "fs"
chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true

jq -r '"[scan-summary] trivy_fs_raw_results=" + (((.Results // []) | length) | tostring)' \
  shift-left/trivy/reports/raw/trivy-fs-raw.json
