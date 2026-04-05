#!/usr/bin/env bash
set -euo pipefail

# =========================
# trivy-config-scan.sh
# =========================

trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh

# Hardcoded Trivy target
readonly DEFAULT_TRIVY_TARGET="infra/azure/student-secure"
TRIVY_TARGET_EFF="${DEFAULT_TRIVY_TARGET}"

bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "config"
chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true

jq -r '"[scan-summary] trivy_config_raw_results=" + (((.Results // []) | length) | tostring)' \
  shift-left/trivy/reports/raw/trivy-config-raw.json
