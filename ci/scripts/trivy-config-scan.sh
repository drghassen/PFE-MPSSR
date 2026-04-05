#!/usr/bin/env bash
set -euo pipefail

trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh
DEFAULT_TRIVY_TARGET="infra/azure/student-secure"
if [ -n "${CI:-}" ]; then
  TRIVY_TARGET_EFF="${DEFAULT_TRIVY_TARGET}"
else
  TRIVY_TARGET_EFF="${TRIVY_TARGET:-${DEFAULT_TRIVY_TARGET}}"
fi
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "config"
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_config_opa.json
chmod -R a+r shift-left/trivy/reports/raw .cloudsentinel/trivy_config_opa.json 2>/dev/null || true
jq -r '"[scan-summary] trivy-config=" + ((.stats.TOTAL // 0) | tostring) + " state=" + (.status // "unknown")' .cloudsentinel/trivy_config_opa.json
