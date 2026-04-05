#!/usr/bin/env bash
trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh
<<<<<<< HEAD
DEFAULT_TRIVY_TARGET="infra/azure/student-secure"

# [Hardening] Enforce hardcoded targets regardless of environment variables
TRIVY_TARGET_EFF="${DEFAULT_TRIVY_TARGET}"
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "config"
=======
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET}" "config"
>>>>>>> parent of a110374 (shift left)
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_config_opa.json
chmod -R a+r shift-left/trivy/reports/raw .cloudsentinel/trivy_config_opa.json 2>/dev/null || true
jq -r '"[scan-summary] trivy-config=" + ((.stats.TOTAL // 0) | tostring) + " state=" + (.status // "unknown")' .cloudsentinel/trivy_config_opa.json
