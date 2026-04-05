#!/usr/bin/env bash
set -euo pipefail

trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh
DEFAULT_TRIVY_IMAGE_TARGET="alpine:3.21"

# [Hardening] Enforce hardcoded targets regardless of environment variables
TRIVY_IMAGE_TARGET_EFF="${DEFAULT_TRIVY_IMAGE_TARGET}"
if [ -z "${TRIVY_IMAGE_TARGET_EFF:-}" ]; then
  echo "[scan] TRIVY_IMAGE_TARGET is empty -> emitting NOT_RUN for image scan"
  bash shift-left/trivy/scripts/run-trivy.sh
else
  bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_IMAGE_TARGET_EFF}" "image"
fi
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_image_opa.json
chmod -R a+r shift-left/trivy/reports/raw .cloudsentinel/trivy_image_opa.json 2>/dev/null || true
jq -r '"[scan-summary] trivy-image=" + ((.stats.TOTAL // 0) | tostring) + " state=" + (.status // "unknown")' .cloudsentinel/trivy_image_opa.json
