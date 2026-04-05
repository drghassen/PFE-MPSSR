#!/usr/bin/env bash
set -euo pipefail

# =========================
# trivy-image-scan.sh
# =========================

trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh

readonly DEFAULT_TRIVY_IMAGE_TARGET="alpine:3.21"
TRIVY_IMAGE_TARGET_EFF="${DEFAULT_TRIVY_IMAGE_TARGET}"

if [ -z "${TRIVY_IMAGE_TARGET_EFF}" ]; then
  echo "[scan][ERROR] TRIVY_IMAGE_TARGET is empty" >&2
  exit 2
else
  bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_IMAGE_TARGET_EFF}" "image"
fi

chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true

jq -r '"[scan-summary] trivy_image_raw_results=" + (((.Results // []) | length) | tostring)' \
  shift-left/trivy/reports/raw/trivy-image-raw.json
