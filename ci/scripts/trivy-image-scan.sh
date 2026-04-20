#!/usr/bin/env bash
set -euo pipefail

# =========================
# trivy-image-scan.sh
# =========================

trivy --version
mkdir -p .cloudsentinel

# 1. Resolve effective image target
if [[ -n "${CI:-}" ]]; then
  if [[ -z "${TRIVY_IMAGE_TARGET:-}" ]]; then
    echo "[scan][ERROR] TRIVY_IMAGE_TARGET must be set in CI mode" >&2
    exit 2
  fi
  TRIVY_IMAGE_TARGET_EFF="$TRIVY_IMAGE_TARGET"
else
  TRIVY_IMAGE_TARGET_EFF="${TRIVY_IMAGE_TARGET:-alpine:3.21}"
fi

# 2. Derive report name
if [[ -n "${TRIVY_IMAGE_REPORT_NAME:-}" ]]; then
  REPORT_NAME="$TRIVY_IMAGE_REPORT_NAME"
else
  _basename="${TRIVY_IMAGE_TARGET_EFF##*/}"
  REPORT_NAME="${_basename%%@*}"
fi

# 3. Create output dir and define report path
mkdir -p shift-left/trivy/reports/raw/image
IMAGE_REPORT_PATH="shift-left/trivy/reports/raw/image/trivy-image-${REPORT_NAME}-raw.json"

# 4. Run scan
TRIVY_IMAGE_OUTPUT_PATH="$IMAGE_REPORT_PATH" \
  bash shift-left/trivy/scripts/run-trivy.sh "$TRIVY_IMAGE_TARGET_EFF" "image"

chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true

jq -r '"[scan-summary] trivy_image_raw_results=" + (((.Results // []) | length) | tostring)' \
  "$IMAGE_REPORT_PATH"
