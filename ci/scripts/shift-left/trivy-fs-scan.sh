#!/usr/bin/env bash
set -euo pipefail

# =========================
# trivy-fs-scan.sh
# =========================

trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel

readonly DEFAULT_TRIVY_TARGET="."
TRIVY_TARGET_EFF="${TRIVY_FS_TARGET:-${TRIVY_TARGET:-${DEFAULT_TRIVY_TARGET}}}"

bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "fs"
python3 ci/libs/cloudsentinel_contracts.py stamp-artifact-metadata \
  --artifact shift-left/trivy/reports/raw/trivy-fs-raw.json \
  --tool trivy \
  --executed-target "${TRIVY_TARGET_EFF}" \
  --scan-status success
chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true

jq -r '"[scan-summary] trivy_fs_raw_results=" + (((.Results // []) | length) | tostring)' \
  shift-left/trivy/reports/raw/trivy-fs-raw.json
