#!/usr/bin/env bash
set -euo pipefail

# =========================
# checkov-scan.sh
# =========================

source ci/scripts/shift-left/audit-utils.sh
trap 'cloudsentinel_finalize_audit "$?" "checkov-scan" "scan" "checkov" ".cloudsentinel/checkov_raw.json" ".cloudsentinel/checkov_scan.log"' EXIT

checkov --version
mkdir -p .cloudsentinel
cloudsentinel_invalidate_downstream_artifacts

# Default target is the active IaC root. This avoids scanning generated
# artifacts/caches while preserving Terraform module coverage through
# shift-left/checkov/run-checkov.sh's module-library pass.
if [[ -d "infra/azure" ]]; then
  readonly DEFAULT_SCAN_TARGET="infra/azure"
else
  readonly DEFAULT_SCAN_TARGET="."
fi
# Override with CHECKOV_SCAN_TARGET=<path> only for an explicit targeted run.
SCAN_TARGET_EFF="${CHECKOV_SCAN_TARGET:-${DEFAULT_SCAN_TARGET}}"

TF_FILE_COUNT=$(find "${SCAN_TARGET_EFF}" -name "*.tf" 2>/dev/null | wc -l)
echo "[checkov] scan target=${SCAN_TARGET_EFF} tf_files=${TF_FILE_COUNT}"
if [[ "$TF_FILE_COUNT" -eq 0 ]]; then
  echo "[checkov][WARN] No .tf files found under ${SCAN_TARGET_EFF} — verify CHECKOV_SCAN_TARGET or repository layout." >&2
fi

bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET_EFF}"
python3 ci/libs/cloudsentinel_contracts.py stamp-artifact-metadata \
  --artifact .cloudsentinel/checkov_raw.json \
  --tool checkov \
  --executed-target "${SCAN_TARGET_EFF}" \
  --scan-status success

if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
  python3 ci/scripts/shift-left/artifact_hmac.py sign .cloudsentinel/checkov_raw.json
elif [[ -n "${CI:-}" ]]; then
  echo "[checkov][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
  exit 1
else
  echo "[checkov][WARN] CLOUDSENTINEL_HMAC_SECRET not set — skipping HMAC signing (non-CI mode)."
fi

chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_raw.json.hmac .cloudsentinel/checkov_scan.log 2>/dev/null || true

jq -r '"[scan-summary] checkov_raw_failed_checks=" + (((.results.failed_checks // []) | length) | tostring)' \
  .cloudsentinel/checkov_raw.json
