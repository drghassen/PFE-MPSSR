#!/usr/bin/env bash
set -euo pipefail

python3 shift-left/cloudinit-scanner/cloudinit_scan.py \
  --terraform-dir . \
  --output .cloudsentinel/cloudinit_analysis.json \
  --default-env "${CI_ENVIRONMENT_NAME:-dev}"

if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
  python3 ci/scripts/shift-left/artifact_hmac.py sign .cloudsentinel/cloudinit_analysis.json
elif [[ -n "${CI:-}" ]]; then
  echo "[cloudinit][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
  exit 1
else
  echo "[cloudinit][WARN] CLOUDSENTINEL_HMAC_SECRET not set — skipping HMAC signing (non-CI mode)."
fi

chmod a+r .cloudsentinel/cloudinit_analysis.json .cloudsentinel/cloudinit_analysis.json.hmac 2>/dev/null || true
