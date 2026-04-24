#!/usr/bin/env bash
set -euo pipefail

# CloudSentinel — Artifact Contract Test (detection + normalization)
# Fail-fast guard before OPA decision stage.

expected_scan_id="${CLOUDSENTINEL_SCAN_ID:-${CI_COMMIT_SHA:-}}"
cmd=(
  python3 ci/libs/cloudsentinel_contracts.py validate-artifact-contract
  --contract ci/contracts/artifact_contract.json
  --report-output .cloudsentinel/artifact_contract_report.json
  --golden-schema shift-left/normalizer/schema/cloudsentinel_report.schema.json
  --stage detection
  --stage normalization
)
if [[ -n "${expected_scan_id}" ]]; then
  cmd+=(--expected-scan-id "${expected_scan_id}")
fi

"${cmd[@]}"

echo "[contract] Detection + normalization artifact integrity checks passed."
