#!/usr/bin/env bash
set -euo pipefail

# CloudSentinel — Artifact Contract Test (detection + normalization)
# Fail-fast guard before OPA decision stage.

source ci/scripts/shift-left/audit-utils.sh
trap 'cloudsentinel_finalize_audit "$?" "contract-test" "contract" "artifact-contract" ".cloudsentinel/gitleaks_raw.json" ".cloudsentinel/checkov_raw.json" "shift-left/trivy/reports/raw/trivy-fs-raw.json" ".cloudsentinel/cloudinit_analysis.json" ".cloudsentinel/golden_report.json" ".cloudsentinel/exceptions.json" ".cloudsentinel/audit_events.jsonl" ".cloudsentinel/artifact_contract_report.json"' EXIT

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
