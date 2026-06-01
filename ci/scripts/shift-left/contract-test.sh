#!/usr/bin/env bash
set -euo pipefail

# CloudSentinel — Artifact Contract Test (detection + normalization)
# Fail-fast guard before OPA decision stage.

source ci/scripts/shift-left/audit-utils.sh
trap 'cloudsentinel_finalize_audit "$?" "contract-test" "contract" "artifact-contract" ".cloudsentinel/gitleaks_raw.json" ".cloudsentinel/checkov_raw.json" "shift-left/trivy/reports/raw/trivy-fs-raw.json" ".cloudsentinel/cloudinit_analysis.json" ".cloudsentinel/golden_report.json" ".cloudsentinel/exceptions.json" ".cloudsentinel/audit_events.jsonl" ".cloudsentinel/artifact_contract_report.json"' EXIT

print_line() {
  printf '%s\n' '==============================================================================='
}

print_contract_header() {
  print_line
  printf 'CloudSentinel Contract Test\n'
  print_line
  printf 'Purpose : Validate scanner artifacts and Golden Report before OPA decision\n'
  printf 'Scope   : detection + normalization\n'
  printf 'Mode    : fail-closed artifact contract\n'
  printf 'Report  : .cloudsentinel/artifact_contract_report.json\n'
  print_line
}

print_contract_summary() {
  local report_file=".cloudsentinel/artifact_contract_report.json"
  local golden_file=".cloudsentinel/golden_report.json"
  local status checked failed stages scan_id

  if [[ ! -s "$report_file" ]]; then
    printf '[contract][summary] report missing: %s\n' "$report_file" >&2
    return 1
  fi

  status="$(jq -r '.status // "unknown"' "$report_file")"
  checked="$(jq -r '.summary.artifacts_checked // 0' "$report_file")"
  failed="$(jq -r '.summary.failed_artifacts // 0' "$report_file")"
  stages="$(jq -r '.selected_stages | join(", ")' "$report_file")"
  scan_id="$(jq -r '.expected_scan_id // ""' "$report_file")"

  printf '\n'
  print_line
  printf 'Contract Result Summary\n'
  print_line
  printf 'Status              : %s\n' "$status"
  printf 'Validated stages    : %s\n' "$stages"
  printf 'Artifacts checked   : %s\n' "$checked"
  printf 'Failed artifacts    : %s\n' "$failed"
  printf 'Correlation scan_id : %s\n' "${scan_id:-not-resolved}"
  print_line

  printf '%-24s %-10s %-10s %-14s %s\n' \
    'Artifact' 'Status' 'Findings' 'HMAC' 'Path'
  printf '%-24s %-10s %-10s %-14s %s\n' \
    '--------' '------' '--------' '----' '----'
  jq -r '
    .stages[]
    | .artifacts[]
    | [
        (.id // "unknown"),
        (.status // "unknown"),
        ((.details.findings_count // .details.results_count // "-") | tostring),
        (.details.hmac_verification // "-"),
        (.path // "-")
      ]
    | @tsv
  ' "$report_file" | while IFS=$'\t' read -r artifact artifact_status findings hmac path; do
    printf '%-24s %-10s %-10s %-14s %s\n' \
      "$artifact" "$artifact_status" "$findings" "$hmac" "$path"
  done
  print_line

  if [[ -s "$golden_file" ]]; then
    printf 'Golden Report Scanner Summary\n'
    print_line
    printf '%-12s %-10s %8s %8s %8s %8s %8s\n' \
      'Scanner' 'Status' 'Total' 'Critical' 'High' 'Medium' 'Low'
    printf '%-12s %-10s %8s %8s %8s %8s %8s\n' \
      '-------' '------' '-----' '--------' '----' '------' '---'
    jq -r '
      (.summary.by_tool // {})
      | to_entries[]
      | [
          .key,
          (.value.status // "unknown"),
          ((.value.TOTAL // 0) | tostring),
          ((.value.CRITICAL // 0) | tostring),
          ((.value.HIGH // 0) | tostring),
          ((.value.MEDIUM // 0) | tostring),
          ((.value.LOW // 0) | tostring)
        ]
      | @tsv
    ' "$golden_file" | while IFS=$'\t' read -r scanner scanner_status total critical high medium low; do
      printf '%-12s %-10s %8s %8s %8s %8s %8s\n' \
        "$scanner" "$scanner_status" "$total" "$critical" "$high" "$medium" "$low"
    done
    print_line
    printf 'OPA input quality   : schema, scan_id correlation, scanner status, audit log\n'
    printf 'Decision ownership  : OPA only; scanners remain advisory\n'
    print_line
  fi
}

print_contract_header

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

set +e
"${cmd[@]}"
contract_rc=$?
set -e

print_contract_summary || true

if [[ "$contract_rc" -ne 0 ]]; then
  echo "[contract] Detection + normalization artifact integrity checks failed." >&2
  exit "$contract_rc"
fi

echo "[contract] Detection + normalization artifact integrity checks passed."
