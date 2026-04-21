#!/usr/bin/env bash
set -euo pipefail

UP_TO="decision"
REPORT_OUTPUT="${CLOUDSENTINEL_ARTIFACT_CONTRACT_REPORT:-.cloudsentinel/artifact_contract_report.json}"
CONTRACT_FILE="${CLOUDSENTINEL_ARTIFACT_CONTRACT_FILE:-ci/contracts/artifact_contract.json}"
EXPECTED_SCAN_ID="${CLOUDSENTINEL_SCAN_ID:-${CI_COMMIT_SHA:-}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --up-to)
      [[ $# -ge 2 ]] || { echo "[artifact-integrity][ERROR] --up-to requires a value" >&2; exit 2; }
      UP_TO="$2"
      shift 2
      ;;
    --report-output)
      [[ $# -ge 2 ]] || { echo "[artifact-integrity][ERROR] --report-output requires a value" >&2; exit 2; }
      REPORT_OUTPUT="$2"
      shift 2
      ;;
    --contract)
      [[ $# -ge 2 ]] || { echo "[artifact-integrity][ERROR] --contract requires a value" >&2; exit 2; }
      CONTRACT_FILE="$2"
      shift 2
      ;;
    --expected-scan-id)
      [[ $# -ge 2 ]] || { echo "[artifact-integrity][ERROR] --expected-scan-id requires a value" >&2; exit 2; }
      EXPECTED_SCAN_ID="$2"
      shift 2
      ;;
    *)
      echo "[artifact-integrity][ERROR] unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$UP_TO" in
  detection)
    STAGES=("detection")
    ;;
  normalization)
    STAGES=("detection" "normalization")
    ;;
  decision)
    STAGES=("detection" "normalization" "decision")
    ;;
  *)
    echo "[artifact-integrity][ERROR] --up-to must be 'detection', 'normalization' or 'decision'" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$REPORT_OUTPUT")"

cmd=(
  python3 ci/libs/cloudsentinel_contracts.py validate-artifact-contract
  --contract "$CONTRACT_FILE"
  --report-output "$REPORT_OUTPUT"
  --golden-schema shift-left/normalizer/schema/cloudsentinel_report.schema.json
)

if [[ -n "$EXPECTED_SCAN_ID" ]]; then
  cmd+=(--expected-scan-id "$EXPECTED_SCAN_ID")
fi

for st in "${STAGES[@]}"; do
  cmd+=(--stage "$st")
done

"${cmd[@]}"

jq -r '
  "[artifact-integrity] status=" + (.status // "unknown") +
  " checked=" + ((.summary.artifacts_checked // 0)|tostring) +
  " failed=" + ((.summary.failed_artifacts // 0)|tostring)
' "$REPORT_OUTPUT"
