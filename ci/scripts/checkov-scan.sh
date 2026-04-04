#!/usr/bin/env bash
checkov --version
mkdir -p .cloudsentinel
chmod +x shift-left/checkov/run-checkov.sh
bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET}"
chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_opa.json .cloudsentinel/checkov_scan.log 2>/dev/null || true
jq -r '"[scan-summary] checkov=" + ((.stats.TOTAL // 0) | tostring) + " has_findings=" + ((.has_findings // false) | tostring) + " state=" + (if (.status // "") == "NOT_RUN" then "NOT_RUN" else "OK" end)' .cloudsentinel/checkov_opa.json
