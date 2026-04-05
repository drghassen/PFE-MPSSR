#!/usr/bin/env bash
gitleaks version
mkdir -p .cloudsentinel
export USE_BASELINE="false"
chmod +x shift-left/gitleaks/run-gitleaks.sh
bash shift-left/gitleaks/run-gitleaks.sh
chmod a+r .cloudsentinel/gitleaks_raw.json .cloudsentinel/gitleaks_opa.json 2>/dev/null || true
jq -r '"[scan-summary] gitleaks=" + ((.stats.TOTAL // 0) | tostring) + " has_findings=" + ((.has_findings // false) | tostring) + " state=" + (if (.status // "") == "NOT_RUN" then "NOT_RUN" else "OK" end)' .cloudsentinel/gitleaks_opa.json
