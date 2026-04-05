#!/usr/bin/env bash
set -euo pipefail

gitleaks version
mkdir -p .cloudsentinel
chmod +x shift-left/gitleaks/run-gitleaks.sh
bash shift-left/gitleaks/run-gitleaks.sh
chmod a+r .cloudsentinel/gitleaks_raw.json 2>/dev/null || true
jq -r '"[scan-summary] gitleaks_raw_findings=" + (length|tostring)' .cloudsentinel/gitleaks_raw.json
