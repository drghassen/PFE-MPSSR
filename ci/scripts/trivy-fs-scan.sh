#!/usr/bin/env bash
trivy --version
mkdir -p shift-left/trivy/reports/raw .cloudsentinel
chmod +x shift-left/trivy/scripts/run-trivy.sh
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET}" "fs"
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_fs_opa.json
chmod -R a+r shift-left/trivy/reports/raw .cloudsentinel/trivy_fs_opa.json 2>/dev/null || true
jq -r '"[scan-summary] trivy-fs=" + ((.stats.TOTAL // 0) | tostring) + " state=" + (.status // "unknown")' .cloudsentinel/trivy_fs_opa.json
