#!/usr/bin/env bash
set -euo pipefail

gitleaks version
mkdir -p .cloudsentinel
bash shift-left/gitleaks/run-gitleaks.sh
python3 ci/libs/cloudsentinel_contracts.py stamp-artifact-metadata \
  --artifact .cloudsentinel/gitleaks_raw.json \
  --tool gitleaks \
  --executed-target "${SCAN_TARGET:-repo}" \
  --scan-status success
if [[ -f .cloudsentinel/gitleaks_range_raw.json ]]; then
  python3 ci/libs/cloudsentinel_contracts.py stamp-artifact-metadata \
    --artifact .cloudsentinel/gitleaks_range_raw.json \
    --tool gitleaks \
    --executed-target "${SCAN_TARGET:-repo}" \
    --scan-status success
fi

if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
  python3 ci/scripts/shift-left/artifact_hmac.py sign .cloudsentinel/gitleaks_raw.json
  if [[ -f .cloudsentinel/gitleaks_range_raw.json ]]; then
    python3 ci/scripts/shift-left/artifact_hmac.py sign .cloudsentinel/gitleaks_range_raw.json
  fi
elif [[ -n "${CI:-}" ]]; then
  echo "[gitleaks][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
  exit 1
else
  echo "[gitleaks][WARN] CLOUDSENTINEL_HMAC_SECRET not set — skipping HMAC signing (non-CI mode)."
fi

chmod a+r .cloudsentinel/gitleaks_raw.json .cloudsentinel/gitleaks_raw.json.hmac .cloudsentinel/gitleaks_range_raw.json .cloudsentinel/gitleaks_range_raw.json.hmac 2>/dev/null || true

IGNORE_FILE="shift-left/gitleaks/.gitleaksignore"
if [[ -f "$IGNORE_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    IFS=':' read -ra parts <<< "$line"
    if [[ "${#parts[@]}" -lt 4 ]]; then
      echo "[gitleaks][GOVERNANCE] FAIL: malformed .gitleaksignore entry (expected fingerprint:ticket:expiry:justification): $line" >&2
      exit 1
    fi
    expiry="${parts[2]}"
    if [[ -n "$expiry" ]] && [[ "$expiry" < "$(date +%Y-%m-%d)" ]]; then
      echo "[gitleaks][GOVERNANCE] FAIL: expired suppression in .gitleaksignore: $line" >&2
      exit 1
    fi
  done < "$IGNORE_FILE"
  echo "[gitleaks][GOVERNANCE] .gitleaksignore governance check passed."
fi
jq -r '"[scan-summary] gitleaks_raw_findings=" + (((.findings // []) | length)|tostring)' .cloudsentinel/gitleaks_raw.json
