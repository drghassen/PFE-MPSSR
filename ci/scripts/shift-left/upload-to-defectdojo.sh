#!/usr/bin/env bash
set -euo pipefail

DOJO_URL_EFF="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
DOJO_API_KEY_EFF="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
DOJO_ENGAGEMENT_ID_EFF="${DOJO_ENGAGEMENT_ID:-${DEFECTDOJO_ENGAGEMENT_ID_LEFT:-}}"
VERIFY_HMAC_SCRIPT="ci/scripts/verify-hmac.sh"
# Optional enterprise PKI bootstrap for DefectDojo TLS.
source ci/scripts/setup-custom-ca.sh

if [ -z "${DOJO_URL_EFF}" ] || [ -z "${DOJO_API_KEY_EFF}" ] || [ -z "${DOJO_ENGAGEMENT_ID_EFF}" ]; then
  echo "[dojo] Missing Dojo vars. Accepted names:"
  echo "[dojo] URL: DOJO_URL or DEFECTDOJO_URL"
  echo "[dojo] API key: DOJO_API_KEY or DEFECTDOJO_API_KEY or DEFECTDOJO_API_TOKEN"
  echo "[dojo] Engagement: DOJO_ENGAGEMENT_ID or DEFECTDOJO_ENGAGEMENT_ID_LEFT"
  echo "[dojo] Skipping upload."
  exit 0
fi

chmod -R a+r .cloudsentinel shift-left/trivy/reports/raw 2>/dev/null || true
mkdir -p .cloudsentinel/dojo-responses

verify_artifact_integrity() {
  local file_path="$1"
  local label="$2"
  if ! bash "${VERIFY_HMAC_SCRIPT}" "${file_path}"; then
    echo "[dojo] ${label}: artifact integrity verification failed (${file_path})." >&2
    return 1
  fi
}

upload_scan() {
  file_path="$1"
  scan_type="$2"
  label="$3"
  upload_file_path="$file_path"
  safe_label="$(echo "${label}" | tr ' /()' '_____' | tr -cd '[:alnum:]_.-')"
  response_file=".cloudsentinel/dojo-responses/${safe_label}.json"

  if [ ! -f "${file_path}" ]; then
    echo "[dojo] ${label}: report not found (${file_path}), skipping."
    return 0
  fi

  if [ ! -r "${file_path}" ]; then
    echo "[dojo] ${label}: report exists but is not readable (${file_path})."
    ls -l "${file_path}" || true
    return 1
  fi

  verify_artifact_integrity "${file_path}" "${label}"

  if [ "${scan_type}" = "Gitleaks Scan" ]; then
    if jq -e 'type == "object" and (.findings | type == "array")' "${file_path}" >/dev/null 2>&1; then
      upload_file_path=".cloudsentinel/dojo-responses/${safe_label}.gitleaks-findings.json"
      jq '.findings' "${file_path}" > "${upload_file_path}"
    fi
    if ! jq -e 'type == "array" and all(.[]; ((.CloudSentinelSecretHash // .SecretHash // "") | type == "string" and test("^[0-9a-f]{64}$")))' "${upload_file_path}" >/dev/null 2>&1; then
      echo "[dojo] ${label}: invalid findings payload, CloudSentinelSecretHash is required on all findings."
      return 1
    fi
  fi

  if ! jq empty "${upload_file_path}" >/dev/null 2>&1; then
    echo "[dojo] ${label}: invalid JSON payload (${upload_file_path}), skipping upload."
    return 1
  fi

  HTTP_CODE=$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -X POST "${DOJO_URL_EFF}/api/v2/import-scan/" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    -F "file=@${upload_file_path}" \
    -F "scan_type=${scan_type}" \
    --form-string "engagement=${DOJO_ENGAGEMENT_ID_EFF}" \
    --form-string "active=true" \
    --form-string "verified=true" \
    --form-string "close_old_findings=true" \
    --form-string "close_old_findings_product_scope=false" \
    --form-string "deduplication_on_engagement=true")

  if [ "${HTTP_CODE}" = "201" ]; then
    echo "[dojo] ${label} uploaded HTTP=201"
  else
    echo "[dojo] ${label} upload failed HTTP=${HTTP_CODE}"
    cat "${response_file}" || true
    return 1
  fi
}

upload_cloudinit_generic_findings() {
  local file_path=".cloudsentinel/cloudinit_analysis.json"
  local label="Cloud-init"
  local generic_file=".cloudsentinel/dojo-responses/cloudinit-generic-findings.json"
  local response_file=".cloudsentinel/dojo-responses/cloudinit-generic-response.json"

  if [[ ! -f "${file_path}" ]]; then
    echo "[dojo] ${label}: report not found (${file_path}), skipping."
    return 0
  fi

  verify_artifact_integrity "${file_path}" "${label}"

  if ! jq -e '
    type == "object"
    and (.resources_analyzed | type == "array")
    and (.summary | type == "object")
  ' "${file_path}" >/dev/null 2>&1; then
    echo "[dojo] ${label}: invalid cloudinit_analysis structure, skipping."
    return 1
  fi

  local scan_date
  scan_date="$(jq -r '(.generated_at // now | tostring)[0:10]' "${file_path}")"
  local scan_id
  scan_id="$(jq -r '.scan_id // ""' "${file_path}")"

  jq -c \
    --arg scan_date "${scan_date}" \
    --arg scan_id "${scan_id}" \
    '
    def normalize_severity($s):
      if ($s // "" | ascii_downcase) == "critical" then "Critical"
      elif ($s // "" | ascii_downcase) == "high" then "High"
      elif ($s // "" | ascii_downcase) == "medium" then "Medium"
      elif ($s // "" | ascii_downcase) == "low" then "Low"
      elif ($s // "" | ascii_downcase) == "info" then "Info"
      else "Medium"
      end;
    {
      findings: [
        (.resources_analyzed // [])[] as $r
        | ($r.violations // [])[]
        | {
            title: ("Cloud-init violation: " + ((.rule // "unknown") | tostring)),
            vuln_id_from_tool: ((.rule // "unknown") | tostring),
            component_name: (($r.resource_address // $r.resource_name // "unknown") | tostring),
            unique_id_from_tool:
              (
                "cloudinit:"
                + ((.rule // "unknown") | tostring) + ":"
                + (($r.resource_address // "unknown") | tostring) + ":"
                + (($r.file // "unknown") | tostring) + ":"
                + (($r.line // 0) | tostring)
              ),
            severity: normalize_severity(.severity),
            date: $scan_date,
            description:
              (
                "CloudSentinel cloud-init finding\n"
                + "- Rule: " + ((.rule // "unknown") | tostring) + "\n"
                + "- Resource: " + (($r.resource_address // "unknown") | tostring) + "\n"
                + "- File: " + (($r.file // "unknown") | tostring) + ":" + (($r.line // 0) | tostring) + "\n"
                + "- Environment: " + (($r.environment // "unknown") | tostring) + "\n"
                + "- Message: " + ((.message // "n/a") | tostring) + "\n"
                + "- Non waivable in prod: " + ((.non_waivable_in_prod // false) | tostring) + "\n"
                + "- Block: " + ((.block // false) | tostring) + "\n"
                + (if ($scan_id | length) > 0 then "- Scan ID: " + $scan_id else "- Scan ID: n/a" end)
              ),
            mitigation:
              "Harden cloud-init bootstrap script and align resource intent/tagging before deployment.",
            references:
              (
                "CloudSentinel cloudinit_analysis.json"
                + (if ($scan_id | length) > 0 then " scan_id=" + $scan_id else "" end)
              )
          }
      ]
    }' "${file_path}" > "${generic_file}"

  local findings_count
  findings_count="$(jq -r '(.findings // []) | length' "${generic_file}")"
  if [[ "${findings_count}" -eq 0 ]]; then
    echo "[dojo] ${label}: no violations to upload (findings=0)."
    return 0
  fi

  HTTP_CODE="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -X POST "${DOJO_URL_EFF}/api/v2/import-scan/" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    -F "file=@${generic_file}" \
    -F "scan_type=Generic Findings Import" \
    --form-string "engagement=${DOJO_ENGAGEMENT_ID_EFF}" \
    --form-string "test_title=CloudSentinel Cloud-init (Shift-Left)" \
    --form-string "scan_date=${scan_date}" \
    --form-string "active=true" \
    --form-string "verified=true" \
    --form-string "close_old_findings=true" \
    --form-string "close_old_findings_product_scope=false" \
    --form-string "deduplication_on_engagement=true" \
    --form-string "minimum_severity=Info")"

  if [[ "${HTTP_CODE}" = "201" ]]; then
    echo "[dojo] ${label} uploaded HTTP=201 (findings=${findings_count})"
  else
    echo "[dojo] ${label} upload failed HTTP=${HTTP_CODE}"
    cat "${response_file}" || true
    return 1
  fi
}

validate_optional_json_artifact() {
  local file_path="$1"
  local label="$2"
  if [[ ! -f "$file_path" ]]; then
    echo "[dojo] ${label}: not found (${file_path}), skipping."
    return 0
  fi
  if ! jq empty "$file_path" >/dev/null 2>&1; then
    echo "[dojo] ${label}: invalid JSON (${file_path}), skipping."
    return 1
  fi
  echo "[dojo] ${label}: present + valid JSON."
  return 0
}

# Golden report is not uploaded to DefectDojo, but we keep a safe guard so CI never
# attempts to treat missing/invalid normalization artifacts as upload candidates.
validate_optional_json_artifact ".cloudsentinel/golden_report.json" "golden_report"
if [[ -f ".cloudsentinel/golden_report.json" ]]; then
  verify_artifact_integrity ".cloudsentinel/golden_report.json" "golden_report"
fi

# Shift-Left scanners
upload_scan ".cloudsentinel/gitleaks_raw.json"                                       "Gitleaks Scan" "Gitleaks"
upload_scan ".cloudsentinel/checkov_raw.json"                                        "Checkov Scan"  "Checkov"
upload_scan "shift-left/trivy/reports/raw/trivy-fs-raw.json"                        "Trivy Scan"    "Trivy (FS/SCA)"
upload_scan "shift-left/trivy/reports/raw/trivy-config-raw.json"                    "Trivy Scan"    "Trivy (Config)"
upload_cloudinit_generic_findings
