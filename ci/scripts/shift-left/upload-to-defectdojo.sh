#!/usr/bin/env bash
set -euo pipefail

DOJO_URL_EFF="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
DOJO_API_KEY_EFF="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
DOJO_ENGAGEMENT_ID_EFF="${DOJO_ENGAGEMENT_ID:-${DEFECTDOJO_ENGAGEMENT_ID_LEFT:-}}"
DOJO_ENGAGEMENT_NAME_EFF="${DOJO_ENGAGEMENT_NAME:-${DEFECTDOJO_ENGAGEMENT_NAME:-${DEFECTDOJO_ENGAGEMENT_NAME_LEFT:-}}}"
DOJO_PRODUCT_NAME_EFF="${DOJO_PRODUCT_NAME:-${DEFECTDOJO_PRODUCT_NAME:-}}"
VERIFY_HMAC_SCRIPT="ci/scripts/verify-hmac.sh"
# Optional enterprise PKI bootstrap for DefectDojo TLS.
source ci/scripts/setup-custom-ca.sh
source ci/scripts/shift-left/audit-utils.sh
trap 'cloudsentinel_finalize_audit "$?" "upload-to-defectdojo" "report" "defectdojo" ".cloudsentinel/golden_report.json" ".cloudsentinel/gitleaks_raw.json" ".cloudsentinel/checkov_raw.json" "shift-left/trivy/reports/raw/trivy-fs-raw.json" ".cloudsentinel/cloudinit_analysis.json" ".cloudsentinel/dojo-responses"' EXIT

if [ -z "${DOJO_URL_EFF}" ] || [ -z "${DOJO_API_KEY_EFF}" ] || [ -z "${DOJO_ENGAGEMENT_ID_EFF}" ]; then
  echo "[dojo] Missing Dojo vars. Accepted names:"
  echo "[dojo] URL: DOJO_URL or DEFECTDOJO_URL"
  echo "[dojo] API key: DOJO_API_KEY or DEFECTDOJO_API_KEY or DEFECTDOJO_API_TOKEN"
  echo "[dojo] Engagement: DOJO_ENGAGEMENT_ID or DEFECTDOJO_ENGAGEMENT_ID_LEFT"
  echo "[dojo] Skipping upload."
  exit 0
fi
DOJO_URL_EFF="${DOJO_URL_EFF%/}"
DOJO_REIMPORT_URL="${DOJO_URL_EFF}/api/v2/reimport-scan/"

chmod -R a+r .cloudsentinel shift-left/trivy/reports/raw 2>/dev/null || true
mkdir -p .cloudsentinel/dojo-responses

DOJO_TEST_CONTEXT_EFF="${DOJO_TEST_CONTEXT:-${CI_COMMIT_REF_SLUG:-${CI_COMMIT_BRANCH:-}}}"

dojo_test_title() {
  local scanner_name="$1"
  if [[ -n "${DOJO_TEST_CONTEXT_EFF}" ]]; then
    printf 'CloudSentinel %s (Shift-Left - %s)' "${scanner_name}" "${DOJO_TEST_CONTEXT_EFF}"
  else
    printf 'CloudSentinel %s (Shift-Left)' "${scanner_name}"
  fi
}

dojo_http_success() {
  case "$1" in
    200|201) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_dojo_product_name() {
  if [[ -n "${DOJO_PRODUCT_NAME_EFF}" ]]; then
    return 0
  fi

  local engagement_response=".cloudsentinel/dojo-responses/engagement-context.json"
  local product_response=".cloudsentinel/dojo-responses/product-context.json"
  local http_code product_id product_name

  http_code="$(curl -sS -L -o "${engagement_response}" -w "%{http_code}" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    "${DOJO_URL_EFF}/api/v2/engagements/${DOJO_ENGAGEMENT_ID_EFF}/")"

  if ! dojo_http_success "${http_code}"; then
    echo "[dojo] Unable to resolve product from engagement=${DOJO_ENGAGEMENT_ID_EFF} HTTP=${http_code}" >&2
    cat "${engagement_response}" >&2 || true
    return 1
  fi

  product_name="$(jq -r '
    if (.product | type) == "object" then (.product.name // "")
    else (.product_name // "")
    end
  ' "${engagement_response}")"

  if [[ -n "${product_name}" && "${product_name}" != "null" ]]; then
    DOJO_PRODUCT_NAME_EFF="${product_name}"
    echo "[dojo] Resolved product_name from engagement context: ${DOJO_PRODUCT_NAME_EFF}"
    return 0
  fi

  product_id="$(jq -r '
    if (.product | type) == "number" then (.product | tostring)
    elif (.product | type) == "string" then .product
    else ""
    end
  ' "${engagement_response}")"

  if [[ -z "${product_id}" || "${product_id}" == "null" ]]; then
    echo "[dojo] Engagement context does not contain product name or product id." >&2
    cat "${engagement_response}" >&2 || true
    return 1
  fi

  http_code="$(curl -sS -L -o "${product_response}" -w "%{http_code}" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    "${DOJO_URL_EFF}/api/v2/products/${product_id}/")"

  if ! dojo_http_success "${http_code}"; then
    echo "[dojo] Unable to resolve product id=${product_id} HTTP=${http_code}" >&2
    cat "${product_response}" >&2 || true
    return 1
  fi

  product_name="$(jq -r '.name // ""' "${product_response}")"
  if [[ -z "${product_name}" || "${product_name}" == "null" ]]; then
    echo "[dojo] Product context does not contain a product name." >&2
    cat "${product_response}" >&2 || true
    return 1
  fi

  DOJO_PRODUCT_NAME_EFF="${product_name}"
  echo "[dojo] Resolved product_name from product context: ${DOJO_PRODUCT_NAME_EFF}"
}

resolve_dojo_engagement_name() {
  if [[ -n "${DOJO_ENGAGEMENT_NAME_EFF}" ]]; then
    return 0
  fi

  local engagement_response=".cloudsentinel/dojo-responses/engagement-context.json"
  local http_code engagement_name

  http_code="$(curl -sS -L -o "${engagement_response}" -w "%{http_code}" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    "${DOJO_URL_EFF}/api/v2/engagements/${DOJO_ENGAGEMENT_ID_EFF}/")"

  if ! dojo_http_success "${http_code}"; then
    echo "[dojo] Unable to resolve engagement_name from engagement=${DOJO_ENGAGEMENT_ID_EFF} HTTP=${http_code}" >&2
    cat "${engagement_response}" >&2 || true
    return 1
  fi

  engagement_name="$(jq -r '.name // ""' "${engagement_response}")"
  if [[ -z "${engagement_name}" || "${engagement_name}" == "null" ]]; then
    echo "[dojo] Engagement context does not contain an engagement name." >&2
    cat "${engagement_response}" >&2 || true
    return 1
  fi

  DOJO_ENGAGEMENT_NAME_EFF="${engagement_name}"
  echo "[dojo] Resolved engagement_name from engagement context: ${DOJO_ENGAGEMENT_NAME_EFF}"
}

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
  test_title="$4"
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

  HTTP_CODE=$(curl -sS -L --post301 --post302 -o "${response_file}" -w "%{http_code}" \
    -X POST "${DOJO_REIMPORT_URL}" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    -F "file=@${upload_file_path}" \
    -F "scan_type=${scan_type}" \
    --form-string "product_name=${DOJO_PRODUCT_NAME_EFF}" \
    --form-string "engagement=${DOJO_ENGAGEMENT_ID_EFF}" \
    --form-string "engagement_name=${DOJO_ENGAGEMENT_NAME_EFF}" \
    --form-string "test_title=${test_title}" \
    --form-string "active=true" \
    --form-string "verified=true" \
    --form-string "close_old_findings=true" \
    --form-string "close_old_findings_product_scope=false" \
    --form-string "deduplication_on_engagement=true")

  if dojo_http_success "${HTTP_CODE}"; then
    echo "[dojo] ${label} reimported HTTP=${HTTP_CODE} test_title=${test_title}"
  else
    echo "[dojo] ${label} reimport failed HTTP=${HTTP_CODE}"
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

  local test_title
  test_title="$(dojo_test_title "Cloud-init")"

  HTTP_CODE="$(curl -sS -L --post301 --post302 -o "${response_file}" -w "%{http_code}" \
    -X POST "${DOJO_REIMPORT_URL}" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    -F "file=@${generic_file}" \
    -F "scan_type=Generic Findings Import" \
    --form-string "product_name=${DOJO_PRODUCT_NAME_EFF}" \
    --form-string "engagement=${DOJO_ENGAGEMENT_ID_EFF}" \
    --form-string "engagement_name=${DOJO_ENGAGEMENT_NAME_EFF}" \
    --form-string "test_title=${test_title}" \
    --form-string "scan_date=${scan_date}" \
    --form-string "active=true" \
    --form-string "verified=true" \
    --form-string "close_old_findings=true" \
    --form-string "close_old_findings_product_scope=false" \
    --form-string "deduplication_on_engagement=true" \
    --form-string "minimum_severity=Info")"

  if dojo_http_success "${HTTP_CODE}"; then
    echo "[dojo] ${label} reimported HTTP=${HTTP_CODE} (findings=${findings_count}) test_title=${test_title}"
  else
    echo "[dojo] ${label} reimport failed HTTP=${HTTP_CODE}"
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

if ! resolve_dojo_product_name; then
  echo "[dojo] Missing product_name. Set DOJO_PRODUCT_NAME or DEFECTDOJO_PRODUCT_NAME, or ensure the API key can read engagement/product context." >&2
  exit 1
fi

if ! resolve_dojo_engagement_name; then
  echo "[dojo] Missing engagement_name. Set DOJO_ENGAGEMENT_NAME or DEFECTDOJO_ENGAGEMENT_NAME, or ensure the API key can read engagement context." >&2
  exit 1
fi

# Shift-Left scanners
upload_scan ".cloudsentinel/gitleaks_raw.json"                "Gitleaks Scan" "Gitleaks"       "$(dojo_test_title "Gitleaks")"
upload_scan ".cloudsentinel/checkov_raw.json"                 "Checkov Scan"  "Checkov"        "$(dojo_test_title "Checkov")"
upload_scan "shift-left/trivy/reports/raw/trivy-fs-raw.json"  "Trivy Scan"    "Trivy (FS/SCA)" "$(dojo_test_title "Trivy FS/SCA")"
upload_cloudinit_generic_findings
