#!/usr/bin/env bash
set -euo pipefail

DOJO_URL_EFF="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
DOJO_API_KEY_EFF="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
DOJO_ENGAGEMENT_ID_EFF="${DOJO_ENGAGEMENT_ID:-${DEFECTDOJO_ENGAGEMENT_ID:-}}"

REPORT_PATH="${DRIFT_REPORT_PATH:-shift-right/drift-engine/output/drift-report.json}"
OUTPUT_DIR=".cloudsentinel"
GENERIC_FINDINGS_FILE="${OUTPUT_DIR}/drift_generic_findings.json"
DOJO_RESPONSE_FILE="${OUTPUT_DIR}/dojo-responses/drift-engine.json"

if [ -z "${DOJO_URL_EFF}" ] || [ -z "${DOJO_API_KEY_EFF}" ] || [ -z "${DOJO_ENGAGEMENT_ID_EFF}" ]; then
  echo "[dojo-drift] Missing Dojo vars. Accepted names:"
  echo "[dojo-drift] URL: DOJO_URL or DEFECTDOJO_URL"
  echo "[dojo-drift] API key: DOJO_API_KEY or DEFECTDOJO_API_KEY or DEFECTDOJO_API_TOKEN"
  echo "[dojo-drift] Engagement: DOJO_ENGAGEMENT_ID or DEFECTDOJO_ENGAGEMENT_ID"
  echo "[dojo-drift] Skipping upload."
  exit 0
fi

if [ ! -f "${REPORT_PATH}" ]; then
  echo "[dojo-drift][ERROR] Drift report not found: ${REPORT_PATH}"
  exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "[dojo-drift][ERROR] jq is required"; exit 1; }

mkdir -p "${OUTPUT_DIR}/dojo-responses"

SCAN_DATE="$(jq -r '.cloudsentinel.finished_at // .ocsf.time // now | tostring | .[0:10]' "${REPORT_PATH}")"
RUN_ID="$(jq -r '.cloudsentinel.run_id // "unknown"' "${REPORT_PATH}")"

jq -c \
  --arg scan_date "${SCAN_DATE}" \
  --arg run_id "${RUN_ID}" \
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
      (.drift.items // [])[] |
      {
        title: ("Terraform drift detected: " + ((.address // "unknown") | tostring)),
        severity: normalize_severity(.severity),
        date: $scan_date,
        description:
          ("CloudSentinel shift-right drift finding\n"
          + "- Run ID: " + $run_id + "\n"
          + "- Address: " + ((.address // "unknown") | tostring) + "\n"
          + "- Resource type: " + ((.type // "unknown") | tostring) + "\n"
          + "- Actions: " + (((.actions // []) | tostring)) + "\n"
          + "- Action required: " + ((.action_required // "none") | tostring) + "\n"
          + "- Changed paths: " + (((.changed_paths // []) | tostring))),
        mitigation: "Reconcile Terraform state and cloud state or apply approved exception.",
        references: ("CloudSentinel Drift Report run_id=" + $run_id)
      }
    ]
  }' "${REPORT_PATH}" > "${GENERIC_FINDINGS_FILE}"

HTTP_CODE="$(curl -sS -o "${DOJO_RESPONSE_FILE}" -w "%{http_code}" \
  -X POST "${DOJO_URL_EFF}/api/v2/import-scan/" \
  -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
  -F "file=@${GENERIC_FINDINGS_FILE}" \
  -F "scan_type=Generic Findings Import" \
  --form-string "engagement=${DOJO_ENGAGEMENT_ID_EFF}" \
  --form-string "test_title=CloudSentinel Drift Engine (Shift-Right)" \
  --form-string "scan_date=${SCAN_DATE}" \
  --form-string "active=true" \
  --form-string "verified=true" \
  --form-string "close_old_findings=true" \
  --form-string "close_old_findings_product_scope=false" \
  --form-string "deduplication_on_engagement=true" \
  --form-string "minimum_severity=Info")"

if [ "${HTTP_CODE}" = "201" ]; then
  echo "[dojo-drift] Drift report uploaded HTTP=201"
else
  echo "[dojo-drift][ERROR] Upload failed HTTP=${HTTP_CODE}"
  cat "${DOJO_RESPONSE_FILE}" || true
  exit 1
fi
