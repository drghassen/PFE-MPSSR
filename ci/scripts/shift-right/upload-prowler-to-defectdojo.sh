#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CloudSentinel CI — Upload Prowler Compliance Findings to DefectDojo
#
# Reads .cloudsentinel/prowler_generic_findings.json (written by run-prowler.sh)
# and posts it to DefectDojo via Generic Findings Import.
#
# Deduplication key: unique_id_from_tool = "prowler:{check_id}:{resource_uid}"
# close_old_findings=true closes findings whose resources no longer exist in Azure.
#
# This job mirrors upload-drift-to-defectdojo.sh and runs in the same CI stage
# (report). The two uploads are independent and can run in parallel.
# =============================================================================

DOJO_URL_EFF="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
DOJO_API_KEY_EFF="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
DOJO_ENGAGEMENT_ID_RIGHT_EFF="${DOJO_ENGAGEMENT_ID_RIGHT:-${DEFECTDOJO_ENGAGEMENT_ID_RIGHT:-}}"

# Enterprise PKI bootstrap — trusts private DefectDojo TLS certificates.
# Reads CLOUDSENTINEL_CUSTOM_CA_PEM_B64 or CLOUDSENTINEL_CUSTOM_CA_PEM if set.
source ci/scripts/setup-custom-ca.sh

GENERIC_FINDINGS_FILE=".cloudsentinel/prowler_generic_findings.json"
OUTPUT_DIR=".cloudsentinel"
DOJO_RESPONSE_FILE="${OUTPUT_DIR}/dojo-responses/prowler-compliance.json"

# ── Guard: missing DefectDojo config ──────────────────────────────────────────
# Warn and skip (exit 0) rather than exit 1 so a missing DOJO var doesn't
# fail a job that is already allow_failure: true. Mirrors drift upload pattern.
if [[ -z "${DOJO_URL_EFF}" || -z "${DOJO_API_KEY_EFF}" || -z "${DOJO_ENGAGEMENT_ID_RIGHT_EFF}" ]]; then
  echo "[dojo-prowler] Missing DefectDojo connection vars. Accepted names:"
  echo "[dojo-prowler]   URL       : DOJO_URL or DEFECTDOJO_URL"
  echo "[dojo-prowler]   API key   : DOJO_API_KEY or DEFECTDOJO_API_KEY or DEFECTDOJO_API_TOKEN"
  echo "[dojo-prowler]   Engagement: DOJO_ENGAGEMENT_ID_RIGHT or DEFECTDOJO_ENGAGEMENT_ID_RIGHT"
  echo "[dojo-prowler] Skipping upload."
  exit 0
fi

# ── Guard: missing findings file ──────────────────────────────────────────────
# If run-prowler.sh didn't produce the file at all (e.g. runner crashed before
# writing DEGRADED), fail loudly so the missing artifact is visible in CI.
if [[ ! -f "${GENERIC_FINDINGS_FILE}" ]]; then
  echo "[dojo-prowler][ERROR] Findings file not found: ${GENERIC_FINDINGS_FILE}"
  echo "[dojo-prowler][ERROR] Did prowler-audit artifact upload succeed?"
  exit 1
fi

command -v jq  >/dev/null 2>&1 || { echo "[dojo-prowler][ERROR] jq is required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "[dojo-prowler][ERROR] curl is required"; exit 1; }

mkdir -p "${OUTPUT_DIR}/dojo-responses"

# ── DEGRADED mode: upload empty findings to close stale records ───────────────
# If run-prowler.sh wrote a DEGRADED payload, we still upload it.
# DefectDojo with close_old_findings=true will close findings that no longer
# appear — which is the correct behaviour when the sensor couldn't scan.
DEGRADED_MODE="$(jq -r '.meta.mode // "NORMAL"' "${GENERIC_FINDINGS_FILE}")"
if [[ "${DEGRADED_MODE}" == "DEGRADED" ]]; then
  DEGRADED_REASON="$(jq -r '.meta.reason // "unknown"' "${GENERIC_FINDINGS_FILE}")"
  echo "[dojo-prowler][WARN] Findings file is in DEGRADED mode (reason: ${DEGRADED_REASON})."
  echo "[dojo-prowler][WARN] Uploading empty findings set to keep DefectDojo state consistent."
  # Rewrite as a valid Generic Findings payload with zero findings.
  jq -n '{findings: []}' > "${GENERIC_FINDINGS_FILE}.upload"
  UPLOAD_FILE="${GENERIC_FINDINGS_FILE}.upload"
else
  UPLOAD_FILE="${GENERIC_FINDINGS_FILE}"
fi

SCAN_DATE="$(date -u +"%Y-%m-%d")"
FINDING_COUNT="$(jq '.findings | length' "${UPLOAD_FILE}")"
echo "[dojo-prowler] Uploading ${FINDING_COUNT} finding(s) to DefectDojo engagement ${DOJO_ENGAGEMENT_ID_RIGHT_EFF}"

# ── POST to DefectDojo ─────────────────────────────────────────────────────────
# scan_type=Generic Findings Import is the only scan type that accepts our
# custom finding schema with unique_id_from_tool for deduplication.
# close_old_findings=true + deduplication_on_engagement=true ensures that
# resolved misconfigurations (fixed resources) are closed automatically.

HTTP_CODE="$(curl -sS \
  -o "${DOJO_RESPONSE_FILE}" \
  -w "%{http_code}" \
  -X POST "${DOJO_URL_EFF}/api/v2/import-scan/" \
  -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
  -F "file=@${UPLOAD_FILE}" \
  -F "scan_type=Generic Findings Import" \
  --form-string "engagement=${DOJO_ENGAGEMENT_ID_RIGHT_EFF}" \
  --form-string "test_title=CloudSentinel Prowler Compliance Audit" \
  --form-string "scan_date=${SCAN_DATE}" \
  --form-string "active=true" \
  --form-string "verified=true" \
  --form-string "close_old_findings=true" \
  --form-string "close_old_findings_product_scope=false" \
  --form-string "deduplication_on_engagement=true" \
  --form-string "minimum_severity=Info")"

if [[ "${HTTP_CODE}" == "201" ]]; then
  echo "[dojo-prowler] Upload successful HTTP=201 (${FINDING_COUNT} finding(s))"
elif [[ "${HTTP_CODE}" == "400" ]]; then
  echo "[dojo-prowler][ERROR] DefectDojo rejected the payload (HTTP 400 — bad request)."
  echo "[dojo-prowler][ERROR] Response body:"
  cat "${DOJO_RESPONSE_FILE}" || true
  exit 1
else
  echo "[dojo-prowler][ERROR] Unexpected HTTP response: ${HTTP_CODE}"
  cat "${DOJO_RESPONSE_FILE}" || true
  exit 1
fi
