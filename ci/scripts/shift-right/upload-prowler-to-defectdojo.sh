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
DOJO_BASE_URL="${DOJO_URL_EFF%/}"
if [[ "${DOJO_BASE_URL}" =~ /api/v2$ ]]; then
  IMPORT_SCAN_URL="${DOJO_BASE_URL}/import-scan/"
else
  IMPORT_SCAN_URL="${DOJO_BASE_URL}/api/v2/import-scan/"
fi

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

command -v jq  >/dev/null 2>&1 || { echo "[dojo-prowler][ERROR] jq is required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "[dojo-prowler][ERROR] curl is required"; exit 1; }

mkdir -p "${OUTPUT_DIR}/dojo-responses"

# ── Guard: missing findings file ──────────────────────────────────────────────
# Reporting jobs are non-blocking by design. If the artifact is missing, publish
# a DEGRADED empty payload and preserve existing DefectDojo history.
if [[ ! -f "${GENERIC_FINDINGS_FILE}" ]]; then
  echo "[dojo-prowler][WARN] Findings file not found: ${GENERIC_FINDINGS_FILE}"
  echo "[dojo-prowler][WARN] Writing DEGRADED empty payload (artifact-missing) and continuing."
  jq -n \
    --arg reason "artifact_missing" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{meta:{mode:"DEGRADED",reason:$reason,timestamp:$ts,tool:"prowler"},findings:[]}' \
    > "${GENERIC_FINDINGS_FILE}"
fi

# ── DEGRADED mode: upload empty findings WITHOUT closing existing records ──────
# If run-prowler.sh wrote a DEGRADED payload (auth failure, network error, etc.),
# we still upload to keep DefectDojo informed, but we MUST NOT close existing
# findings: a transient Azure AD outage must not erase compliance history.
# close_old_findings=false is safe here — findings that were genuinely fixed
# will be closed on the next successful scan.
DEGRADED_MODE="$(jq -r '.meta.mode // "NORMAL"' "${GENERIC_FINDINGS_FILE}")"
CLOSE_OLD_FINDINGS="true"
if [[ "${DEGRADED_MODE}" == "DEGRADED" ]]; then
  DEGRADED_REASON="$(jq -r '.meta.reason // "unknown"' "${GENERIC_FINDINGS_FILE}")"
  echo "[dojo-prowler][WARN] Findings file is in DEGRADED mode (reason: ${DEGRADED_REASON})."
  echo "[dojo-prowler][WARN] Uploading empty findings with close_old_findings=false to preserve history."
  CLOSE_OLD_FINDINGS="false"
  # Rewrite as a valid Generic Findings payload with zero findings.
  jq -n '{findings: []}' > "${GENERIC_FINDINGS_FILE}.upload"
  UPLOAD_FILE="${GENERIC_FINDINGS_FILE}.upload"
else
  UPLOAD_FILE="${GENERIC_FINDINGS_FILE}"
fi

SCAN_DATE="$(date -u +"%Y-%m-%d")"

# ── Correlation enrichment ─────────────────────────────────────────────────────
# If correlate-signals produced a report, annotate each finding whose
# unique_id_from_tool appears in a correlation record. The description field
# receives a drift-correlation note so DefectDojo operators can triage faster.
# This enrichment is best-effort: any error here skips the annotation silently.
CORRELATION_REPORT="${OUTPUT_DIR}/correlation_report.json"
ENRICHED_FILE="${UPLOAD_FILE}.enriched"

if [[ -f "${CORRELATION_REPORT}" ]]; then
  CORR_COUNT="$(jq '.correlations | length' "${CORRELATION_REPORT}" 2>/dev/null || echo 0)"
  if [[ "${CORR_COUNT}" -gt 0 ]]; then
    echo "[dojo-prowler] Applying ${CORR_COUNT} correlation annotation(s) to findings"
    # Build a lookup map: unique_id_from_tool → first matching correlation record.
    # If multiple drift items correlate to the same Prowler finding, take the
    # highest combined_risk (CRITICAL_CONFIRMED > HIGH_CONFIRMED > CORRELATED).
    CORR_MAP="$(jq '
      [.correlations[] | {key: .prowler_uid, value: .}]
      | sort_by(
          if .value.combined_risk == "CRITICAL_CONFIRMED" then 0
          elif .value.combined_risk == "HIGH_CONFIRMED"   then 1
          else 2
          end
        )
      | unique_by(.key)
      | from_entries
    ' "${CORRELATION_REPORT}" 2>/dev/null || echo "{}")"

    jq \
      --argjson corr_map "${CORR_MAP}" \
      '
      .findings |= map(
        . as $f |
        ($corr_map[$f.unique_id_from_tool]) as $c |
        if $c != null then
          .description += (
            "\n\n**⚠ Drift Correlation**: This resource also has an active drift "
            + "finding (address: " + $c.drift_address
            + ", severity: " + $c.drift_severity
            + "). Combined risk: " + $c.combined_risk + "."
          )
        else . end
      )
      ' "${UPLOAD_FILE}" > "${ENRICHED_FILE}" 2>/dev/null \
      && UPLOAD_FILE="${ENRICHED_FILE}" \
      || echo "[dojo-prowler][WARN] Correlation annotation failed — uploading without enrichment"
  fi
fi

FINDING_COUNT="$(jq '.findings | length' "${UPLOAD_FILE}")"
echo "[dojo-prowler] Uploading ${FINDING_COUNT} finding(s) to DefectDojo engagement ${DOJO_ENGAGEMENT_ID_RIGHT_EFF}"

# ── POST to DefectDojo ─────────────────────────────────────────────────────────
# scan_type=Generic Findings Import is the only scan type that accepts our
# custom finding schema with unique_id_from_tool for deduplication.
# close_old_findings=true + deduplication_on_engagement=true ensures that
# resolved misconfigurations (fixed resources) are closed automatically.

HTTP_CODE="$(curl -sS -L --post301 --post302 \
  -o "${DOJO_RESPONSE_FILE}" \
  -w "%{http_code}" \
  -X POST "${IMPORT_SCAN_URL}" \
  -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
  -F "file=@${UPLOAD_FILE}" \
  -F "scan_type=Generic Findings Import" \
  --form-string "engagement=${DOJO_ENGAGEMENT_ID_RIGHT_EFF}" \
  --form-string "test_title=CloudSentinel Prowler Compliance Audit" \
  --form-string "scan_date=${SCAN_DATE}" \
  --form-string "active=true" \
  --form-string "verified=true" \
  --form-string "close_old_findings=${CLOSE_OLD_FINDINGS}" \
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
