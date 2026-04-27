#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

DOJO_URL_EFF="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
DOJO_API_KEY_EFF="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
DOJO_ENGAGEMENT_ID_RIGHT_EFF="${DOJO_ENGAGEMENT_ID_RIGHT:-${DEFECTDOJO_ENGAGEMENT_ID_RIGHT:-}}"
DOJO_BASE_URL="${DOJO_URL_EFF%/}"
if [[ "$DOJO_BASE_URL" =~ /api/v2$ ]]; then
  IMPORT_SCAN_URL="${DOJO_BASE_URL}/import-scan/"
else
  IMPORT_SCAN_URL="${DOJO_BASE_URL}/api/v2/import-scan/"
fi

source ci/scripts/setup-custom-ca.sh

OUTPUT_DIR=".cloudsentinel"
GENERIC_FINDINGS_FILE="${OUTPUT_DIR}/prowler_generic_findings.json"
CORRELATION_REPORT="${OUTPUT_DIR}/correlation_report.json"
DOJO_RESPONSE_FILE="${OUTPUT_DIR}/dojo-responses/prowler-compliance.json"
AUDIT_FILE="${OUTPUT_DIR}/upload_prowler_audit.jsonl"
ENRICHED_FILE="${GENERIC_FINDINGS_FILE}.enriched"

mkdir -p "${OUTPUT_DIR}/dojo-responses"

sr_init_guard "shift-right/prowler-report" "$AUDIT_FILE"
sr_require_command jq curl
sr_require_env DOJO_URL_EFF DOJO_API_KEY_EFF DOJO_ENGAGEMENT_ID_RIGHT_EFF
sr_require_nonempty_file "$GENERIC_FINDINGS_FILE" "prowler generic findings"
sr_require_nonempty_file "$CORRELATION_REPORT" "correlation report"

sr_require_json "$GENERIC_FINDINGS_FILE" '
  type == "object"
  and (.meta | type == "object")
  and (.findings | type == "array")
  and ((.meta.raw_fail_count // null) | type == "number")
  and ((.meta.normalized_findings_count // null) | type == "number")
' "prowler generic findings"
sr_require_json "$CORRELATION_REPORT" '
  type == "object"
  and (.meta | type == "object")
  and (.correlations | type == "array")
' "correlation report"

FINDING_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.findings | length' 'prowler generic findings')"
RAW_FAIL_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.meta.raw_fail_count' 'prowler generic findings')"
META_NORMALIZED_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.meta.normalized_findings_count' 'prowler generic findings')"
CORRELATION_COUNT="$(sr_json_number "$CORRELATION_REPORT" '.meta.correlations_found' 'correlation report')"

sr_assert_eq "$FINDING_COUNT" "$RAW_FAIL_COUNT" "prowler upload input lost FAIL findings"
sr_assert_eq "$FINDING_COUNT" "$META_NORMALIZED_COUNT" "prowler upload input metadata mismatch"

sr_audit "INFO" "stage_start" "starting DefectDojo upload for prowler findings" "$(jq -cn \
  --arg findings_file "$GENERIC_FINDINGS_FILE" \
  --arg correlation_report "$CORRELATION_REPORT" \
  --arg import_scan_url "$IMPORT_SCAN_URL" \
  --argjson finding_count "$FINDING_COUNT" \
  --argjson correlation_count "$CORRELATION_COUNT" \
  '{findings_file:$findings_file,correlation_report:$correlation_report,import_scan_url:$import_scan_url,finding_count:$finding_count,correlation_count:$correlation_count}')"

if [[ "$CORRELATION_COUNT" -gt 0 ]]; then
  CORR_MAP="$(jq '
    [.correlations[] | {key: .prowler_uid, value: .}]
    | sort_by(
        if .value.combined_risk == "CRITICAL_CONFIRMED" then 0
        elif .value.combined_risk == "HIGH_CONFIRMED" then 1
        else 2
        end
      )
    | unique_by(.key)
    | from_entries
  ' "$CORRELATION_REPORT")"

  jq \
    --argjson corr_map "$CORR_MAP" \
    '
    .findings |= map(
      . as $f |
      ($corr_map[$f.unique_id_from_tool]) as $c |
      if $c != null then
        .description += (
          "\n\nDrift correlation: resource also has active drift "
          + "(address: " + $c.drift_address
          + ", severity: " + $c.drift_severity
          + ", combined_risk: " + $c.combined_risk + ")."
        )
      else . end
    )
    ' "$GENERIC_FINDINGS_FILE" > "$ENRICHED_FILE"
  UPLOAD_FILE="$ENRICHED_FILE"
else
  UPLOAD_FILE="$GENERIC_FINDINGS_FILE"
fi

sr_require_json "$UPLOAD_FILE" 'type == "object" and (.findings | type == "array")' "prowler DefectDojo upload payload"
SCAN_DATE="$(date -u +"%Y-%m-%d")"
HTTP_CODE="$(curl -sS -L --post301 --post302 \
  -o "$DOJO_RESPONSE_FILE" \
  -w "%{http_code}" \
  -X POST "$IMPORT_SCAN_URL" \
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

if [[ "$HTTP_CODE" != "201" ]]; then
  sr_fail "DefectDojo rejected prowler upload" 1 "$(jq -cn --arg http_code "$HTTP_CODE" --arg response_file "$DOJO_RESPONSE_FILE" '{http_code:$http_code,response_file:$response_file}')"
fi

sr_audit "INFO" "stage_complete" "DefectDojo upload for prowler findings completed" "$(jq -cn \
  --arg response_file "$DOJO_RESPONSE_FILE" \
  --arg upload_file "$UPLOAD_FILE" \
  --argjson finding_count "$FINDING_COUNT" \
  --argjson correlation_count "$CORRELATION_COUNT" \
  '{response_file:$response_file,upload_file:$upload_file,finding_count:$finding_count,correlation_count:$correlation_count}')"
