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

REPORT_PATH="${DRIFT_REPORT_PATH:-shift-right/drift-engine/output/drift-report.json}"
OPA_DECISION_PATH="${OPA_DRIFT_DECISION_PATH:-.cloudsentinel/opa_drift_decision.json}"
OUTPUT_DIR=".cloudsentinel"
GENERIC_FINDINGS_FILE="${OUTPUT_DIR}/drift_generic_findings.json"
DOJO_RESPONSE_FILE="${OUTPUT_DIR}/dojo-responses/drift-engine.json"
AUDIT_FILE="${OUTPUT_DIR}/upload_drift_audit.jsonl"

mkdir -p "${OUTPUT_DIR}/dojo-responses"

sr_init_guard "shift-right/drift-report" "$AUDIT_FILE"
sr_require_command jq curl
sr_require_env DOJO_URL_EFF DOJO_API_KEY_EFF DOJO_ENGAGEMENT_ID_RIGHT_EFF
sr_require_nonempty_file "$REPORT_PATH" "drift report"
sr_require_nonempty_file "$OPA_DECISION_PATH" "OPA drift decision"

sr_require_json "$REPORT_PATH" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.drift | type == "object")
  and (.drift.items | type == "array")
  and (.errors | type == "array")
' "drift report"
sr_require_json "$OPA_DECISION_PATH" '
  type == "object"
  and (.result | type == "object")
  and ((.result.violations // null) | type == "array")
' "OPA drift decision"

REPORT_ERROR_COUNT="$(sr_json_number "$REPORT_PATH" '.errors | length' 'drift report')"
DRIFT_COUNT="$(sr_json_number "$REPORT_PATH" '.drift.items | length' 'drift report')"
OPA_RAW_VIOLATIONS="$(sr_json_number "$OPA_DECISION_PATH" '(.result.violations | length)' 'OPA drift decision')"
OPA_EFFECTIVE_VIOLATIONS="$(sr_json_number "$OPA_DECISION_PATH" '((.result.effective_violations // .result.violations) | length)' 'OPA drift decision')"

if [[ "$REPORT_ERROR_COUNT" -gt 0 ]]; then
  sr_fail "drift report contains errors; refusing DefectDojo upload" 1 "$(jq -cn --argjson report_error_count "$REPORT_ERROR_COUNT" '{report_error_count:$report_error_count}')"
fi
sr_assert_eq "$OPA_RAW_VIOLATIONS" "$DRIFT_COUNT" "drift upload input mismatch between report and OPA decision"

SCAN_DATE="$(jq -r '.cloudsentinel.finished_at // .ocsf.time | tostring | .[0:10]' "$REPORT_PATH")"
RUN_ID="$(jq -r '.cloudsentinel.run_id // "unknown"' "$REPORT_PATH")"
CORRELATION_ID="$(jq -r '.cloudsentinel.correlation_id // .cloudsentinel.run_id // "unknown"' "$REPORT_PATH")"
VIOLATION_MAP="$(jq '
  (.result.violations // [])
  | map(select(.resource_id != null and .resource_id != ""))
  | map({ key: .resource_id, value: . })
  | from_entries
' "$OPA_DECISION_PATH")"
EFFECTIVE_MAP="$(jq '
  (.result.effective_violations // .result.violations // [])
  | map(select(.resource_id != null and .resource_id != ""))
  | map({ key: .resource_id, value: true })
  | from_entries
' "$OPA_DECISION_PATH")"

sr_audit "INFO" "stage_start" "starting DefectDojo upload for drift findings" "$(sr_build_details \
  --arg  import_scan_url       "$IMPORT_SCAN_URL" \
  --arg  engagement_id         "$DOJO_ENGAGEMENT_ID_RIGHT_EFF" \
  --argjson drift_findings     "$DRIFT_COUNT" \
  --argjson opa_raw_violations "$OPA_RAW_VIOLATIONS" \
  --argjson opa_effective_violations "$OPA_EFFECTIVE_VIOLATIONS" \
  '{
    upload_target: {
      url:           $import_scan_url,
      engagement_id: $engagement_id,
      scan_type:     "Generic Findings Import"
    },
    payload: {
      drift_findings:        $drift_findings,
      opa_raw_violations:    $opa_raw_violations,
      opa_effective_violations: $opa_effective_violations
    }
  }')"

jq -c \
  --arg scan_date "$SCAN_DATE" \
  --arg run_id "$RUN_ID" \
  --arg correlation_id "$CORRELATION_ID" \
  --argjson violations "$VIOLATION_MAP" \
  --argjson effective_map "$EFFECTIVE_MAP" \
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
      (.drift.items // [])[] as $item |
      ($violations[$item.address] // error("missing_opa_violation:" + ($item.address // "unknown"))) as $decision |
      {
        title: ("Terraform drift detected: " + (($item.address // "unknown") | tostring)),
        vuln_id_from_tool: ("drift_type:" + (($item.type // "unknown") | tostring)),
        component_name: (($item.address // "unknown") | tostring),
        unique_id_from_tool: ("cloudsentinel-drift:" + (($item.type // "unknown") | tostring) + ":" + (($item.address // "unknown") | tostring)),
        severity: normalize_severity($decision.severity),
        date: $scan_date,
        description:
          ("CloudSentinel shift-right drift finding\n"
          + "- Run ID: " + $run_id + "\n"
          + "- Correlation ID: " + $correlation_id + "\n"
          + "- Address: " + (($item.address // "unknown") | tostring) + "\n"
          + "- Resource type: " + (($item.type // "unknown") | tostring) + "\n"
          + "- Actions: " + ((($item.actions // []) | tostring)) + "\n"
          + "- Changed paths: " + ((($item.changed_paths // []) | tostring)) + "\n"
          + "- OPA severity: " + (($decision.severity // "UNKNOWN") | tostring) + "\n"
          + "- OPA response_type: " + (($decision.response_type // $decision.action_required // "unknown") | tostring) + "\n"
          + "- OPA requires_remediation: " + (($decision.requires_remediation // false) | tostring) + "\n"
          + "- OPA effective: " + ((if $effective_map[$item.address] then "true" else "false" end)) + "\n"
          + "- OPA reason: " + (($decision.reason // "") | tostring)),
        mitigation: "Reconcile Terraform state and cloud state or apply approved exception.",
        references: ("CloudSentinel Drift Report run_id=" + $run_id + " correlation_id=" + $correlation_id)
      }
    ]
  }' "$REPORT_PATH" > "$GENERIC_FINDINGS_FILE"

sr_require_json "$GENERIC_FINDINGS_FILE" 'type == "object" and (.findings | type == "array")' "drift generic findings"
GENERATED_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.findings | length' 'drift generic findings')"
sr_assert_eq "$GENERATED_COUNT" "$DRIFT_COUNT" "drift upload lost findings during report conversion"
sr_assert_positive_if_expected "$DRIFT_COUNT" "$GENERATED_COUNT" "drift upload generated zero findings from non-empty drift input"

HTTP_CODE="$(curl -sS -L --post301 --post302 \
  -o "$DOJO_RESPONSE_FILE" \
  -w "%{http_code}" \
  -X POST "$IMPORT_SCAN_URL" \
  -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
  -F "file=@${GENERIC_FINDINGS_FILE}" \
  -F "scan_type=Generic Findings Import" \
  --form-string "engagement=${DOJO_ENGAGEMENT_ID_RIGHT_EFF}" \
  --form-string "test_title=CloudSentinel Drift Engine (Shift-Right)" \
  --form-string "scan_date=${SCAN_DATE}" \
  --form-string "active=true" \
  --form-string "verified=true" \
  --form-string "close_old_findings=true" \
  --form-string "close_old_findings_product_scope=false" \
  --form-string "deduplication_on_engagement=true" \
  --form-string "minimum_severity=Info")"

if [[ "$HTTP_CODE" != "201" ]]; then
  sr_fail "DefectDojo rejected drift upload" 1 "$(jq -cn --arg http_code "$HTTP_CODE" --arg response_file "$DOJO_RESPONSE_FILE" '{http_code:$http_code,response_file:$response_file}')"
fi

sr_audit "INFO" "stage_complete" "DefectDojo upload for drift findings completed" "$(sr_build_details \
  --arg  http_code             "$HTTP_CODE" \
  --argjson findings_uploaded  "$GENERATED_COUNT" \
  --argjson drift_input_count  "$DRIFT_COUNT" \
  --arg  response_file         "$DOJO_RESPONSE_FILE" \
  --arg  generic_findings_file "$GENERIC_FINDINGS_FILE" \
  '{
    result: {
      status:           "success",
      http_code:        $http_code,
      findings_uploaded: $findings_uploaded,
      drift_input_count: $drift_input_count
    },
    artifacts: {
      dojo_response:    $response_file,
      generic_findings: $generic_findings_file
    }
  }')"
