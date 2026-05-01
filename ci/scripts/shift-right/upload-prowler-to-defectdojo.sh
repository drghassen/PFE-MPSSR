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

REPORT_PATH="${PROWLER_REPORT_PATH:-shift-right/prowler/output/prowler-report.json}"
OPA_DECISION_PATH="${OPA_PROWLER_DECISION_PATH:-.cloudsentinel/opa_prowler_decision.json}"
OUTPUT_DIR=".cloudsentinel"
GENERIC_FINDINGS_FILE="${OUTPUT_DIR}/prowler_generic_findings.json"
DOJO_RESPONSE_FILE="${OUTPUT_DIR}/dojo-responses/prowler.json"
AUDIT_FILE="${OUTPUT_DIR}/upload_prowler_audit.jsonl"
PROWLER_UPLOAD_DRY_RUN="${PROWLER_UPLOAD_DRY_RUN:-false}"

mkdir -p "${OUTPUT_DIR}/dojo-responses"

sr_init_guard "shift-right/prowler-report" "$AUDIT_FILE"
sr_require_command jq curl
if [[ "$PROWLER_UPLOAD_DRY_RUN" != "true" ]]; then
  sr_require_env DOJO_URL_EFF DOJO_API_KEY_EFF DOJO_ENGAGEMENT_ID_RIGHT_EFF
fi
sr_require_nonempty_file "$REPORT_PATH" "prowler report"
sr_require_nonempty_file "$OPA_DECISION_PATH" "OPA prowler decision"

sr_require_json "$REPORT_PATH" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.prowler | type == "object")
  and (.prowler.items | type == "array")
  and (.prowler.summary | type == "object")
  and (.errors | type == "array")
' "prowler report"

sr_require_json "$OPA_DECISION_PATH" '
  type == "object"
  and (.result | type == "object")
  and ((.result.violations // null) | type == "array")
' "OPA prowler decision"

REPORT_ERROR_COUNT="$(sr_json_number "$REPORT_PATH" '.errors | length' 'prowler report')"
PROWLER_ITEM_COUNT="$(sr_json_number "$REPORT_PATH" '.prowler.items | length' 'prowler report')"
PROWLER_FAIL_COUNT="$(sr_json_number "$REPORT_PATH" '.prowler.summary.fail_count' 'prowler report')"
OPA_RAW_VIOLATIONS="$(sr_json_number "$OPA_DECISION_PATH" '(.result.violations | length)' 'OPA prowler decision')"
OPA_EFFECTIVE_VIOLATIONS="$(sr_json_number "$OPA_DECISION_PATH" '((.result.effective_violations // .result.violations) | length)' 'OPA prowler decision')"

if [[ "$REPORT_ERROR_COUNT" -gt 0 ]]; then
  sr_fail "prowler report contains errors; refusing DefectDojo upload" 1 "$(jq -cn --argjson report_error_count "$REPORT_ERROR_COUNT" '{report_error_count:$report_error_count}')"
fi
sr_assert_eq "$PROWLER_ITEM_COUNT" "$PROWLER_FAIL_COUNT" "prowler upload input mismatch between report item count and fail count"
sr_assert_eq "$OPA_RAW_VIOLATIONS" "$PROWLER_ITEM_COUNT" "prowler upload input mismatch between report and OPA decision"

SCAN_DATE="$(jq -r '.cloudsentinel.finished_at // now | tostring | .[0:10]' "$REPORT_PATH")"
RUN_ID="$(jq -r '.cloudsentinel.run_id // "unknown"' "$REPORT_PATH")"
CORRELATION_ID="$(jq -r '.cloudsentinel.correlation_id // .cloudsentinel.run_id // "unknown"' "$REPORT_PATH")"

EFFECTIVE_DECISION_MAP="$(jq '
  (.result.effective_violations // .result.violations // [])
  | map(select(.check_id != null and .resource_id != null and .check_id != "" and .resource_id != ""))
  | map({ key: (.check_id + "|" + .resource_id), value: . })
  | from_entries
' "$OPA_DECISION_PATH")"

EFFECTIVE_MAP="$(jq '
  (.result.effective_violations // .result.violations // [])
  | map(select(.check_id != null and .resource_id != null and .check_id != "" and .resource_id != ""))
  | map({ key: (.check_id + "|" + .resource_id), value: true })
  | from_entries
' "$OPA_DECISION_PATH")"

sr_audit "INFO" "stage_start" "starting DefectDojo upload for prowler findings" "$(sr_build_details \
  --arg  import_scan_url "$IMPORT_SCAN_URL" \
  --arg  engagement_id "$DOJO_ENGAGEMENT_ID_RIGHT_EFF" \
  --arg  dry_run "$PROWLER_UPLOAD_DRY_RUN" \
  --argjson prowler_findings "$PROWLER_ITEM_COUNT" \
  --argjson opa_raw_violations "$OPA_RAW_VIOLATIONS" \
  --argjson opa_effective_violations "$OPA_EFFECTIVE_VIOLATIONS" \
  '{
    upload_target: {
      url: $import_scan_url,
      engagement_id: $engagement_id,
      scan_type: "Generic Findings Import",
      dry_run: ($dry_run == "true")
    },
    payload: {
      prowler_findings: $prowler_findings,
      opa_raw_violations: $opa_raw_violations,
      opa_effective_violations: $opa_effective_violations
    }
  }')"

jq -c \
  --arg scan_date "$SCAN_DATE" \
  --arg run_id "$RUN_ID" \
  --arg correlation_id "$CORRELATION_ID" \
  --argjson effective_decisions "$EFFECTIVE_DECISION_MAP" \
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
      (.prowler.items // [])[] as $item |
      (($item.check_id // "") + "|" + ($item.resource_id // "")) as $k |
      select($effective_map[$k]) |
      ($effective_decisions[$k] // error("missing_opa_effective_violation:" + $k)) as $decision |
      {
        title: ("Prowler finding: " + (($item.check_id // "unknown") | tostring)),
        vuln_id_from_tool: ("prowler_check:" + (($item.check_id // "unknown") | tostring)),
        component_name: (($item.resource_id // "unknown") | tostring),
        unique_id_from_tool: ("cloudsentinel-prowler:" + (($item.check_id // "unknown") | tostring) + ":" + (($item.resource_id // "unknown") | tostring)),
        active: true,
        severity: normalize_severity($decision.severity),
        date: $scan_date,
        description:
          ("CloudSentinel shift-right prowler finding\n"
          + "- Run ID: " + $run_id + "\n"
          + "- Correlation ID: " + $correlation_id + "\n"
          + "- Check ID: " + (($item.check_id // "unknown") | tostring) + "\n"
          + "- Resource ID: " + (($item.resource_id // "unknown") | tostring) + "\n"
          + "- Resource type: " + (($item.resource_type // "unknown") | tostring) + "\n"
          + "- Region: " + (($item.region // "global") | tostring) + "\n"
          + "- OPA severity: " + (($decision.severity // "UNKNOWN") | tostring) + "\n"
          + "- OPA response_type: " + (($decision.response_type // $decision.action_required // "unknown") | tostring) + "\n"
          + "- OPA requires_remediation: " + (($decision.requires_remediation // false) | tostring) + "\n"
          + "- OPA effective: true\n"
          + "- OPA reason: " + (($decision.reason // "") | tostring)),
        mitigation: "Apply cloud hardening control or approved exception.",
        references: ("CloudSentinel Prowler Report run_id=" + $run_id + " correlation_id=" + $correlation_id)
      }
    ]
  }
' "$REPORT_PATH" > "$GENERIC_FINDINGS_FILE"

sr_require_json "$GENERIC_FINDINGS_FILE" 'type == "object" and (.findings | type == "array")' "prowler generic findings"
GENERATED_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.findings | length' 'prowler generic findings')"
sr_assert_eq "$GENERATED_COUNT" "$OPA_EFFECTIVE_VIOLATIONS" "prowler upload effective findings count mismatch with OPA decision"
sr_assert_positive_if_expected "$OPA_EFFECTIVE_VIOLATIONS" "$GENERATED_COUNT" "prowler upload generated zero effective findings from non-empty effective OPA input"

if [[ "$PROWLER_UPLOAD_DRY_RUN" == "true" ]]; then
  jq -cn \
    --arg status "dry_run" \
    --argjson findings_uploaded "$GENERATED_COUNT" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{status:$status, findings_uploaded:$findings_uploaded, generated_at:$generated_at}' > "$DOJO_RESPONSE_FILE"
  HTTP_CODE="DRY_RUN"
else
  HTTP_CODE="$(curl -sS -L --post301 --post302 \
    -o "$DOJO_RESPONSE_FILE" \
    -w "%{http_code}" \
    -X POST "$IMPORT_SCAN_URL" \
    -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
    -F "file=@${GENERIC_FINDINGS_FILE}" \
    -F "scan_type=Generic Findings Import" \
    --form-string "engagement=${DOJO_ENGAGEMENT_ID_RIGHT_EFF}" \
    --form-string "test_title=CloudSentinel Prowler (Shift-Right)" \
    --form-string "scan_date=${SCAN_DATE}" \
    --form-string "verified=true" \
    --form-string "close_old_findings=true" \
    --form-string "close_old_findings_product_scope=false" \
    --form-string "deduplication_on_engagement=true" \
    --form-string "minimum_severity=Info")"

  if [[ "$HTTP_CODE" != "201" ]]; then
    sr_fail "DefectDojo rejected prowler upload" 1 "$(jq -cn --arg http_code "$HTTP_CODE" --arg response_file "$DOJO_RESPONSE_FILE" '{http_code:$http_code,response_file:$response_file}')"
  fi
fi

sr_audit "INFO" "stage_complete" "DefectDojo upload for prowler findings completed" "$(sr_build_details \
  --arg  http_code "$HTTP_CODE" \
  --arg  dry_run "$PROWLER_UPLOAD_DRY_RUN" \
  --argjson findings_uploaded "$GENERATED_COUNT" \
  --argjson prowler_input_count "$PROWLER_ITEM_COUNT" \
  --arg  response_file "$DOJO_RESPONSE_FILE" \
  --arg  generic_findings_file "$GENERIC_FINDINGS_FILE" \
  '{
    result: {
      status: "success",
      http_code: $http_code,
      dry_run: ($dry_run == "true"),
      findings_uploaded: $findings_uploaded,
      prowler_input_count: $prowler_input_count
    },
    artifacts: {
      dojo_response: $response_file,
      generic_findings: $generic_findings_file
    }
  }')"
