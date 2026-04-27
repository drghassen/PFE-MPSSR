#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

PROWLER_FINDINGS="${PROWLER_FINDINGS_PATH:-.cloudsentinel/prowler_generic_findings.json}"
DRIFT_REPORT="${DRIFT_REPORT_PATH:-shift-right/drift-engine/output/drift-report.json}"
OPA_PROWLER_DECISION="${OPA_PROWLER_DECISION_PATH:-.cloudsentinel/opa_prowler_decision.json}"
OPA_DRIFT_DECISION="${OPA_DRIFT_DECISION_PATH:-.cloudsentinel/opa_drift_decision.json}"
MAPPINGS_FILE="${CORRELATION_MAPPINGS_PATH:-ci/scripts/shift-right/correlation_mappings.json}"
OUTPUT_DIR="${CORRELATION_OUTPUT_DIR:-.cloudsentinel}"
CORRELATION_REPORT="${OUTPUT_DIR}/correlation_report.json"
CORRELATION_ENV="${OUTPUT_DIR}/correlation.env"
AUDIT_FILE="${OUTPUT_DIR}/correlation_audit.jsonl"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/correlation" "$AUDIT_FILE"
sr_require_command jq sha256sum
sr_require_nonempty_file "$PROWLER_FINDINGS" "prowler findings"
sr_require_nonempty_file "$DRIFT_REPORT" "drift report"
sr_require_nonempty_file "$OPA_PROWLER_DECISION" "OPA prowler decision"
sr_require_nonempty_file "$OPA_DRIFT_DECISION" "OPA drift decision"
sr_require_nonempty_file "$MAPPINGS_FILE" "correlation mappings"

sr_require_json "$PROWLER_FINDINGS" '
  type == "object"
  and (.meta | type == "object")
  and (.findings | type == "array")
  and ((.meta.raw_fail_count // null) | type == "number")
' "prowler findings"
sr_require_json "$DRIFT_REPORT" '
  type == "object"
  and (.drift | type == "object")
  and (.drift.items | type == "array")
  and (.errors | type == "array")
' "drift report"
sr_require_json "$OPA_PROWLER_DECISION" '
  type == "object"
  and (.result | type == "object")
  and ((.result.metrics.total // null) | type == "number")
' "OPA prowler decision"
sr_require_json "$OPA_DRIFT_DECISION" '
  type == "object"
  and (.result | type == "object")
  and ((.result.violations // null) | type == "array")
' "OPA drift decision"
sr_require_json "$MAPPINGS_FILE" 'type == "object"' "correlation mappings"

REPORT_ERROR_COUNT="$(sr_json_number "$DRIFT_REPORT" '.errors | length' 'drift report')"
if [[ "$REPORT_ERROR_COUNT" -gt 0 ]]; then
  sr_fail "drift report contains errors; refusing correlation" 1 "$(jq -cn --argjson report_error_count "$REPORT_ERROR_COUNT" '{report_error_count:$report_error_count}')"
fi

PROWLER_COUNT="$(sr_json_number "$PROWLER_FINDINGS" '.findings | length' 'prowler findings')"
PROWLER_RAW_FAIL_COUNT="$(sr_json_number "$PROWLER_FINDINGS" '.meta.raw_fail_count' 'prowler findings')"
DRIFT_COUNT="$(sr_json_number "$DRIFT_REPORT" '.drift.items | length' 'drift report')"
OPA_PROWLER_TOTAL="$(sr_json_number "$OPA_PROWLER_DECISION" '.result.metrics.total' 'OPA prowler decision')"
OPA_DRIFT_TOTAL="$(sr_json_number "$OPA_DRIFT_DECISION" '(.result.violations | length)' 'OPA drift decision')"

sr_assert_eq "$PROWLER_COUNT" "$PROWLER_RAW_FAIL_COUNT" "correlation input mismatch: prowler normalized count differs from raw FAIL count"
sr_assert_eq "$OPA_PROWLER_TOTAL" "$PROWLER_COUNT" "correlation input mismatch: OPA prowler total differs from findings count"
sr_assert_eq "$OPA_DRIFT_TOTAL" "$DRIFT_COUNT" "correlation input mismatch: OPA drift total differs from drift item count"

PROWLER_FINDINGS_DATA="$(jq -c '.findings' "$PROWLER_FINDINGS")"
DRIFT_ITEMS_DATA="$(jq -c '.drift.items' "$DRIFT_REPORT")"
DRIFT_SEVERITY_MAP="$(jq '
  (.result.effective_violations // [])
  | map(select(.resource_id != null and .resource_id != ""))
  | map({ key: .resource_id, value: (.severity // "MEDIUM") })
  | from_entries
' "$OPA_DRIFT_DECISION")"
MAPPINGS="$(jq -c '.' "$MAPPINGS_FILE")"

sr_audit "INFO" "stage_start" "starting cross-signal correlation" "$(jq -cn \
  --arg prowler_findings "$PROWLER_FINDINGS" \
  --arg drift_report "$DRIFT_REPORT" \
  --arg mappings_file "$MAPPINGS_FILE" \
  --argjson prowler_count "$PROWLER_COUNT" \
  --argjson drift_count "$DRIFT_COUNT" \
  '{prowler_findings:$prowler_findings,drift_report:$drift_report,mappings_file:$mappings_file,prowler_count:$prowler_count,drift_count:$drift_count}')"

RAW_CORRELATIONS="$(jq -n \
  --argjson prowler "$PROWLER_FINDINGS_DATA" \
  --argjson drift "$DRIFT_ITEMS_DATA" \
  --argjson drift_severities "$DRIFT_SEVERITY_MAP" \
  --argjson mappings "$MAPPINGS" \
  '
  [
    $drift[] as $d |
    $prowler[] as $p |
    (
      if (($p.vuln_id_from_tool // "") | startswith("prowler:"))
      then ($p.vuln_id_from_tool)[8:]
      else ($p.vuln_id_from_tool // "")
      end
    ) as $check_id |
    (($p.severity // "medium") | ascii_upcase) as $psev |
    ($drift_severities[$d.address] // "MEDIUM") as $dsev |
    (($mappings[($d.type // "")] // []) | any(. as $pfx | $check_id | startswith($pfx))) as $type_match |
    select(
      ($p.component_name != null and $p.component_name != "") and (
        ($p.component_name == ($d.address // ""))
        or ($d.resource_id != null and $d.resource_id != "" and $p.component_name == $d.resource_id)
        or $type_match
      )
    ) |
    (
      if ($psev == "CRITICAL") then "CRITICAL_CONFIRMED"
      elif ($psev == "HIGH" and ($dsev == "CRITICAL" or $dsev == "HIGH")) then "HIGH_CONFIRMED"
      elif ($psev == "MEDIUM" and $dsev == "CRITICAL") then "HIGH_CONFIRMED"
      else "CORRELATED"
      end
    ) as $combined_risk |
    {
      prowler_uid: ($p.unique_id_from_tool // ""),
      prowler_check_id: $check_id,
      prowler_severity: ($p.severity // "medium"),
      drift_address: ($d.address // ""),
      drift_severity: $dsev,
      resource_uid: (
        if ($p.component_name == ($d.address // "")) then ($d.address // "")
        elif ($d.resource_id != null and $d.resource_id != "" and $p.component_name == $d.resource_id) then $d.resource_id
        else ($d.address // "")
        end
      ),
      combined_risk: $combined_risk
    }
  ]
  | unique_by(.prowler_uid + "::" + .drift_address)
  ')"

CORRELATION_COUNT="$(printf '%s' "$RAW_CORRELATIONS" | jq 'length')"
FINAL_CORRELATIONS='[]'

while IFS= read -r raw_record; do
  [[ -n "$raw_record" ]] || continue
  prowler_uid="$(printf '%s' "$raw_record" | jq -r '.prowler_uid')"
  drift_address="$(printf '%s' "$raw_record" | jq -r '.drift_address')"
  corr_id="$(printf '%s:%s' "$prowler_uid" "$drift_address" | sha256sum | cut -c1-16)"
  enriched="$(printf '%s' "$raw_record" | jq --arg cid "$corr_id" --arg ts "$GENERATED_AT" '. + {correlation_id:$cid, correlated_at:$ts}')"
  FINAL_CORRELATIONS="$(printf '%s' "$FINAL_CORRELATIONS" | jq --argjson rec "$enriched" '. + [$rec]')"
done < <(printf '%s' "$RAW_CORRELATIONS" | jq -c '.[]')

CRITICAL_CONFIRMED="$(printf '%s' "$FINAL_CORRELATIONS" | jq '[.[] | select(.combined_risk == "CRITICAL_CONFIRMED")] | length')"
HIGH_CONFIRMED="$(printf '%s' "$FINAL_CORRELATIONS" | jq '[.[] | select(.combined_risk == "HIGH_CONFIRMED")] | length')"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --argjson prowler_count "$PROWLER_COUNT" \
  --argjson drift_count "$DRIFT_COUNT" \
  --argjson corr_count "$CORRELATION_COUNT" \
  --argjson critical_confirmed "$CRITICAL_CONFIRMED" \
  --argjson high_confirmed "$HIGH_CONFIRMED" \
  --argjson correlations "$FINAL_CORRELATIONS" \
  '{
    meta: {
      generated_at: $generated_at,
      prowler_findings_evaluated: $prowler_count,
      drift_items_evaluated: $drift_count,
      correlations_found: $corr_count,
      critical_confirmed: $critical_confirmed,
      high_confirmed: $high_confirmed
    },
    correlations: $correlations
  }' > "$CORRELATION_REPORT"

sr_require_json "$CORRELATION_REPORT" '
  type == "object"
  and (.meta | type == "object")
  and (.correlations | type == "array")
  and ((.meta.correlations_found // null) | type == "number")
' "correlation report"

REPORT_CORRELATION_COUNT="$(sr_json_number "$CORRELATION_REPORT" '.meta.correlations_found' 'correlation report')"
sr_assert_eq "$REPORT_CORRELATION_COUNT" "$CORRELATION_COUNT" "correlation report metadata count mismatch"

{
  echo "CORRELATION_COUNT=${CORRELATION_COUNT}"
  echo "CORRELATION_CRITICAL_CONFIRMED=${CRITICAL_CONFIRMED}"
  echo "CORRELATION_HIGH_CONFIRMED=${HIGH_CONFIRMED}"
} > "$CORRELATION_ENV"

sr_audit "INFO" "stage_complete" "cross-signal correlation completed" "$(jq -cn \
  --arg report "$CORRELATION_REPORT" \
  --arg env_file "$CORRELATION_ENV" \
  --argjson correlation_count "$CORRELATION_COUNT" \
  --argjson critical_confirmed "$CRITICAL_CONFIRMED" \
  --argjson high_confirmed "$HIGH_CONFIRMED" \
  '{report:$report,env_file:$env_file,correlation_count:$correlation_count,critical_confirmed:$critical_confirmed,high_confirmed:$high_confirmed}')"
