#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CloudSentinel — Prowler Azure Compliance Sensor (Shift-Right Detection)
#
# Contract:
# - runtime failures stop the stage
# - missing/empty/malformed OCSF input stops the stage
# - every raw FAIL record must survive normalization into generic findings
# - audit logs are written as JSONL for deterministic traceability
# =============================================================================

source ci/scripts/shift-right/lib/pipeline-guard.sh

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
OUTPUT_DIR="${PROWLER_OUTPUT_DIR:-shift-right/prowler/output}"
CLOUDSENTINEL_DIR=".cloudsentinel"
GENERIC_FINDINGS_FILE="${CLOUDSENTINEL_DIR}/prowler_generic_findings.json"
CONFIG_FILE="shift-right/prowler/config-azure.yaml"
MUTELIST_FILE="shift-right/prowler/mutelist-azure.yaml"
AUDIT_FILE="${CLOUDSENTINEL_DIR}/prowler_audit.jsonl"

sr_init_guard "shift-right/prowler-detection" "$AUDIT_FILE"
sr_require_command jq prowler
sr_require_env ARM_CLIENT_ID ARM_CLIENT_SECRET ARM_TENANT_ID ARM_SUBSCRIPTION_ID PROWLER_OUTPUT_DIR
sr_require_nonempty_file "$CONFIG_FILE" "prowler config"

mkdir -p "$OUTPUT_DIR" "$CLOUDSENTINEL_DIR" "${CLOUDSENTINEL_DIR}/dojo-responses"

export AZURE_CLIENT_ID="${ARM_CLIENT_ID}"
export AZURE_CLIENT_SECRET="${ARM_CLIENT_SECRET}"
export AZURE_TENANT_ID="${ARM_TENANT_ID}"

PROWLER_EXTRA_ARGS=()
if [[ -f "$MUTELIST_FILE" ]]; then
  sr_require_nonempty_file "$MUTELIST_FILE" "prowler mutelist"
  PROWLER_EXTRA_ARGS+=("--mutelist-file" "$MUTELIST_FILE")
fi

sr_audit "INFO" "stage_start" "starting prowler compliance sensor" "$(jq -cn \
  --arg subscription_id "$ARM_SUBSCRIPTION_ID" \
  --arg output_dir "$OUTPUT_DIR" \
  --arg config_file "$CONFIG_FILE" \
  --arg mutelist_file "${MUTELIST_FILE}" \
  --arg timestamp "$TIMESTAMP" \
  '{subscription_id:$subscription_id,output_dir:$output_dir,config_file:$config_file,mutelist_file:$mutelist_file,timestamp:$timestamp}')"

PROWLER_EXIT=0
if prowler azure \
  --subscription-ids "$ARM_SUBSCRIPTION_ID" \
  --sp-env-auth \
  --compliance cis_2.0_azure \
  --severity medium high critical \
  --output-formats json-ocsf \
  -o "$OUTPUT_DIR" \
  -F "prowler-output-${TIMESTAMP}" \
  --config-file "$CONFIG_FILE" \
  "${PROWLER_EXTRA_ARGS[@]}"; then
  PROWLER_EXIT=0
else
  PROWLER_EXIT=$?
fi

case "$PROWLER_EXIT" in
  0|3)
    ;;
  *)
    sr_fail "prowler execution failed" 1 "$(jq -cn --argjson exit_code "$PROWLER_EXIT" '{exit_code:$exit_code}')"
    ;;
esac

OCSF_FILE=""
if [[ -f "${OUTPUT_DIR}/prowler-output-${TIMESTAMP}.ocsf.json" ]]; then
  OCSF_FILE="${OUTPUT_DIR}/prowler-output-${TIMESTAMP}.ocsf.json"
elif compgen -G "${OUTPUT_DIR}/*.ocsf.json" >/dev/null 2>&1; then
  OCSF_FILE="$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name '*.ocsf.json' -print | LC_ALL=C sort | tail -n1)"
fi

sr_require_nonempty_file "$OCSF_FILE" "prowler OCSF output"
sr_require_json "$OCSF_FILE" '
  (type == "array" or type == "object")
' "prowler OCSF output"

RAW_RECORD_COUNT="$(jq -r '
  if type == "array" then length
  elif type == "object" then 1
  else error("ocsf_root_must_be_array_or_object")
  end
' "$OCSF_FILE")"
RAW_FAIL_COUNT="$(jq -r '
  def fail_record:
    (.status_id == 2)
    or (((.status // "") | tostring | ascii_downcase) == "fail");
  if type == "array" then [ .[] | select(fail_record) ] | length
  elif type == "object" then (if fail_record then 1 else 0 end)
  else error("ocsf_root_must_be_array_or_object")
  end
' "$OCSF_FILE")"

sr_assert_int_ge "$RAW_RECORD_COUNT" 1 "prowler produced an empty OCSF payload"
sr_audit "INFO" "raw_counts" "computed raw prowler finding counts" "$(jq -cn \
  --arg file "$OCSF_FILE" \
  --argjson raw_record_count "$RAW_RECORD_COUNT" \
  --argjson raw_fail_count "$RAW_FAIL_COUNT" \
  --argjson prowler_exit "$PROWLER_EXIT" \
  '{file:$file,raw_record_count:$raw_record_count,raw_fail_count:$raw_fail_count,prowler_exit:$prowler_exit}')"

jq -c \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg scan_date "$(date -u +"%Y-%m-%d")" \
  --arg subscription_id "$ARM_SUBSCRIPTION_ID" \
  --arg source_file "$OCSF_FILE" \
  '
  def dojo_severity($id):
    if   $id == 1 then "Info"
    elif $id == 2 then "Low"
    elif $id == 3 then "Medium"
    elif $id == 4 then "High"
    elif $id == 5 then "Critical"
    else "Medium"
    end;

  def safe($v): ($v // "" | tostring);
  def fail_record:
    (.status_id == 2)
    or (((.status // "") | tostring | ascii_downcase) == "fail");

  [
    (if type == "array" then .[] else . end)
    | select(fail_record)
    | {
        title: (
          "Prowler: " + safe(.finding_info.title // .metadata.event_code // "Unknown check")
        ),
        severity: dojo_severity(.severity_id),
        date: $scan_date,
        description: (
          "CloudSentinel Prowler Finding\n"
          + "Check ID: " + safe(.metadata.event_code // .finding_info.uid) + "\n"
          + "Resource: " + safe(.resources[0].uid // .resources[0].name // "unknown") + "\n"
          + "Region: " + safe(.resources[0].region // .cloud.region // "global") + "\n"
          + "Subscription: " + $subscription_id + "\n"
          + "Detail: " + safe(.status_detail // .finding_info.desc)
        ),
        mitigation: safe(
          .remediation.desc
          // .remediation.recommendation.text
          // ("See Prowler remediation guidance for check " + safe(.metadata.event_code))
        ),
        references: safe(((.remediation.references // []) | join(", "))),
        unique_id_from_tool: (
          "prowler:"
          + safe(.metadata.event_code // .finding_info.uid)
          + ":"
          + safe(.resources[0].uid // .resources[0].name // "unknown")
        ),
        vuln_id_from_tool: (
          "prowler:" + safe(.metadata.event_code // .finding_info.uid)
        ),
        component_name: safe(.resources[0].uid // .resources[0].name // "unknown")
      }
  ] as $findings
  | {
      meta: {
        tool: "prowler",
        generated_at: $generated_at,
        source_file: $source_file,
        raw_record_count: (if type == "array" then length else 1 end),
        raw_fail_count: ($findings | length),
        normalized_findings_count: ($findings | length)
      },
      findings: $findings
    }
' "$OCSF_FILE" > "$GENERIC_FINDINGS_FILE"

sr_require_json "$GENERIC_FINDINGS_FILE" '
  type == "object"
  and (.meta | type == "object")
  and (.findings | type == "array")
  and ((.meta.raw_record_count // null) | type == "number")
  and ((.meta.raw_fail_count // null) | type == "number")
  and ((.meta.normalized_findings_count // null) | type == "number")
' "prowler normalized findings"

NORMALIZED_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.findings | length' 'prowler normalized findings')"
META_RAW_RECORD_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.meta.raw_record_count' 'prowler normalized findings')"
META_RAW_FAIL_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.meta.raw_fail_count' 'prowler normalized findings')"
META_NORMALIZED_COUNT="$(sr_json_number "$GENERIC_FINDINGS_FILE" '.meta.normalized_findings_count' 'prowler normalized findings')"

sr_assert_eq "$META_RAW_RECORD_COUNT" "$RAW_RECORD_COUNT" "prowler raw record count mismatch after normalization"
sr_assert_eq "$META_RAW_FAIL_COUNT" "$RAW_FAIL_COUNT" "prowler raw FAIL count mismatch after normalization"
sr_assert_eq "$META_NORMALIZED_COUNT" "$NORMALIZED_COUNT" "prowler normalized metadata count mismatch"
sr_assert_eq "$NORMALIZED_COUNT" "$RAW_FAIL_COUNT" "prowler normalization lost FAIL findings"
sr_assert_positive_if_expected "$RAW_FAIL_COUNT" "$NORMALIZED_COUNT" "prowler reported FAIL findings but normalized output is empty"

sr_audit "INFO" "stage_complete" "prowler normalization completed" "$(jq -cn \
  --arg output_file "$GENERIC_FINDINGS_FILE" \
  --argjson raw_record_count "$RAW_RECORD_COUNT" \
  --argjson raw_fail_count "$RAW_FAIL_COUNT" \
  --argjson normalized_findings_count "$NORMALIZED_COUNT" \
  '{output_file:$output_file,raw_record_count:$raw_record_count,raw_fail_count:$raw_fail_count,normalized_findings_count:$normalized_findings_count}')"
