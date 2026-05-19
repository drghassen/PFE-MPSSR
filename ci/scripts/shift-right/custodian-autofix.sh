#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/custodian_audit.jsonl"
ENV_FILE="${OUTPUT_DIR}/custodian.env"
CUSTODIAN_OUTPUT_DIR="${OUTPUT_DIR}/custodian-output"
SCOPED_POLICIES_DIR="${OUTPUT_DIR}/custodian-scoped-policies"
CUSTODIAN_PLAN_FILE="${OUTPUT_DIR}/custodian_remediation_plan.json"
CUSTODIAN_PLAN_ERROR_FILE="${OUTPUT_DIR}/custodian_remediation_plan_error.json"
METRICS_FILE="${OUTPUT_DIR}/remediation_metrics.json"
DRIFT_DECISION_FILE="${OPA_DRIFT_DECISION_PATH:-${OUTPUT_DIR}/opa_drift_decision.json}"
BUILD_PLAN_SCRIPT="ci/scripts/shift-right/lib/build-custodian-plan.py"
SCOPE_POLICY_SCRIPT="ci/scripts/shift-right/lib/scope-custodian-policy.py"

mkdir -p "$OUTPUT_DIR" "$CUSTODIAN_OUTPUT_DIR" "$SCOPED_POLICIES_DIR"
sr_init_guard "shift-right/custodian-autofix" "$AUDIT_FILE"

# OPA_CUSTODIAN_POLICIES is an audit/dotenv summary. The JSON OPA decision
# artifact is the only execution authority for runtime remediation.
OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"
OPA_PROWLER_CUSTODIAN_POLICIES="${OPA_PROWLER_CUSTODIAN_POLICIES:-}"
OPA_DRIFT_L3_COUNT="${OPA_DRIFT_L3_COUNT:-0}"
OPA_PROWLER_L3_COUNT="${OPA_PROWLER_L3_COUNT:-0}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-unknown}"
REMEDIATION_MODE="${REMEDIATION_MODE:-enforced}"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-}"
CUSTODIAN_POLICIES_DIR="${CUSTODIAN_POLICIES_DIR:-shift-right/custodian/policies}"

ACTUALLY_EXECUTED="false"
TRIGGERED_JOINED=""
EXECUTED_JOINED=""
FAILED_JOINED=""
TRIGGERED_RESOURCE_IDS_JOINED=""
EXECUTED_RESOURCE_IDS_JOINED=""
FAILED_TARGETS_JOINED=""
PLAN_COUNT=0
CUSTODIAN_DRY_RUN_EFFECTIVE="${CUSTODIAN_DRY_RUN:-true}"
CUSTODIAN_EXECUTED_COUNT=0
CUSTODIAN_REMEDIATED_COUNT=0
CUSTODIAN_FAILED_COUNT=0
CUSTODIAN_IGNORED_COUNT=0
PROWLER_IGNORED_COUNT=0
PYTHON_BIN=""

write_env_file() {
  {
    echo "CUSTODIAN_EXECUTED=${ACTUALLY_EXECUTED}"
    echo "CUSTODIAN_POLICIES_TRIGGERED=${TRIGGERED_JOINED}"
    echo "CUSTODIAN_POLICIES_EXECUTED=${EXECUTED_JOINED}"
    echo "CUSTODIAN_DRY_RUN=${CUSTODIAN_DRY_RUN_EFFECTIVE}"
    echo "CUSTODIAN_POLICIES_FAILED=${FAILED_JOINED}"
    echo "CUSTODIAN_TARGETS_TOTAL=${PLAN_COUNT}"
    echo "CUSTODIAN_RESOURCE_IDS_TRIGGERED=${TRIGGERED_RESOURCE_IDS_JOINED}"
    echo "CUSTODIAN_RESOURCE_IDS_EXECUTED=${EXECUTED_RESOURCE_IDS_JOINED}"
    echo "CUSTODIAN_TARGETS_FAILED=${FAILED_TARGETS_JOINED}"
    echo "CUSTODIAN_TARGETS_REMEDIATED=${CUSTODIAN_REMEDIATED_COUNT}"
    echo "CUSTODIAN_TARGETS_FAILED_COUNT=${CUSTODIAN_FAILED_COUNT}"
    echo "CUSTODIAN_TARGETS_IGNORED=${CUSTODIAN_IGNORED_COUNT}"
    echo "CUSTODIAN_TARGETS_VERIFIED=0"
    echo "CUSTODIAN_REMEDIATION_PLAN=${CUSTODIAN_PLAN_FILE}"
    echo "CUSTODIAN_SCOPED_POLICIES_DIR=${SCOPED_POLICIES_DIR}"
    echo "CUSTODIAN_REMEDIATION_METRICS=${METRICS_FILE}"
    echo "CUSTODIAN_CORRELATION_ID=${OPA_CORRELATION_ID}"
  } > "$ENV_FILE"
}

write_metrics_file() {
  if ! command -v jq >/dev/null 2>&1; then
    return 0
  fi

  jq -cn \
    --arg schema_version "1.0" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg correlation_id "$OPA_CORRELATION_ID" \
    --arg remediation_mode "$REMEDIATION_MODE" \
    --arg dry_run "$CUSTODIAN_DRY_RUN_EFFECTIVE" \
    --arg plan_file "$CUSTODIAN_PLAN_FILE" \
    --arg scoped_policies_dir "$SCOPED_POLICIES_DIR" \
    --argjson planned "$PLAN_COUNT" \
    --argjson executed "$CUSTODIAN_EXECUTED_COUNT" \
    --argjson remediated "$CUSTODIAN_REMEDIATED_COUNT" \
    --argjson failed "$CUSTODIAN_FAILED_COUNT" \
    --argjson ignored "$CUSTODIAN_IGNORED_COUNT" \
    --argjson prowler_ignored "$PROWLER_IGNORED_COUNT" \
    '{
      schema_version: $schema_version,
      generated_at: $timestamp,
      correlation_id: $correlation_id,
      scope: "shift-right-runtime-remediation",
      counters: {
        remediated: $remediated,
        failed: $failed,
        ignored: $ignored,
        verified: 0
      },
      stages: {
        custodian: {
          planned: $planned,
          executed: $executed,
          remediated: $remediated,
          failed: $failed,
          ignored: $ignored,
          prowler_ignored: $prowler_ignored,
          dry_run: ($dry_run == "true"),
          remediation_mode: $remediation_mode,
          plan_file: $plan_file,
          scoped_policies_dir: $scoped_policies_dir
        },
        verification: {
          total_candidates: 0,
          verified: 0,
          failed: 0,
          ignored: 0,
          skipped_unverifiable: 0,
          status: "not_started"
        }
      }
    }' > "$METRICS_FILE" || true
}

resolve_dry_run_mode() {
  if [[ -n "$CUSTODIAN_DRY_RUN" ]]; then
    CUSTODIAN_DRY_RUN_EFFECTIVE="$CUSTODIAN_DRY_RUN"
    return
  fi

  case "$REMEDIATION_MODE" in
    advisory) CUSTODIAN_DRY_RUN="true" ;;
    enforced) CUSTODIAN_DRY_RUN="false" ;;
    *)
      sr_fail "invalid REMEDIATION_MODE (expected advisory|enforced)" 1 \
        "$(sr_build_details --arg remediation_mode "$REMEDIATION_MODE" '{remediation_mode:$remediation_mode}')"
      ;;
  esac
  CUSTODIAN_DRY_RUN_EFFECTIVE="$CUSTODIAN_DRY_RUN"
}

resolve_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    sr_fail "python is required for Custodian plan and scoped policy generation" 1 '{}'
  fi
}

audit_prowler_guardrail() {
  if [[ -z "$OPA_PROWLER_CUSTODIAN_POLICIES" ]]; then
    return
  fi

  PROWLER_IGNORED_COUNT="${OPA_PROWLER_L3_COUNT:-0}"
  CUSTODIAN_IGNORED_COUNT="$PROWLER_IGNORED_COUNT"

  sr_audit "WARN" "prowler_policies_ignored" \
    "ignoring prowler custodian policies; auto-remediation scope is drift-only" \
    "$(sr_build_details \
      --arg prowler_policies "$OPA_PROWLER_CUSTODIAN_POLICIES" \
      '{prowler_policies:$prowler_policies, remediation_scope:"DRIFT_ONLY"}')"
}

build_custodian_plan() {
  sr_require_command jq "$PYTHON_BIN"
  sr_require_nonempty_file "$DRIFT_DECISION_FILE" "OPA drift decision"
  sr_require_nonempty_file "$BUILD_PLAN_SCRIPT" "Custodian plan builder"

  rm -f "$CUSTODIAN_PLAN_ERROR_FILE"
  if ! "$PYTHON_BIN" "$BUILD_PLAN_SCRIPT" \
      --decision "$DRIFT_DECISION_FILE" \
      --output "$CUSTODIAN_PLAN_FILE" \
      --error-output "$CUSTODIAN_PLAN_ERROR_FILE"; then
    local details='{}'
    if [[ -s "$CUSTODIAN_PLAN_ERROR_FILE" ]] && jq -e . "$CUSTODIAN_PLAN_ERROR_FILE" >/dev/null 2>&1; then
      details="$(jq -c . "$CUSTODIAN_PLAN_ERROR_FILE")"
    fi
    sr_fail "failed to build resource_id-scoped Custodian remediation plan" 1 "$details"
  fi

  sr_require_json "$CUSTODIAN_PLAN_FILE" '
    type == "array"
    and all(.[]; ((.policy // "") | type == "string" and length > 0)
                and ((.resource_id // "") | type == "string" and test("^/subscriptions/"; "i")))
  ' "Custodian remediation plan"

  PLAN_COUNT="$(sr_json_number "$CUSTODIAN_PLAN_FILE" 'length' "Custodian remediation plan")"
  TRIGGERED_JOINED="$(jq -r 'map(.policy) | unique | join(",")' "$CUSTODIAN_PLAN_FILE")"
  TRIGGERED_RESOURCE_IDS_JOINED="$(jq -r 'map(.resource_id) | unique | join(",")' "$CUSTODIAN_PLAN_FILE")"
}

fail_if_remediation_was_expected_without_targets() {
  if [[ "$PLAN_COUNT" -gt 0 ]]; then
    return
  fi

  if [[ "$OPA_DRIFT_L3_COUNT" -gt 0 || -n "$OPA_CUSTODIAN_POLICIES" ]]; then
    sr_fail "L3 drift remediation was requested but no validated OPA resource_id-scoped Custodian target was produced" 1 \
      "$(sr_build_details \
        --arg opa_custodian_policies "$OPA_CUSTODIAN_POLICIES" \
        --argjson opa_drift_l3 "$OPA_DRIFT_L3_COUNT" \
        --arg plan_file "$CUSTODIAN_PLAN_FILE" \
        '{opa_custodian_policies:$opa_custodian_policies, opa_drift_l3:$opa_drift_l3, plan_file:$plan_file}')"
  fi
}

skip_if_no_targets() {
  if [[ "$PLAN_COUNT" -gt 0 ]]; then
    return
  fi

  sr_audit "INFO" "skip" "no L3 drift auto-remediation findings - custodian not triggered" \
    "$(sr_build_details \
      --arg policies "$OPA_CUSTODIAN_POLICIES" \
      --arg prowler_policies "$OPA_PROWLER_CUSTODIAN_POLICIES" \
      --arg correlation_id "$OPA_CORRELATION_ID" \
      --arg plan_file "$CUSTODIAN_PLAN_FILE" \
      --argjson l3_drift "$OPA_DRIFT_L3_COUNT" \
      --argjson l3_prowler "$OPA_PROWLER_L3_COUNT" \
      '{policies:$policies, prowler_policies:$prowler_policies, l3_drift:$l3_drift, l3_prowler:$l3_prowler, remediation_model:"L0-L3", remediation_scope:"L3_DRIFT_ONLY_RESOURCE_ID_SCOPED", correlation_id:$correlation_id, plan_file:$plan_file}')"
  exit 0
}

init_azure_credentials() {
  : "${AZURE_TENANT_ID:=${ARM_TENANT_ID:-}}"
  : "${AZURE_CLIENT_ID:=${ARM_CLIENT_ID:-}}"
  : "${AZURE_CLIENT_SECRET:=${ARM_CLIENT_SECRET:-}}"
  : "${AZURE_SUBSCRIPTION_ID:=${ARM_SUBSCRIPTION_ID:-}}"

  if [[ -n "${AZURE_TENANT_ID}" && -n "${AZURE_CLIENT_ID}" && -n "${AZURE_CLIENT_SECRET}" && -n "${AZURE_SUBSCRIPTION_ID}" ]]; then
    export AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_SUBSCRIPTION_ID
    sr_audit "INFO" "auth_mode" "using service principal environment credentials for custodian" \
      "$(sr_build_details '{auth_mode:"service_principal_env"}')"
    return
  fi

  if command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; then
    unset AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_SUBSCRIPTION_ID
    sr_audit "WARN" "auth_mode_fallback" "service principal env vars missing; falling back to Azure CLI authentication" \
      "$(sr_build_details '{auth_mode:"azure_cli"}')"
    return
  fi

  sr_fail "missing SP credentials and Azure CLI context unavailable for fallback auth" 1 \
    "$(sr_build_details '{expected_env:["AZURE_TENANT_ID","AZURE_CLIENT_ID","AZURE_CLIENT_SECRET","AZURE_SUBSCRIPTION_ID"],fallback:"azure_cli"}')"
}

prepare_scoped_targets() {
  sr_require_command custodian "$PYTHON_BIN"
  sr_require_nonempty_file "$SCOPE_POLICY_SCRIPT" "Custodian scope policy helper"

  planned_policy_names=()
  planned_resource_ids=()
  scoped_policy_files=()
  policy_output_dirs=()
  validation_failures=()

  local target_index=0
  while IFS=$'\t' read -r policy_name resource_id; do
    target_index=$((target_index + 1))
    local policy_file="${CUSTODIAN_POLICIES_DIR}/${policy_name}.yml"
    local policy_out="${CUSTODIAN_OUTPUT_DIR}/${policy_name}/target-${target_index}"
    local scoped_policy_file="${SCOPED_POLICIES_DIR}/${target_index}-${policy_name}.yml"
    mkdir -p "$policy_out"

    validate_and_scope_target "$policy_name" "$resource_id" "$policy_file" "$policy_out" "$scoped_policy_file"
  done < <(jq -r '.[] | [.policy, .resource_id] | @tsv' "$CUSTODIAN_PLAN_FILE")

  if ((${#validation_failures[@]} > 0)); then
    CUSTODIAN_FAILED_COUNT="${#validation_failures[@]}"
    CUSTODIAN_REMEDIATED_COUNT=0
    CUSTODIAN_EXECUTED_COUNT=0
    CUSTODIAN_IGNORED_COUNT=$((PROWLER_IGNORED_COUNT + PLAN_COUNT - CUSTODIAN_FAILED_COUNT))
    if ((CUSTODIAN_IGNORED_COUNT < PROWLER_IGNORED_COUNT)); then
      CUSTODIAN_IGNORED_COUNT="$PROWLER_IGNORED_COUNT"
    fi
    IFS=',' FAILED_TARGETS_JOINED="${validation_failures[*]:-}"
    write_env_file
    write_metrics_file
    sr_fail "Custodian policy validation failed; no remediation was executed" 1 \
      "$(printf '%s\n' "${validation_failures[@]}" | jq -R . | jq -sc '{validation_failures:., execution:"aborted_before_remediation"}')"
  fi
}

validate_and_scope_target() {
  local policy_name="$1"
  local resource_id="$2"
  local policy_file="$3"
  local policy_out="$4"
  local scoped_policy_file="$5"

  if [[ ! -f "$policy_file" ]]; then
    sr_audit "ERROR" "policy_file_missing" \
      "policy YAML not found for '${policy_name}' — L3 remediation cannot proceed" \
      "$(sr_build_details --arg policy "$policy_name" --arg file "$policy_file" --arg resource_id "$resource_id" '{policy:$policy, file:$file, resource_id:$resource_id}')"
    validation_failures+=("${policy_name}:${resource_id}:missing_policy_file")
    return
  fi

  if ! custodian validate "$policy_file" > "${policy_out}/validate-original.log" 2>&1; then
    sr_audit "ERROR" "policy_validation_failed" \
      "original Custodian policy '${policy_name}' failed validation" \
      "$(sr_build_details --arg policy "$policy_name" --arg file "$policy_file" --arg resource_id "$resource_id" --arg log "${policy_out}/validate-original.log" '{policy:$policy, file:$file, resource_id:$resource_id, log:$log}')"
    validation_failures+=("${policy_name}:${resource_id}:original_validation_failed")
    return
  fi

  if ! "$PYTHON_BIN" "$SCOPE_POLICY_SCRIPT" \
      --policy-file "$policy_file" \
      --policy-name "$policy_name" \
      --resource-id "$resource_id" \
      --output "$scoped_policy_file" > "${policy_out}/scope-generation.log" 2>&1; then
    sr_audit "ERROR" "scoped_policy_generation_failed" \
      "failed to generate resource_id-scoped Custodian policy '${policy_name}'" \
      "$(sr_build_details --arg policy "$policy_name" --arg file "$policy_file" --arg resource_id "$resource_id" --arg log "${policy_out}/scope-generation.log" '{policy:$policy, file:$file, resource_id:$resource_id, log:$log}')"
    validation_failures+=("${policy_name}:${resource_id}:scope_generation_failed")
    return
  fi

  if ! custodian validate "$scoped_policy_file" > "${policy_out}/validate-scoped.log" 2>&1; then
    sr_audit "ERROR" "scoped_policy_validation_failed" \
      "resource_id-scoped Custodian policy '${policy_name}' failed validation" \
      "$(sr_build_details --arg policy "$policy_name" --arg file "$scoped_policy_file" --arg resource_id "$resource_id" --arg log "${policy_out}/validate-scoped.log" '{policy:$policy, file:$file, resource_id:$resource_id, log:$log}')"
    validation_failures+=("${policy_name}:${resource_id}:scoped_validation_failed")
    return
  fi

  planned_policy_names+=("$policy_name")
  planned_resource_ids+=("$resource_id")
  scoped_policy_files+=("$scoped_policy_file")
  policy_output_dirs+=("$policy_out")
}

audit_execution_start() {
  sr_audit "INFO" "execution_start" "custodian autofix starting" \
    "$(sr_build_details \
      --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
      --arg remediation_mode "$REMEDIATION_MODE" \
      --arg custodian_policies_dir "$CUSTODIAN_POLICIES_DIR" \
      --arg opa_policies "$TRIGGERED_JOINED" \
      --arg plan_file "$CUSTODIAN_PLAN_FILE" \
      --arg correlation_id "$OPA_CORRELATION_ID" \
      --argjson target_count "$PLAN_COUNT" \
      '{custodian_dry_run:($custodian_dry_run=="true"), remediation_mode:$remediation_mode, custodian_policies_dir:$custodian_policies_dir, opa_policies:$opa_policies, remediation_scope:"L3_DRIFT_ONLY_RESOURCE_ID_SCOPED", target_count:$target_count, plan_file:$plan_file, correlation_id:$correlation_id}')"
}

run_scoped_targets() {
  actually_executed_policies=()
  actually_executed_resource_ids=()
  failed_policies=()
  failed_targets=()

  for idx in "${!planned_policy_names[@]}"; do
    run_scoped_target \
      "${planned_policy_names[$idx]}" \
      "${planned_resource_ids[$idx]}" \
      "${scoped_policy_files[$idx]}" \
      "${policy_output_dirs[$idx]}"
  done

  IFS=',' EXECUTED_JOINED="${actually_executed_policies[*]:-}"
  IFS=',' EXECUTED_RESOURCE_IDS_JOINED="${actually_executed_resource_ids[*]:-}"
  IFS=',' FAILED_JOINED="${failed_policies[*]:-}"
  IFS=',' FAILED_TARGETS_JOINED="${failed_targets[*]:-}"
  CUSTODIAN_EXECUTED_COUNT="${#actually_executed_resource_ids[@]}"
  CUSTODIAN_FAILED_COUNT="${#failed_targets[@]}"

  if [[ "$CUSTODIAN_DRY_RUN" == "true" ]]; then
    CUSTODIAN_REMEDIATED_COUNT=0
    CUSTODIAN_IGNORED_COUNT=$((PROWLER_IGNORED_COUNT + CUSTODIAN_EXECUTED_COUNT))
  else
    CUSTODIAN_REMEDIATED_COUNT="$CUSTODIAN_EXECUTED_COUNT"
    CUSTODIAN_IGNORED_COUNT="$PROWLER_IGNORED_COUNT"
  fi

  if ((${#failed_policies[@]} > 0)); then
    write_env_file
    write_metrics_file
    sr_fail "Custodian resource_id-scoped policy execution failed for: ${FAILED_TARGETS_JOINED}" 1 \
      "$(sr_build_details --arg failed "$FAILED_JOINED" --arg failed_targets "$FAILED_TARGETS_JOINED" '{failed_policies:($failed | split(",")), failed_targets:($failed_targets | split(","))}')"
  fi
}

run_scoped_target() {
  local policy_name="$1"
  local resource_id="$2"
  local scoped_policy_file="$3"
  local policy_out="$4"
  local custodian_cmd=(
    custodian run
    --output-dir "$policy_out"
    --cache-period 0
  )
  [[ "$CUSTODIAN_DRY_RUN" == "true" ]] && custodian_cmd+=(--dryrun)
  custodian_cmd+=("$scoped_policy_file")

  sr_audit "INFO" "custodian_policy_start" "running resource_id-scoped policy '${policy_name}'" \
    "$(sr_build_details --arg policy "$policy_name" --arg file "$scoped_policy_file" --arg output_dir "$policy_out" --arg dry_run "$CUSTODIAN_DRY_RUN" --arg resource_id "$resource_id" --arg correlation_id "$OPA_CORRELATION_ID" '{policy:$policy, file:$file, output_dir:$output_dir, dry_run:($dry_run=="true"), resource_id:$resource_id, remediation_scope:"L3_DRIFT_ONLY_RESOURCE_ID_SCOPED", correlation_id:$correlation_id}')"

  local custodian_exit=0
  if "${custodian_cmd[@]}" 2>&1 | tee "${policy_out}/run.log"; then
    actually_executed_policies+=("$policy_name")
    actually_executed_resource_ids+=("$resource_id")
    sr_audit "INFO" "custodian_policy_ok" "resource_id-scoped policy '${policy_name}' completed" \
      "$(sr_build_details --arg policy "$policy_name" --arg resource_id "$resource_id" --arg log "${policy_out}/run.log" '{policy:$policy, resource_id:$resource_id, log:$log}')"
  else
    custodian_exit=$?
    failed_policies+=("$policy_name")
    failed_targets+=("${policy_name}:${resource_id}")
    sr_audit "ERROR" "custodian_policy_failed" \
      "resource_id-scoped policy '${policy_name}' exited with code ${custodian_exit}" \
      "$(sr_build_details --arg policy "$policy_name" --arg resource_id "$resource_id" --argjson rc "$custodian_exit" --arg log "${policy_out}/run.log" '{policy:$policy, resource_id:$resource_id, exit_code:$rc, log:$log}')"
  fi
}

audit_stage_complete() {
  ((${#actually_executed_resource_ids[@]} > 0)) && ACTUALLY_EXECUTED="true"
  write_env_file
  write_metrics_file

  sr_audit "INFO" "stage_complete" "custodian autofix complete" \
    "$(sr_build_details \
      --arg executed "$ACTUALLY_EXECUTED" \
      --arg triggered "$TRIGGERED_JOINED" \
      --arg executed_list "$EXECUTED_JOINED" \
      --arg executed_resources "$EXECUTED_RESOURCE_IDS_JOINED" \
      --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
      --argjson target_count "$PLAN_COUNT" \
      --arg plan_file "$CUSTODIAN_PLAN_FILE" \
      '{custodian_executed:($executed=="true"), policies_triggered:$triggered, policies_executed:$executed_list, resource_ids_executed:$executed_resources, target_count:$target_count, plan_file:$plan_file, remediation_scope:"L3_DRIFT_ONLY_RESOURCE_ID_SCOPED", custodian_dry_run:($custodian_dry_run=="true") }')"
}

trap 'write_env_file; write_metrics_file' EXIT
write_env_file
write_metrics_file

resolve_dry_run_mode
resolve_python
audit_prowler_guardrail
build_custodian_plan
fail_if_remediation_was_expected_without_targets
skip_if_no_targets
prepare_scoped_targets
init_azure_credentials
audit_execution_start
run_scoped_targets
audit_stage_complete
