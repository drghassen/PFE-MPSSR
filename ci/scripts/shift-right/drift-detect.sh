#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh
source ci/scripts/setup-custom-ca.sh

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR=".cloudsentinel"
DRIFT_OUTPUT_PATH="${DRIFT_OUTPUT_PATH:-${CI_PROJECT_DIR:-$REPO_ROOT}/shift-right/drift-engine/output/drift-report.json}"
DRIFT_REPORT_PATH="$DRIFT_OUTPUT_PATH"
DRIFT_ENGINE_ENV_FILE="${OUTPUT_DIR}/drift_engine.env"
DRIFT_EXCEPTIONS_FILE="${OUTPUT_DIR}/drift_exceptions.json"
AUDIT_FILE="${OUTPUT_DIR}/drift_detect_audit.jsonl"
DRIFT_CONFIG_PATH="${DRIFT_CONFIG_PATH:-/app/config/drift_config.yaml}"
DRIFT_ENGINE_ENTRYPOINT="${DRIFT_ENGINE_ENTRYPOINT:-/app/drift-engine.py}"
TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-${REPO_ROOT}/.cloudsentinel/tf-plugin-cache}"
ENVIRONMENT="${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}"

mkdir -p "$(dirname "$DRIFT_REPORT_PATH")" "$OUTPUT_DIR" "$TF_PLUGIN_CACHE_DIR"

sr_init_guard "shift-right/drift-detection" "$AUDIT_FILE"
sr_require_command jq python
sr_require_env ARM_SUBSCRIPTION_ID
sr_require_nonempty_file "$DRIFT_CONFIG_PATH" "drift engine config"
sr_require_nonempty_file "$DRIFT_ENGINE_ENTRYPOINT" "drift engine entrypoint"

export TF_VAR_subscription_id="${TF_VAR_subscription_id:-${ARM_SUBSCRIPTION_ID}}"
export OPA_ENABLED="${OPA_ENABLED:-false}"

sr_audit "INFO" "stage_start" "starting drift detection" "$(jq -cn \
  --arg drift_output_path "$DRIFT_REPORT_PATH" \
  --arg drift_config_path "$DRIFT_CONFIG_PATH" \
  --arg environment "$ENVIRONMENT" \
  --arg tf_working_dir "${TF_WORKING_DIR:-}" \
  --arg opa_enabled "$OPA_ENABLED" \
  '{drift_output_path:$drift_output_path,drift_config_path:$drift_config_path,environment:$environment,tf_working_dir:$tf_working_dir,opa_enabled:$opa_enabled}')"

DRIFT_ENGINE_EXIT_CODE=0
if python "$DRIFT_ENGINE_ENTRYPOINT" --config "$DRIFT_CONFIG_PATH"; then
  DRIFT_ENGINE_EXIT_CODE=0
else
  DRIFT_ENGINE_EXIT_CODE=$?
fi

if [[ "$DRIFT_ENGINE_EXIT_CODE" -ne 0 && "$DRIFT_ENGINE_EXIT_CODE" -ne 2 ]]; then
  sr_fail "drift engine execution failed" 1 "$(jq -cn --argjson exit_code "$DRIFT_ENGINE_EXIT_CODE" '{exit_code:$exit_code}')"
fi

sr_require_nonempty_file "$DRIFT_REPORT_PATH" "drift report"
sr_require_json "$DRIFT_REPORT_PATH" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.drift | type == "object")
  and (.drift.summary | type == "object")
  and (.drift.items | type == "array")
  and (.errors | type == "array")
  and ((.drift.detected // null) | type == "boolean")
  and ((.drift.exit_code // null) | type == "number")
' "drift report"

REPORT_ERROR_COUNT="$(sr_json_number "$DRIFT_REPORT_PATH" '.errors | length' 'drift report')"
DRIFT_ITEM_COUNT="$(sr_json_number "$DRIFT_REPORT_PATH" '.drift.items | length' 'drift report')"
REPORT_EXIT_CODE="$(sr_json_number "$DRIFT_REPORT_PATH" '.drift.exit_code' 'drift report')"
REPORT_DETECTED="$(jq -r '.drift.detected' "$DRIFT_REPORT_PATH")"

sr_assert_eq "$REPORT_EXIT_CODE" "$DRIFT_ENGINE_EXIT_CODE" "drift engine exit code does not match report exit code"
if [[ "$REPORT_ERROR_COUNT" -gt 0 ]]; then
  sr_fail "drift report contains embedded errors" 1 "$(jq -cn --argjson report_error_count "$REPORT_ERROR_COUNT" '{report_error_count:$report_error_count}')"
fi
if [[ "$REPORT_DETECTED" == "true" && "$DRIFT_ITEM_COUNT" -eq 0 ]]; then
  sr_fail "drift detected but report contains zero items" 1 "$(jq -cn --argjson drift_item_count "$DRIFT_ITEM_COUNT" '{drift_item_count:$drift_item_count}')"
fi
if [[ "$REPORT_DETECTED" == "false" && "$DRIFT_ITEM_COUNT" -gt 0 ]]; then
  sr_fail "drift report contains items while detected=false" 1 "$(jq -cn --argjson drift_item_count "$DRIFT_ITEM_COUNT" '{drift_item_count:$drift_item_count}')"
fi

python shift-right/scripts/fetch_drift_exceptions.py \
  --output "$DRIFT_EXCEPTIONS_FILE" \
  --environment "$ENVIRONMENT"

sr_require_nonempty_file "$DRIFT_EXCEPTIONS_FILE" "drift exceptions"
sr_require_json "$DRIFT_EXCEPTIONS_FILE" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.cloudsentinel.drift_exceptions | type == "object")
  and (.cloudsentinel.drift_exceptions.exceptions | type == "array")
' "drift exceptions"

{
  echo "DRIFT_ENGINE_EXIT_CODE=${DRIFT_ENGINE_EXIT_CODE}"
  if [[ "$DRIFT_ENGINE_EXIT_CODE" -eq 2 ]]; then
    echo "DRIFT_DETECTED=true"
  else
    echo "DRIFT_DETECTED=false"
  fi
  echo "DRIFT_ITEM_COUNT=${DRIFT_ITEM_COUNT}"
  echo "DRIFT_EXCEPTION_COUNT=$(sr_json_number "$DRIFT_EXCEPTIONS_FILE" '.cloudsentinel.drift_exceptions.exceptions | length' 'drift exceptions')"
} > "$DRIFT_ENGINE_ENV_FILE"

sr_audit "INFO" "stage_complete" "drift detection completed" "$(jq -cn \
  --arg report_path "$DRIFT_REPORT_PATH" \
  --arg env_file "$DRIFT_ENGINE_ENV_FILE" \
  --arg exceptions_file "$DRIFT_EXCEPTIONS_FILE" \
  --argjson exit_code "$DRIFT_ENGINE_EXIT_CODE" \
  --arg detected "$REPORT_DETECTED" \
  --argjson drift_item_count "$DRIFT_ITEM_COUNT" \
  '{report_path:$report_path,env_file:$env_file,exceptions_file:$exceptions_file,exit_code:$exit_code,detected:$detected,drift_item_count:$drift_item_count}')"
