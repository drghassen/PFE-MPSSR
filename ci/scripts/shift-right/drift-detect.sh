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
EXCEPTIONS_FETCH_MODE="${EXCEPTIONS_FETCH_MODE:-strict}"
DRIFT_EXCEPTIONS_SNAPSHOT_PATH="${DRIFT_EXCEPTIONS_SNAPSHOT_PATH:-${OUTPUT_DIR}/last-known-good/drift_exceptions.json}"
DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH="${DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH:-${DRIFT_EXCEPTIONS_SNAPSHOT_PATH}.sha256}"
DRIFT_DEGRADED_ARTIFACT="${DRIFT_DEGRADED_ARTIFACT:-${OUTPUT_DIR}/drift_degraded_mode.json}"
AUDIT_FILE="${OUTPUT_DIR}/drift_detect_audit.jsonl"
TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-${REPO_ROOT}/.cloudsentinel/tf-plugin-cache}"
ENVIRONMENT="${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}"
DEFAULT_REPO_DRIFT_CONFIG_PATH="${REPO_ROOT}/shift-right/drift-engine/config/drift_config.yaml"
DEFAULT_REPO_DRIFT_ENGINE_ENTRYPOINT="${REPO_ROOT}/shift-right/drift-engine/drift-engine.py"

if [[ -z "${DRIFT_CONFIG_PATH:-}" ]]; then
  if [[ -f "$DEFAULT_REPO_DRIFT_CONFIG_PATH" ]]; then
    DRIFT_CONFIG_PATH="$DEFAULT_REPO_DRIFT_CONFIG_PATH"
  else
    DRIFT_CONFIG_PATH="/app/config/drift_config.yaml"
  fi
fi

if [[ -z "${DRIFT_ENGINE_ENTRYPOINT:-}" ]]; then
  if [[ -f "$DEFAULT_REPO_DRIFT_ENGINE_ENTRYPOINT" ]]; then
    DRIFT_ENGINE_ENTRYPOINT="$DEFAULT_REPO_DRIFT_ENGINE_ENTRYPOINT"
  else
    DRIFT_ENGINE_ENTRYPOINT="/app/drift-engine.py"
  fi
fi

mkdir -p "$(dirname "$DRIFT_REPORT_PATH")" "$OUTPUT_DIR" "$TF_PLUGIN_CACHE_DIR"

sr_init_guard "shift-right/drift-detection" "$AUDIT_FILE"
sr_require_command jq python sha256sum
sr_require_env ARM_SUBSCRIPTION_ID
sr_require_nonempty_file "$DRIFT_CONFIG_PATH" "drift engine config"
sr_require_nonempty_file "$DRIFT_ENGINE_ENTRYPOINT" "drift engine entrypoint"

export TF_VAR_subscription_id="${TF_VAR_subscription_id:-${ARM_SUBSCRIPTION_ID}}"
# OPA evaluation is intentionally delegated to the external opa-drift-decision job.
# The drift engine's built-in OPA guard is disabled here to avoid redundant evaluation.
export OPA_ENABLED="${OPA_ENABLED:-false}"

sr_audit "INFO" "stage_start" "starting drift detection" "$(sr_build_details \
  --arg environment "$ENVIRONMENT" \
  --arg terraform_workspace "${TF_WORKSPACE:-default}" \
  --arg terraform_working_dir "${TF_WORKING_DIR:-unknown}" \
  --arg config_path "$DRIFT_CONFIG_PATH" \
  --arg report_path "$DRIFT_REPORT_PATH" \
  --arg opa_evaluation "delegated_to_opa_drift_decision_job" \
  '{
    scan_target: {
      environment:          $environment,
      terraform_workspace:  $terraform_workspace,
      terraform_working_dir: $terraform_working_dir
    },
    configuration: {
      config_path:    $config_path,
      opa_evaluation: $opa_evaluation
    },
    output: { report_path: $report_path }
  }')"

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

REPORT_PIPELINE_CORRELATION_ID="$(jq -er '.cloudsentinel.pipeline_correlation_id // empty' "$DRIFT_REPORT_PATH" 2>/dev/null || true)"
if [[ -z "$REPORT_PIPELINE_CORRELATION_ID" ]]; then
  tmp_report="$(mktemp)"
  if ! jq --arg pipeline_correlation_id "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" \
    '.cloudsentinel.pipeline_correlation_id = $pipeline_correlation_id' \
    "$DRIFT_REPORT_PATH" > "$tmp_report"; then
    rm -f "$tmp_report"
    sr_fail "failed to normalize drift report pipeline correlation id" 1 \
      "$(sr_build_details --arg report_path "$DRIFT_REPORT_PATH" '{report_path:$report_path}')"
  fi
  mv "$tmp_report" "$DRIFT_REPORT_PATH"
  sr_audit "WARN" "drift_report_pipeline_correlation_id_injected" \
    "drift report missing pipeline_correlation_id; injected wrapper correlation id" \
    "$(sr_build_details \
      --arg report_path "$DRIFT_REPORT_PATH" \
      --arg pipeline_correlation_id "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" \
      '{report_path:$report_path, pipeline_correlation_id:$pipeline_correlation_id}')"
elif [[ "$REPORT_PIPELINE_CORRELATION_ID" != "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" ]]; then
  sr_fail "drift report pipeline correlation id mismatch" 1 \
    "$(sr_build_details \
      --arg report_path "$DRIFT_REPORT_PATH" \
      --arg report_pipeline_correlation_id "$REPORT_PIPELINE_CORRELATION_ID" \
      --arg expected_pipeline_correlation_id "$CLOUDSENTINEL_PIPELINE_CORRELATION_ID" \
      '{report_path:$report_path, report_pipeline_correlation_id:$report_pipeline_correlation_id, expected_pipeline_correlation_id:$expected_pipeline_correlation_id}')"
fi

sr_require_json "$DRIFT_REPORT_PATH" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and ((.cloudsentinel.correlation_id // "") | type == "string" and length > 0)
  and (.cloudsentinel.pipeline_correlation_id == env.CLOUDSENTINEL_PIPELINE_CORRELATION_ID)
  and (.drift | type == "object")
  and (.drift.summary | type == "object")
  and (.drift.items | type == "array")
  and (.errors | type == "array")
  and (.drift.detected | type == "boolean")
  and (.drift.exit_code | type == "number")
' "drift report"

REPORT_ERROR_COUNT="$(sr_json_number "$DRIFT_REPORT_PATH" '.errors | length' 'drift report')"
DRIFT_ITEM_COUNT="$(sr_json_number "$DRIFT_REPORT_PATH" '.drift.items | length' 'drift report')"
REPORT_EXIT_CODE="$(sr_json_number "$DRIFT_REPORT_PATH" '.drift.exit_code' 'drift report')"
REPORT_DETECTED="$(jq -r '.drift.detected' "$DRIFT_REPORT_PATH")"
DRIFT_CORRELATION_ID="$(jq -r '.cloudsentinel.correlation_id // .cloudsentinel.run_id // "unknown"' "$DRIFT_REPORT_PATH")"
PIPELINE_CORRELATION_ID="$(sr_pipeline_correlation_id)"

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

FETCH_ERROR=""
if ! python shift-right/scripts/fetch_drift_exceptions.py \
  --output "$DRIFT_EXCEPTIONS_FILE" \
  --environment "$ENVIRONMENT"; then
  FETCH_ERROR="fetch_failed"
fi

if [[ -z "$FETCH_ERROR" ]]; then
  mkdir -p "$(dirname "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH")"
  cp "$DRIFT_EXCEPTIONS_FILE" "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH"
  (cd "$(dirname "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH")" && sha256sum "$(basename "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH")" > "$(basename "$DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH")")
else
  if [[ "$EXCEPTIONS_FETCH_MODE" != "degraded" ]]; then
    sr_fail "failed to fetch drift exceptions from DefectDojo in strict mode" 1 \
      "$(jq -cn --arg mode "$EXCEPTIONS_FETCH_MODE" '{mode:$mode}')"
  fi

  sr_require_nonempty_file "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH" "drift exceptions snapshot"
  sr_require_nonempty_file "$DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH" "drift exceptions snapshot signature"
  if ! (cd "$(dirname "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH")" && sha256sum -c "$(basename "$DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH")" >/dev/null 2>&1); then
    sr_fail "degraded mode enabled but drift snapshot signature verification failed" 1 \
      "$(jq -cn --arg snapshot "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH" --arg sig "$DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH" '{snapshot:$snapshot,signature:$sig}')"
  fi

  cp "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH" "$DRIFT_EXCEPTIONS_FILE"
  jq -cn \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg mode "$EXCEPTIONS_FETCH_MODE" \
    --arg snapshot "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH" \
    --arg signature "$DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH" \
    --arg reason "defectdojo_fetch_failed_snapshot_used" \
    '{timestamp:$timestamp, mode:$mode, snapshot:$snapshot, signature:$signature, reason:$reason}' > "$DRIFT_DEGRADED_ARTIFACT"

  sr_audit "WARN" "exceptions_degraded_mode" "DefectDojo unavailable, using signed drift snapshot" \
    "$(sr_build_details --arg snapshot "$DRIFT_EXCEPTIONS_SNAPSHOT_PATH" --arg signature "$DRIFT_EXCEPTIONS_SNAPSHOT_SIG_PATH" '{snapshot:$snapshot, signature:$signature}')"
fi

sr_require_nonempty_file "$DRIFT_EXCEPTIONS_FILE" "drift exceptions"
sr_require_json "$DRIFT_EXCEPTIONS_FILE" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.cloudsentinel.drift_exceptions | type == "object")
  and (.cloudsentinel.drift_exceptions.exceptions | type == "array")
' "drift exceptions"

DRIFT_EXCEPTION_COUNT="$(sr_json_number "$DRIFT_EXCEPTIONS_FILE" '.cloudsentinel.drift_exceptions.exceptions | length' 'drift exceptions')"

# ── Drift Detection Summary Table ─────────────────────────────────────────────
_dur="$(jq -r '(.cloudsentinel.duration_ms // 0) / 1000 | floor | tostring' \
  "$DRIFT_REPORT_PATH" 2>/dev/null || echo "?")s"
_ws="$(jq -r '.cloudsentinel.terraform_workspace // "default"' \
  "$DRIFT_REPORT_PATH" 2>/dev/null || echo "?")"
_status="$([ "$REPORT_DETECTED" == "true" ] && echo "DRIFTED" || echo "CLEAN")"
{
  printf '┌────────────────────────────────────────────────────────────────────────────────┐\n'
  printf '│ %-78s │\n' "CloudSentinel Drift Engine — Terraform State vs Azure Reality"
  printf '│ %-78s │\n' "Env: ${ENVIRONMENT}  |  Workspace: ${_ws}  |  Duration: ${_dur}  |  Status: ${_status}"
  printf '├──────────────────────────────────────────┬───────────┬──────────┬──────────────┤\n'
  printf '│ %-40s │ %-9s │ %-8s │ %-12s │\n' "Terraform Address" "Type" "Action" "Changed"
  printf '├──────────────────────────────────────────┼───────────┼──────────┼──────────────┤\n'
  if [[ "$DRIFT_ITEM_COUNT" -gt 0 ]]; then
    while IFS=$'\t' read -r _a _t _ac _p; do
      printf '│ %-40s │ %-9s │ %-8s │ %-12s │\n' \
        "${_a:0:40}" "${_t:0:9}" "${_ac:0:8}" "${_p:0:12}"
    done < <(jq -r '.drift.items[] |
      [.address, (.type // "?"), (.actions | join(",")), (.changed_paths | join(" "))] | @tsv' \
      "$DRIFT_REPORT_PATH")
  else
    printf '│ %-40s │ %-9s │ %-8s │ %-12s │\n' \
      "  No drift — all resources match Azure" "" "" "—"
  fi
  printf '├──────────────────────────────────────────┴───────────┴──────────┴──────────────┤\n'
  printf '│ %-78s │\n' \
    "Total drifted: ${DRIFT_ITEM_COUNT}   |   Errors: ${REPORT_ERROR_COUNT}   |   Exceptions available: ${DRIFT_EXCEPTION_COUNT}"
  printf '└────────────────────────────────────────────────────────────────────────────────┘\n'
} >&2

{
  echo "DRIFT_ENGINE_EXIT_CODE=${DRIFT_ENGINE_EXIT_CODE}"
  if [[ "$DRIFT_ENGINE_EXIT_CODE" -eq 2 ]]; then
    echo "DRIFT_DETECTED=true"
  else
    echo "DRIFT_DETECTED=false"
  fi
  echo "DRIFT_ITEM_COUNT=${DRIFT_ITEM_COUNT}"
  echo "DRIFT_EXCEPTION_COUNT=${DRIFT_EXCEPTION_COUNT}"
  echo "DRIFT_CORRELATION_ID=${DRIFT_CORRELATION_ID}"
  echo "PIPELINE_CORRELATION_ID=${PIPELINE_CORRELATION_ID}"
} > "$DRIFT_ENGINE_ENV_FILE"

sr_audit "INFO" "stage_complete" "drift detection completed" "$(sr_build_details \
  --arg  environment        "$ENVIRONMENT" \
  --arg  terraform_workspace "${TF_WORKSPACE:-default}" \
  --argjson drift_detected  "$REPORT_DETECTED" \
  --argjson resources_drifted "$DRIFT_ITEM_COUNT" \
  --argjson engine_exit_code  "$DRIFT_ENGINE_EXIT_CODE" \
  --argjson exceptions_available "$DRIFT_EXCEPTION_COUNT" \
  --arg  report_path        "$DRIFT_REPORT_PATH" \
  --arg  env_file           "$DRIFT_ENGINE_ENV_FILE" \
  '{
    result: {
      drift_detected:       $drift_detected,
      resources_drifted:    $resources_drifted,
      engine_exit_code:     $engine_exit_code,
      exceptions_available: $exceptions_available,
      environment:          $environment,
      terraform_workspace:  $terraform_workspace
    },
    artifacts: {
      report:   $report_path,
      env_file: $env_file
    }
  }')"
