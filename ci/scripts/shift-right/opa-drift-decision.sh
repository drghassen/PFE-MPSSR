#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
REPORT_PATH="${DRIFT_REPORT_PATH:-shift-right/drift-engine/output/drift-report.json}"
EXCEPTIONS_FILE="${DRIFT_EXCEPTIONS_PATH:-${OUTPUT_DIR}/drift_exceptions.json}"
DECISION_FILE="${OUTPUT_DIR}/opa_drift_decision.json"
INPUT_FILE="${OUTPUT_DIR}/drift_opa_input.json"
ENV_FILE="${OUTPUT_DIR}/opa_drift.env"
OPA_LOG_FILE="${OUTPUT_DIR}/opa_drift_server.log"
AUDIT_FILE="${OUTPUT_DIR}/opa_drift_audit.jsonl"
OPA_AUTH_CONFIG_FILE="${OUTPUT_DIR}/opa_auth_config.json"
OPA_SERVER_ADDR="${OPA_SERVER_ADDR:-127.0.0.1:8282}"
OPA_SERVER_URL="${OPA_SERVER_URL:-http://${OPA_SERVER_ADDR}}"
OPA_DRIFT_POLICY_DIR="${OPA_DRIFT_POLICY_DIR:-policies/opa/drift}"
OPA_SYSTEM_AUTHZ_FILE="${OPA_SYSTEM_AUTHZ_FILE:-policies/opa/system/authz.rego}"
OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
ENVIRONMENT="${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}"
REPO_PATH="${CI_PROJECT_PATH:-unknown}"
BRANCH_NAME="${CI_COMMIT_REF_NAME:-unknown}"
FAIL_CLOSED="${CLOUDSENTINEL_FAIL_CLOSED:-true}"
export OPA_AUTH_TOKEN

mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/drift-decision" "$AUDIT_FILE"
sr_require_command jq curl opa
sr_require_nonempty_file "$REPORT_PATH" "drift report"
sr_require_nonempty_file "$EXCEPTIONS_FILE" "drift exceptions"
sr_require_nonempty_file "$OPA_SYSTEM_AUTHZ_FILE" "OPA authz policy"
sr_require_nonempty_file "$OPA_DRIFT_POLICY_DIR/drift_evaluate.rego" "OPA drift policy"

sr_require_json "$REPORT_PATH" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.drift | type == "object")
  and (.drift.summary | type == "object")
  and (.drift.items | type == "array")
  and (.errors | type == "array")
  and ((.drift.exit_code // null) | type == "number")
  and ((.drift.detected // null) | type == "boolean")
' "drift report"
sr_require_json "$EXCEPTIONS_FILE" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.cloudsentinel.drift_exceptions | type == "object")
  and (.cloudsentinel.drift_exceptions.exceptions | type == "array")
' "drift exceptions"

REPORT_ERROR_COUNT="$(sr_json_number "$REPORT_PATH" '.errors | length' 'drift report')"
DRIFT_INPUT_COUNT="$(sr_json_number "$REPORT_PATH" '.drift.items | length' 'drift report')"
DRIFT_EXIT_CODE="$(sr_json_number "$REPORT_PATH" '.drift.exit_code' 'drift report')"
DRIFT_DETECTED_RAW="$(jq -r '.drift.detected' "$REPORT_PATH")"
EXCEPTION_COUNT="$(sr_json_number "$EXCEPTIONS_FILE" '.cloudsentinel.drift_exceptions.exceptions | length' 'drift exceptions')"

if [[ "$REPORT_ERROR_COUNT" -gt 0 ]]; then
  sr_fail "drift report contains embedded errors; refusing OPA evaluation" 1 "$(jq -cn --argjson report_error_count "$REPORT_ERROR_COUNT" '{report_error_count:$report_error_count}')"
fi
if [[ "$DRIFT_EXIT_CODE" -ne 0 && "$DRIFT_EXIT_CODE" -ne 2 ]]; then
  sr_fail "drift report exit_code is not a valid detection outcome" 1 "$(jq -cn --argjson drift_exit_code "$DRIFT_EXIT_CODE" '{drift_exit_code:$drift_exit_code}')"
fi
if [[ "$DRIFT_DETECTED_RAW" == "true" && "$DRIFT_INPUT_COUNT" -eq 0 ]]; then
  sr_fail "drift report indicates drift but has zero drift items" 1 "$(jq -cn --argjson drift_input_count "$DRIFT_INPUT_COUNT" '{drift_input_count:$drift_input_count}')"
fi
if [[ "$DRIFT_DETECTED_RAW" == "false" && "$DRIFT_INPUT_COUNT" -gt 0 ]]; then
  sr_fail "drift report contains items while detected=false" 1 "$(jq -cn --argjson drift_input_count "$DRIFT_INPUT_COUNT" '{drift_input_count:$drift_input_count}')"
fi

cat > "$OPA_AUTH_CONFIG_FILE" <<EOF_INNER
{"opa_config":{"auth_token":"${OPA_AUTH_TOKEN}","generated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}}
EOF_INNER

sr_audit "INFO" "stage_start" "starting OPA drift decision" "$(jq -cn \
  --arg report_path "$REPORT_PATH" \
  --arg exceptions_file "$EXCEPTIONS_FILE" \
  --arg environment "$ENVIRONMENT" \
  --arg repo "$REPO_PATH" \
  --arg branch "$BRANCH_NAME" \
  --arg opa_server_url "$OPA_SERVER_URL" \
  --argjson drift_input_count "$DRIFT_INPUT_COUNT" \
  --argjson exception_count "$EXCEPTION_COUNT" \
  '{report_path:$report_path,exceptions_file:$exceptions_file,environment:$environment,repo:$repo,branch:$branch,opa_server_url:$opa_server_url,drift_input_count:$drift_input_count,exception_count:$exception_count}')"

opa run --server --addr="$OPA_SERVER_ADDR" \
  --authentication=token \
  --authorization=basic \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  "$OPA_DRIFT_POLICY_DIR" \
  "$OPA_SYSTEM_AUTHZ_FILE" \
  "$EXCEPTIONS_FILE" \
  "$OPA_AUTH_CONFIG_FILE" \
  > "$OPA_LOG_FILE" 2>&1 &
OPA_PID=$!

cleanup() {
  if [[ -n "${OPA_PID:-}" ]] && kill -0 "$OPA_PID" >/dev/null 2>&1; then
    if ! kill "$OPA_PID" >/dev/null 2>&1; then
      sr_audit "WARN" "cleanup" "OPA drift process exited before cleanup completed" '{}'
    fi
  fi
}
trap cleanup EXIT

OPA_READY=false
for _ in {1..15}; do
  if curl -sf "$OPA_SERVER_URL/health" >/dev/null 2>&1; then
    OPA_READY=true
    break
  fi
  sleep 2
done

if [[ "$OPA_READY" != "true" ]]; then
  sr_fail "OPA server failed to start for drift decision" 1 "$(jq -cn --arg log_file "$OPA_LOG_FILE" '{log_file:$log_file}')"
fi

jq -c \
  --arg environment "$ENVIRONMENT" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg repo "$REPO_PATH" \
  --arg branch "$BRANCH_NAME" \
  '{
     input: {
       source: "drift-engine",
       scan_type: "shift-right-drift",
       timestamp: $timestamp,
       environment: $environment,
       repo: $repo,
       branch: $branch,
       meta: {
         mode: "ENFORCING",
         allow_legacy_exceptions: true,
         allow_degraded: false
       },
       findings: [
         (.drift.items // [])[] | {
           address: .address,
           type: .type,
           mode: (.mode // "managed"),
           name: (.name // ""),
           provider_name: (.provider_name // "unknown"),
           actions: (.actions // []),
           resource_id: .address,
           changed_paths: (.changed_paths // [])
         }
       ]
     }
   }' "$REPORT_PATH" > "$INPUT_FILE"

sr_require_json "$INPUT_FILE" '
  type == "object"
  and (.input | type == "object")
  and (.input.meta | type == "object")
  and (.input.findings | type == "array")
  and ((.input.environment // "") | type == "string" and length > 0)
  and ((.input.repo // "") | type == "string" and length > 0)
  and ((.input.branch // "") | type == "string" and length > 0)
' "OPA drift input"

INPUT_COUNT="$(sr_json_number "$INPUT_FILE" '.input.findings | length' 'OPA drift input')"
sr_assert_eq "$INPUT_COUNT" "$DRIFT_INPUT_COUNT" "OPA drift input count mismatch with drift report"

curl -sS -f -X POST \
  "$OPA_SERVER_URL/v1/data/cloudsentinel/shiftright/drift" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${OPA_AUTH_TOKEN}" \
  -d @"$INPUT_FILE" \
  > "$DECISION_FILE"

sr_require_json "$DECISION_FILE" '
  type == "object"
  and (.result | type == "object")
  and ((.result.deny // null) | type == "array")
  and ((.result.violations // null) | type == "array")
' "OPA drift decision"

DENY_COUNT="$(sr_json_number "$DECISION_FILE" '(.result.deny | length)' 'OPA drift decision')"
RAW_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '(.result.violations | length)' 'OPA drift decision')"
EFFECTIVE_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '((.result.effective_violations // .result.violations) | length)' 'OPA drift decision')"
ACTIONABLE_EFFECTIVE_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select(.action_required != "none" and .action_required != "monitor")] | length' 'OPA drift decision')"
EXCEPTED_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '(.result.drift_exception_summary.excepted_violations // 0)' 'OPA drift decision')"
EFFECTIVE_CRITICAL="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "CRITICAL")] | length' 'OPA drift decision')"
EFFECTIVE_HIGH="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "HIGH")] | length' 'OPA drift decision')"
EFFECTIVE_MEDIUM="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "MEDIUM")] | length' 'OPA drift decision')"
EFFECTIVE_LOW="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "LOW")] | length' 'OPA drift decision')"
TOTAL_EXCEPTIONS_LOADED="$(sr_json_number "$DECISION_FILE" '(.result.drift_exception_summary.total_exceptions_loaded // 0)' 'OPA drift decision')"
VALID_EXCEPTIONS="$(sr_json_number "$DECISION_FILE" '(.result.drift_exception_summary.valid_exceptions // 0)' 'OPA drift decision')"
OPA_CUSTODIAN_POLICIES="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select(.action_required != "none" and .custodian_policy != null) | .custodian_policy] | unique | join(",")' "$DECISION_FILE")"

sr_assert_eq "$RAW_VIOLATIONS" "$INPUT_COUNT" "OPA drift violations count does not match input findings"
sr_assert_int_ge "$RAW_VIOLATIONS" "$EFFECTIVE_VIOLATIONS" "OPA drift effective violations exceed raw violations"
sr_assert_int_ge "$EFFECTIVE_VIOLATIONS" "$ACTIONABLE_EFFECTIVE_VIOLATIONS" "OPA drift actionable violations exceed effective violations"

OPA_DRIFT_BLOCK=false
OPA_DRIFT_DENY=false
if [[ "$DENY_COUNT" -gt 0 || "$ACTIONABLE_EFFECTIVE_VIOLATIONS" -gt 0 ]]; then
  OPA_DRIFT_BLOCK=true
fi
if [[ "$DENY_COUNT" -gt 0 ]]; then
  OPA_DRIFT_DENY=true
fi

{
  echo "OPA_DRIFT_BLOCK=${OPA_DRIFT_BLOCK}"
  echo "OPA_DRIFT_DENY=${OPA_DRIFT_DENY}"
  echo "OPA_DENY_COUNT=${DENY_COUNT}"
  echo "OPA_DECISION_MODE=ENFORCING"
  echo "OPA_FAIL_CLOSED=${FAIL_CLOSED}"
  echo "OPA_RAW_VIOLATIONS=${RAW_VIOLATIONS}"
  echo "OPA_EFFECTIVE_VIOLATIONS=${EFFECTIVE_VIOLATIONS}"
  echo "OPA_ACTIONABLE_EFFECTIVE_VIOLATIONS=${ACTIONABLE_EFFECTIVE_VIOLATIONS}"
  echo "OPA_EXCEPTED_VIOLATIONS=${EXCEPTED_VIOLATIONS}"
  echo "OPA_CUSTODIAN_POLICIES=${OPA_CUSTODIAN_POLICIES}"
  echo "OPA_DRIFT_INPUT_COUNT=${INPUT_COUNT}"
  echo "OPA_DRIFT_EXCEPTION_COUNT=${EXCEPTION_COUNT}"
  echo "OPA_DRIFT_VALID_EXCEPTIONS=${VALID_EXCEPTIONS}"
  echo "OPA_DRIFT_TOTAL_EXCEPTIONS_LOADED=${TOTAL_EXCEPTIONS_LOADED}"
} > "$ENV_FILE"

sr_audit "INFO" "stage_complete" "OPA drift decision completed" "$(jq -cn \
  --arg decision_file "$DECISION_FILE" \
  --arg env_file "$ENV_FILE" \
  --arg block "$OPA_DRIFT_BLOCK" \
  --arg deny "$OPA_DRIFT_DENY" \
  --arg fail_closed "$FAIL_CLOSED" \
  --argjson input_count "$INPUT_COUNT" \
  --argjson raw_violations "$RAW_VIOLATIONS" \
  --argjson effective_violations "$EFFECTIVE_VIOLATIONS" \
  --argjson actionable_violations "$ACTIONABLE_EFFECTIVE_VIOLATIONS" \
  --argjson deny_count "$DENY_COUNT" \
  '{decision_file:$decision_file,env_file:$env_file,block:$block,deny:$deny,fail_closed:$fail_closed,input_count:$input_count,raw_violations:$raw_violations,effective_violations:$effective_violations,actionable_violations:$actionable_violations,deny_count:$deny_count}')"
