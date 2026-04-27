#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
FINDINGS_FILE="${PROWLER_FINDINGS_PATH:-${OUTPUT_DIR}/prowler_generic_findings.json}"
EXCEPTIONS_FILE="${PROWLER_EXCEPTIONS_PATH:-${OUTPUT_DIR}/prowler_exceptions.json}"
DECISION_FILE="${OUTPUT_DIR}/opa_prowler_decision.json"
INPUT_FILE="${OUTPUT_DIR}/prowler_opa_input.json"
ENV_FILE="${OUTPUT_DIR}/opa_prowler.env"
OPA_LOG_FILE="${OUTPUT_DIR}/opa_prowler_server.log"
AUDIT_FILE="${OUTPUT_DIR}/opa_prowler_audit.jsonl"
OPA_AUTH_CONFIG_FILE="${OUTPUT_DIR}/opa_prowler_auth_config.json"
OPA_SERVER_ADDR="${OPA_PROWLER_SERVER_ADDR:-127.0.0.1:8383}"
OPA_SERVER_URL="http://${OPA_SERVER_ADDR}"
OPA_PROWLER_POLICY_DIR="${OPA_PROWLER_POLICY_DIR:-policies/opa/prowler}"
OPA_SYSTEM_AUTHZ_FILE="${OPA_SYSTEM_AUTHZ_FILE:-policies/opa/system/authz.rego}"
OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
ENVIRONMENT="${DRIFT_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}"
export OPA_AUTH_TOKEN

mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/prowler-decision" "$AUDIT_FILE"
sr_require_command jq curl opa
sr_require_nonempty_file "$FINDINGS_FILE" "prowler normalized findings"
sr_require_nonempty_file "$EXCEPTIONS_FILE" "prowler exceptions"
sr_require_nonempty_file "$OPA_SYSTEM_AUTHZ_FILE" "OPA authz policy"
sr_require_nonempty_file "$OPA_PROWLER_POLICY_DIR/prowler_decision.rego" "OPA prowler decision policy"

sr_require_json "$FINDINGS_FILE" '
  type == "object"
  and (.meta | type == "object")
  and (.findings | type == "array")
  and ((.meta.raw_record_count // null) | type == "number")
  and ((.meta.raw_fail_count // null) | type == "number")
  and ((.meta.normalized_findings_count // null) | type == "number")
' "prowler normalized findings"
sr_require_json "$EXCEPTIONS_FILE" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.cloudsentinel.prowler_exceptions | type == "object")
  and (.cloudsentinel.prowler_exceptions.exceptions | type == "array")
' "prowler exceptions"

INPUT_COUNT="$(sr_json_number "$FINDINGS_FILE" '.findings | length' 'prowler normalized findings')"
RAW_RECORD_COUNT="$(sr_json_number "$FINDINGS_FILE" '.meta.raw_record_count' 'prowler normalized findings')"
RAW_FAIL_COUNT="$(sr_json_number "$FINDINGS_FILE" '.meta.raw_fail_count' 'prowler normalized findings')"
META_NORMALIZED_COUNT="$(sr_json_number "$FINDINGS_FILE" '.meta.normalized_findings_count' 'prowler normalized findings')"
EXCEPTION_COUNT="$(sr_json_number "$EXCEPTIONS_FILE" '.cloudsentinel.prowler_exceptions.exceptions | length' 'prowler exceptions')"

sr_assert_int_ge "$RAW_RECORD_COUNT" 1 "prowler decision input has zero raw records"
sr_assert_eq "$INPUT_COUNT" "$META_NORMALIZED_COUNT" "prowler decision input metadata count mismatch"
sr_assert_eq "$INPUT_COUNT" "$RAW_FAIL_COUNT" "prowler decision input lost FAIL findings"
sr_assert_positive_if_expected "$RAW_FAIL_COUNT" "$INPUT_COUNT" "prowler decision received empty findings after non-empty raw FAIL set"

cat > "$OPA_AUTH_CONFIG_FILE" <<EOF_INNER
{"opa_config":{"auth_token":"${OPA_AUTH_TOKEN}","generated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}}
EOF_INNER

sr_audit "INFO" "stage_start" "starting OPA prowler decision" "$(jq -cn \
  --arg findings_file "$FINDINGS_FILE" \
  --arg exceptions_file "$EXCEPTIONS_FILE" \
  --arg environment "$ENVIRONMENT" \
  --arg opa_server_url "$OPA_SERVER_URL" \
  --argjson input_count "$INPUT_COUNT" \
  --argjson exception_count "$EXCEPTION_COUNT" \
  '{findings_file:$findings_file,exceptions_file:$exceptions_file,environment:$environment,opa_server_url:$opa_server_url,input_count:$input_count,exception_count:$exception_count}')"

opa run --server --addr="$OPA_SERVER_ADDR" \
  --authentication=token \
  --authorization=basic \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  "$OPA_PROWLER_POLICY_DIR" \
  "$OPA_SYSTEM_AUTHZ_FILE" \
  "$EXCEPTIONS_FILE" \
  "$OPA_AUTH_CONFIG_FILE" \
  > "$OPA_LOG_FILE" 2>&1 &
OPA_PID=$!

cleanup() {
  if [[ -n "${OPA_PID:-}" ]] && kill -0 "$OPA_PID" >/dev/null 2>&1; then
    if ! kill "$OPA_PID" >/dev/null 2>&1; then
      sr_audit "WARN" "cleanup" "OPA prowler process exited before cleanup completed" '{}'
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
  sr_fail "OPA server failed to start for prowler decision" 1 "$(jq -cn --arg log_file "$OPA_LOG_FILE" '{log_file:$log_file}')"
fi

jq -c \
  --arg environment "$ENVIRONMENT" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    input: {
      source: "prowler",
      scan_type: "shift-right-prowler",
      timestamp: $timestamp,
      environment: $environment,
      findings: (.findings // [])
    }
  }' "$FINDINGS_FILE" > "$INPUT_FILE"

sr_require_json "$INPUT_FILE" '
  type == "object"
  and (.input | type == "object")
  and (.input.findings | type == "array")
  and ((.input.environment // "") | type == "string" and length > 0)
' "OPA prowler input"

curl -sS -f -X POST \
  "$OPA_SERVER_URL/v1/data/cloudsentinel/shiftright/prowler/decision" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${OPA_AUTH_TOKEN}" \
  -d @"$INPUT_FILE" \
  > "$DECISION_FILE"

sr_require_json "$DECISION_FILE" '
  type == "object"
  and (.result | type == "object")
  and ((.result.allow // null) | type == "boolean")
  and ((.result.deny // null) | type == "array")
  and ((.result.violations // null) | type == "array")
  and ((.result.effective_violations // null) | type == "array")
  and ((.result.actionable_violations // null) | type == "array")
  and (.result.metrics | type == "object")
  and ((.result.metrics.total // null) | type == "number")
' "OPA prowler decision"

TOTAL="$(sr_json_number "$DECISION_FILE" '.result.metrics.total' 'OPA prowler decision')"
EFFECTIVE="$(sr_json_number "$DECISION_FILE" '.result.metrics.effective' 'OPA prowler decision')"
ACTIONABLE="$(sr_json_number "$DECISION_FILE" '.result.metrics.actionable' 'OPA prowler decision')"
CRITICAL="$(sr_json_number "$DECISION_FILE" '.result.metrics.critical' 'OPA prowler decision')"
HIGH="$(sr_json_number "$DECISION_FILE" '.result.metrics.high' 'OPA prowler decision')"
MEDIUM="$(sr_json_number "$DECISION_FILE" '.result.metrics.medium' 'OPA prowler decision')"
LOW="$(sr_json_number "$DECISION_FILE" '.result.metrics.low' 'OPA prowler decision')"
DENY_COUNT="$(sr_json_number "$DECISION_FILE" '(.result.deny | length)' 'OPA prowler decision')"
ALLOW_VALUE="$(jq -r '.result.allow' "$DECISION_FILE")"

sr_assert_eq "$TOTAL" "$INPUT_COUNT" "OPA prowler decision total count does not match input findings"
sr_assert_int_ge "$TOTAL" "$EFFECTIVE" "OPA prowler effective count exceeds total"
sr_assert_int_ge "$EFFECTIVE" "$ACTIONABLE" "OPA prowler actionable count exceeds effective"

if [[ "$ACTIONABLE" -gt 0 && "$ALLOW_VALUE" != "false" ]]; then
  sr_fail "OPA prowler decision is inconsistent: actionable violations with allow=true" 1 "$(jq -cn --argjson actionable "$ACTIONABLE" --arg allow "$ALLOW_VALUE" '{actionable:$actionable,allow:$allow}')"
fi

OPA_PROWLER_BLOCK=false
if [[ "$ACTIONABLE" -gt 0 || "$DENY_COUNT" -gt 0 ]]; then
  OPA_PROWLER_BLOCK=true
fi

{
  echo "OPA_PROWLER_BLOCK=${OPA_PROWLER_BLOCK}"
  echo "OPA_PROWLER_VIOLATIONS=${TOTAL}"
  echo "OPA_PROWLER_EFFECTIVE_VIOLATIONS=${EFFECTIVE}"
  echo "OPA_PROWLER_ACTIONABLE_VIOLATIONS=${ACTIONABLE}"
  echo "OPA_PROWLER_CRITICAL=${CRITICAL}"
  echo "OPA_PROWLER_HIGH=${HIGH}"
  echo "OPA_PROWLER_MEDIUM=${MEDIUM}"
  echo "OPA_PROWLER_LOW=${LOW}"
  echo "OPA_PROWLER_INPUT_COUNT=${INPUT_COUNT}"
  echo "OPA_PROWLER_EXCEPTION_COUNT=${EXCEPTION_COUNT}"
} > "$ENV_FILE"

sr_audit "INFO" "stage_complete" "OPA prowler decision completed" "$(jq -cn \
  --arg decision_file "$DECISION_FILE" \
  --arg env_file "$ENV_FILE" \
  --arg allow "$ALLOW_VALUE" \
  --arg block "$OPA_PROWLER_BLOCK" \
  --argjson input_count "$INPUT_COUNT" \
  --argjson total "$TOTAL" \
  --argjson effective "$EFFECTIVE" \
  --argjson actionable "$ACTIONABLE" \
  --argjson deny_count "$DENY_COUNT" \
  '{decision_file:$decision_file,env_file:$env_file,allow:$allow,block:$block,input_count:$input_count,total:$total,effective:$effective,actionable:$actionable,deny_count:$deny_count}')"
