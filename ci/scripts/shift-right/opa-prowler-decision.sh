#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
REPORT_PATH="${PROWLER_REPORT_PATH:-shift-right/prowler/output/prowler-report.json}"
EXCEPTIONS_FILE="${PROWLER_EXCEPTIONS_PATH:-${OUTPUT_DIR}/prowler_exceptions.json}"
DECISION_FILE="${OUTPUT_DIR}/opa_prowler_decision.json"
INPUT_FILE="${OUTPUT_DIR}/prowler_opa_input.json"
ENV_FILE="${OUTPUT_DIR}/opa_prowler.env"
OPA_LOG_FILE="${OUTPUT_DIR}/opa_prowler_server.log"
AUDIT_FILE="${OUTPUT_DIR}/opa_prowler_audit.jsonl"
OPA_AUTH_CONFIG_FILE="${OUTPUT_DIR}/opa_prowler_auth_config.json"
OPA_SERVER_ADDR="${OPA_PROWLER_SERVER_ADDR:-127.0.0.1:8383}"
OPA_SERVER_URL="${OPA_PROWLER_SERVER_URL:-http://${OPA_SERVER_ADDR}}"
OPA_PROWLER_POLICY_DIR="${OPA_PROWLER_POLICY_DIR:-policies/opa/prowler}"
OPA_SYSTEM_AUTHZ_FILE="${OPA_SYSTEM_AUTHZ_FILE:-policies/opa/system/authz.rego}"
REMEDIATION_CAPABILITIES_FILE="${REMEDIATION_CAPABILITIES_FILE:-config/remediation-capabilities.json}"
OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
ENVIRONMENT="${PROWLER_ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-production}}"
REPO_PATH="${CI_PROJECT_PATH:-unknown}"
BRANCH_NAME="${CI_COMMIT_REF_NAME:-unknown}"
FAIL_CLOSED="${CLOUDSENTINEL_FAIL_CLOSED:-true}"
export OPA_AUTH_TOKEN

mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/prowler-decision" "$AUDIT_FILE"
sr_require_command jq curl opa
sr_require_nonempty_file "$REPORT_PATH" "prowler report"
sr_require_nonempty_file "$EXCEPTIONS_FILE" "prowler exceptions"
sr_require_nonempty_file "$OPA_SYSTEM_AUTHZ_FILE" "OPA authz policy"
sr_require_nonempty_file "$OPA_PROWLER_POLICY_DIR/prowler_evaluate.rego" "OPA prowler policy"
sr_require_nonempty_file "$REMEDIATION_CAPABILITIES_FILE" "remediation capabilities registry"

sr_require_json "$REPORT_PATH" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.prowler | type == "object")
  and (.prowler.summary | type == "object")
  and (.prowler.items | type == "array")
  and (.errors | type == "array")
  and (.prowler.detected | type == "boolean")
' "prowler report"

sr_require_json "$EXCEPTIONS_FILE" '
  type == "object"
  and (.cloudsentinel | type == "object")
  and (.cloudsentinel.prowler_exceptions | type == "object")
  and (.cloudsentinel.prowler_exceptions.exceptions | type == "array")
' "prowler exceptions"
sr_require_json "$REMEDIATION_CAPABILITIES_FILE" '
  type == "object"
  and (.capabilities | type == "object")
' "remediation capabilities registry"

REPORT_ERROR_COUNT="$(sr_json_number "$REPORT_PATH" '.errors | length' 'prowler report')"
PROWLER_INPUT_COUNT="$(sr_json_number "$REPORT_PATH" '.prowler.items | length' 'prowler report')"
PROWLER_FAIL_COUNT="$(sr_json_number "$REPORT_PATH" '.prowler.summary.fail_count' 'prowler report')"
PROWLER_DETECTED_RAW="$(jq -r '.prowler.detected' "$REPORT_PATH")"
CORRELATION_ID="$(jq -r '.cloudsentinel.correlation_id // .cloudsentinel.run_id // "unknown"' "$REPORT_PATH")"
PIPELINE_CORRELATION_ID="$(sr_pipeline_correlation_id)"
if [[ -n "$PIPELINE_CORRELATION_ID" && "$PIPELINE_CORRELATION_ID" != "unknown" ]]; then
  CORRELATION_ID="$PIPELINE_CORRELATION_ID"
fi
EXCEPTION_COUNT="$(sr_json_number "$EXCEPTIONS_FILE" '.cloudsentinel.prowler_exceptions.exceptions | length' 'prowler exceptions')"

sr_assert_eq "$PROWLER_FAIL_COUNT" "$PROWLER_INPUT_COUNT" "prowler report fail_count mismatch with items"
if [[ "$REPORT_ERROR_COUNT" -gt 0 ]]; then
  sr_fail "prowler report contains embedded errors; refusing OPA evaluation" 1 "$(jq -cn --argjson report_error_count "$REPORT_ERROR_COUNT" '{report_error_count:$report_error_count}')"
fi
if [[ "$PROWLER_DETECTED_RAW" == "true" && "$PROWLER_INPUT_COUNT" -eq 0 ]]; then
  sr_fail "prowler report indicates findings but has zero items" 1 "$(jq -cn --argjson prowler_input_count "$PROWLER_INPUT_COUNT" '{prowler_input_count:$prowler_input_count}')"
fi
if [[ "$PROWLER_DETECTED_RAW" == "false" && "$PROWLER_INPUT_COUNT" -gt 0 ]]; then
  sr_fail "prowler report contains items while detected=false" 1 "$(jq -cn --argjson prowler_input_count "$PROWLER_INPUT_COUNT" '{prowler_input_count:$prowler_input_count}')"
fi

cat > "$OPA_AUTH_CONFIG_FILE" <<EOF_INNER
{"opa_config":{"auth_token":"${OPA_AUTH_TOKEN}","generated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}}
EOF_INNER

sr_audit "INFO" "stage_start" "starting OPA prowler decision" "$(sr_build_details \
  --arg  environment "$ENVIRONMENT" \
  --arg  repo "$REPO_PATH" \
  --arg  branch "$BRANCH_NAME" \
  --arg  mode "ENFORCING" \
  --arg  fail_closed "$FAIL_CLOSED" \
  --argjson prowler_findings "$PROWLER_INPUT_COUNT" \
  --argjson exceptions_loaded "$EXCEPTION_COUNT" \
  --arg  correlation_id "$CORRELATION_ID" \
  --arg  opa_server_url "$OPA_SERVER_URL" \
  '{
    evaluation_context: {
      environment: $environment,
      repo: $repo,
      branch: $branch,
      mode: $mode,
      fail_closed: ($fail_closed == "true")
    },
    input_summary: {
      prowler_findings: $prowler_findings,
      exceptions_loaded: $exceptions_loaded
    },
    correlation_id: $correlation_id,
    opa_server: $opa_server_url
  }')"

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
  --arg repo "$REPO_PATH" \
  --arg branch "$BRANCH_NAME" \
  --arg correlation_id "$CORRELATION_ID" \
  --slurpfile capabilities "$REMEDIATION_CAPABILITIES_FILE" \
  '{
     input: {
       source: "prowler",
       scan_type: "shift-right-prowler",
       correlation_id: $correlation_id,
       timestamp: $timestamp,
       environment: $environment,
       repo: $repo,
       branch: $branch,
       meta: {
         mode: "ENFORCING",
         allow_legacy_exceptions: true,
         allow_degraded: false
       },
       capabilities: (($capabilities[0].capabilities // {})),
       findings: [
         (.prowler.items // [])[] | {
           check_id: .check_id,
           check_uid: (.check_uid // ""),
           title: (.title // "Prowler finding"),
           resource_id: .resource_id,
           resource_type: (.resource_type // "unknown"),
           region: (.region // "global"),
           provider: (.provider // "azure"),
           severity: (.severity // "LOW"),
           status_code: (.status_code // "FAIL"),
           status_detail: (.status_detail // ""),
           correlation_id: $correlation_id
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
  and ((.input.correlation_id // "") | type == "string" and length > 0)
' "OPA prowler input"

INPUT_COUNT="$(sr_json_number "$INPUT_FILE" '.input.findings | length' 'OPA prowler input')"
sr_assert_eq "$INPUT_COUNT" "$PROWLER_INPUT_COUNT" "OPA prowler input count mismatch with report"

curl -sS -f -X POST \
  "$OPA_SERVER_URL/v1/data/cloudsentinel/shiftright/prowler" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${OPA_AUTH_TOKEN}" \
  -d @"$INPUT_FILE" \
  > "$DECISION_FILE"

sr_require_json "$DECISION_FILE" '
  type == "object"
  and (.result | type == "object")
  and ((.result.deny // null) | type == "array")
  and ((.result.violations // null) | type == "array")
' "OPA prowler decision"

DENY_COUNT="$(sr_json_number "$DECISION_FILE" '(.result.deny | length)' 'OPA prowler decision')"
RAW_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '(.result.violations | length)' 'OPA prowler decision')"
EFFECTIVE_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '((.result.effective_violations // .result.violations) | length)' 'OPA prowler decision')"
ACTIONABLE_EFFECTIVE_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "CRITICAL" or (.severity // "") == "HIGH")] | length' 'OPA prowler decision')"
MANUAL_REVIEW_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.manual_review_required // false) == true)] | length' 'OPA prowler decision')"
AUTO_REMEDIATION_CANDIDATES="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.requires_remediation // false) == true)] | length' 'OPA prowler decision')"
NON_REMEDIABLE_ACTIONABLE_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select(((.severity // "") == "CRITICAL" or (.severity // "") == "HIGH") and ((.requires_remediation // false) == false))] | length' 'OPA prowler decision')"
MANUAL_ONLY_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.manual_review_required // false) == true and ((.severity // "") != "CRITICAL" and (.severity // "") != "HIGH"))] | length' 'OPA prowler decision')"
EXCEPTED_VIOLATIONS="$(sr_json_number "$DECISION_FILE" '(.result.prowler_exception_summary.excepted_violations // 0)' 'OPA prowler decision')"
EFFECTIVE_CRITICAL="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "CRITICAL")] | length' 'OPA prowler decision')"
EFFECTIVE_HIGH="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "HIGH")] | length' 'OPA prowler decision')"
EFFECTIVE_MEDIUM="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "MEDIUM")] | length' 'OPA prowler decision')"
EFFECTIVE_LOW="$(sr_json_number "$DECISION_FILE" '[((.result.effective_violations // .result.violations) // [])[] | select((.severity // "") == "LOW")] | length' 'OPA prowler decision')"
L0_COUNT="$(sr_json_number "$DECISION_FILE" '(.result.l0_count // 0)' "OPA prowler decision")"
L1_COUNT="$(sr_json_number "$DECISION_FILE" '(.result.l1_count // 0)' "OPA prowler decision")"
L2_COUNT="$(sr_json_number "$DECISION_FILE" '(.result.l2_count // 0)' "OPA prowler decision")"
L3_COUNT="$(sr_json_number "$DECISION_FILE" '(.result.l3_count // 0)' "OPA prowler decision")"
BLOCK_REASON="$(jq -r '.result.block_reason // "none"' "$DECISION_FILE")"
TOTAL_EXCEPTIONS_LOADED="$(sr_json_number "$DECISION_FILE" '(.result.prowler_exception_summary.total_exceptions_loaded // 0)' 'OPA prowler decision')"
VALID_EXCEPTIONS="$(sr_json_number "$DECISION_FILE" '(.result.prowler_exception_summary.valid_exceptions // 0)' 'OPA prowler decision')"
OPA_PROWLER_CUSTODIAN_POLICIES="$(jq -r '[(.result.effective_violations // .result.violations // [])[] | select((.requires_remediation // false) == true and .custodian_policy != null) | .custodian_policy] | unique | join(",")' "$DECISION_FILE")"
OPA_PROWLER_CORRELATION_ID="$(jq -r '.result.correlation_id // "unknown"' "$DECISION_FILE")"
if [[ "$OPA_PROWLER_CORRELATION_ID" == "unknown" ]]; then
  OPA_PROWLER_CORRELATION_ID="$CORRELATION_ID"
fi

sr_assert_eq "$RAW_VIOLATIONS" "$INPUT_COUNT" "OPA prowler violations count does not match input findings"
sr_assert_int_ge "$RAW_VIOLATIONS" "$EFFECTIVE_VIOLATIONS" "OPA prowler effective violations exceed raw violations"
sr_assert_int_ge "$EFFECTIVE_VIOLATIONS" "$ACTIONABLE_EFFECTIVE_VIOLATIONS" "OPA prowler actionable violations exceed effective violations"
sr_assert_int_ge "$EFFECTIVE_VIOLATIONS" "$MANUAL_REVIEW_VIOLATIONS" "OPA prowler manual-review violations exceed effective violations"
sr_assert_int_ge "$ACTIONABLE_EFFECTIVE_VIOLATIONS" "$NON_REMEDIABLE_ACTIONABLE_VIOLATIONS" "OPA prowler non-remediable actionable violations exceed actionable violations"

OPA_PROWLER_BLOCK=false
OPA_PROWLER_DENY=false
OPA_PROWLER_BLOCK_REASON="$BLOCK_REASON"
OPA_PROWLER_BLOCK_MANUAL_ONLY=false
OPA_PROWLER_BLOCK_REQUIRES_CUSTODIAN=false
OPA_PROWLER_REQUIRES_AUTO_REMEDIATION=false
OPA_PROWLER_REQUIRES_TICKET=false
if [[ "$DENY_COUNT" -gt 0 || "$L2_COUNT" -gt 0 || "$L3_COUNT" -gt 0 ]]; then
  OPA_PROWLER_BLOCK=true
fi
if [[ "$DENY_COUNT" -gt 0 ]]; then
  OPA_PROWLER_DENY=true
fi
if [[ "$BLOCK_REASON" == "manual_review_only" ]]; then
  OPA_PROWLER_BLOCK_MANUAL_ONLY=true
fi
if [[ "$L3_COUNT" -gt 0 ]]; then
  OPA_PROWLER_BLOCK_REQUIRES_CUSTODIAN=true
  OPA_PROWLER_REQUIRES_AUTO_REMEDIATION=true
fi
if [[ "$L2_COUNT" -gt 0 || "$L3_COUNT" -gt 0 ]]; then
  OPA_PROWLER_REQUIRES_TICKET=true
fi

# ── OPA Policy Decision Table ───────────────────────────────────────────────
{
  printf '┌────────────────────────────────────────────────────────────────────────────────┐\n'
  printf '│ %-78s │\n' "CloudSentinel OPA — Prowler Policy Evaluation"
  printf '│ %-78s │\n' "Mode: ENFORCING  |  Fail-closed: ${FAIL_CLOSED}  |  Env: ${ENVIRONMENT}  |  Branch: ${BRANCH_NAME}"
  printf '├────────────────────────────────────────────────────────────────────────────────┤\n'
  if [[ "$OPA_PROWLER_BLOCK" == "true" ]]; then
    if [[ "$OPA_PROWLER_BLOCK_REASON" == "manual_review_only" ]]; then
      printf '│ %-78s │\n' "  DECISION: BLOCK  <<< pipeline blocked — manual-review-only findings"
    else
      printf '│ %-78s │\n' "  DECISION: BLOCK  <<< pipeline blocked — actionable violations found"
    fi
  else
    printf '│ %-78s │\n' "  DECISION: ALLOW  — no gate-blocking violations"
  fi
  printf '│ %-78s │\n' \
    "  Deny: ${OPA_PROWLER_DENY}  |  Deny count: ${DENY_COUNT}  |  Raw: ${RAW_VIOLATIONS}  |  Effective: ${EFFECTIVE_VIOLATIONS}  |  Actionable: ${ACTIONABLE_EFFECTIVE_VIOLATIONS}  |  ManualReview: ${MANUAL_REVIEW_VIOLATIONS}"
  printf '│ %-78s │\n' \
    "  Severity — CRITICAL: ${EFFECTIVE_CRITICAL}  HIGH: ${EFFECTIVE_HIGH}  MEDIUM: ${EFFECTIVE_MEDIUM}  LOW: ${EFFECTIVE_LOW}  |  Excepted: ${EXCEPTED_VIOLATIONS}"
  printf '└────────────────────────────────────────────────────────────────────────────────┘\n'
} >&2

{
  echo "OPA_PROWLER_BLOCK=${OPA_PROWLER_BLOCK}"
  echo "OPA_PROWLER_DENY=${OPA_PROWLER_DENY}"
  echo "OPA_PROWLER_DENY_COUNT=${DENY_COUNT}"
  echo "OPA_PROWLER_DECISION_MODE=ENFORCING"
  echo "OPA_PROWLER_FAIL_CLOSED=${FAIL_CLOSED}"
  echo "OPA_PROWLER_RAW_VIOLATIONS=${RAW_VIOLATIONS}"
  echo "OPA_PROWLER_EFFECTIVE_VIOLATIONS=${EFFECTIVE_VIOLATIONS}"
  echo "OPA_PROWLER_ACTIONABLE_EFFECTIVE_VIOLATIONS=${ACTIONABLE_EFFECTIVE_VIOLATIONS}"
  echo "OPA_PROWLER_MANUAL_REVIEW_VIOLATIONS=${MANUAL_REVIEW_VIOLATIONS}"
  echo "OPA_PROWLER_MANUAL_ONLY_VIOLATIONS=${MANUAL_ONLY_VIOLATIONS}"
  echo "OPA_PROWLER_AUTO_REMEDIATION_CANDIDATES=${AUTO_REMEDIATION_CANDIDATES}"
  echo "OPA_PROWLER_NON_REMEDIABLE_ACTIONABLE_VIOLATIONS=${NON_REMEDIABLE_ACTIONABLE_VIOLATIONS}"
  echo "OPA_PROWLER_EXCEPTED_VIOLATIONS=${EXCEPTED_VIOLATIONS}"
  echo "OPA_PROWLER_INPUT_COUNT=${INPUT_COUNT}"
  echo "OPA_PROWLER_EXCEPTION_COUNT=${EXCEPTION_COUNT}"
  echo "OPA_PROWLER_VALID_EXCEPTIONS=${VALID_EXCEPTIONS}"
  echo "OPA_PROWLER_TOTAL_EXCEPTIONS_LOADED=${TOTAL_EXCEPTIONS_LOADED}"
  echo "OPA_PROWLER_CUSTODIAN_POLICIES=${OPA_PROWLER_CUSTODIAN_POLICIES}"
  echo "OPA_PROWLER_CORRELATION_ID=${OPA_PROWLER_CORRELATION_ID}"
  echo "OPA_PIPELINE_CORRELATION_ID=${CORRELATION_ID}"
  echo "OPA_PROWLER_L0_COUNT=${L0_COUNT}"
  echo "OPA_PROWLER_L1_COUNT=${L1_COUNT}"
  echo "OPA_PROWLER_L2_COUNT=${L2_COUNT}"
  echo "OPA_PROWLER_L3_COUNT=${L3_COUNT}"
  echo "OPA_PROWLER_BLOCK_REASON=${OPA_PROWLER_BLOCK_REASON}"
  echo "OPA_PROWLER_BLOCK_MANUAL_ONLY=${OPA_PROWLER_BLOCK_MANUAL_ONLY}"
  echo "OPA_PROWLER_BLOCK_REQUIRES_CUSTODIAN=${OPA_PROWLER_BLOCK_REQUIRES_CUSTODIAN}"
  echo "OPA_PROWLER_REQUIRES_TICKET=${OPA_PROWLER_REQUIRES_TICKET}"
  echo "OPA_PROWLER_REQUIRES_AUTO_REMEDIATION=${OPA_PROWLER_REQUIRES_AUTO_REMEDIATION}"
  echo "OPA_PROWLER_CRITICAL_COUNT=${EFFECTIVE_CRITICAL}"
  echo "OPA_PROWLER_HIGH_COUNT=${EFFECTIVE_HIGH}"
  echo "OPA_PROWLER_MEDIUM_COUNT=${EFFECTIVE_MEDIUM}"
  echo "OPA_PROWLER_LOW_COUNT=${EFFECTIVE_LOW}"
  echo "OPA_PROWLER_REQUIRES_EMERGENCY_ALERT=$([ "$EFFECTIVE_CRITICAL" -gt 0 ] && echo true || echo false)"
  echo "OPA_PROWLER_REMEDIATION_SCOPE=RUNTIME_CANDIDATES_ONLY"
} > "$ENV_FILE"

sr_audit "INFO" "stage_complete" "OPA prowler decision completed" "$(sr_build_details \
  --arg  block "$OPA_PROWLER_BLOCK" \
  --arg  deny "$OPA_PROWLER_DENY" \
  --arg  mode "ENFORCING" \
  --arg  fail_closed "$FAIL_CLOSED" \
  --argjson raw_violations "$RAW_VIOLATIONS" \
  --argjson effective_violations "$EFFECTIVE_VIOLATIONS" \
  --argjson actionable_violations "$ACTIONABLE_EFFECTIVE_VIOLATIONS" \
  --argjson excepted_violations "$EXCEPTED_VIOLATIONS" \
  --argjson exception_count "$EXCEPTION_COUNT" \
  --arg  decision_file "$DECISION_FILE" \
  --arg  env_file "$ENV_FILE" \
  '{
    decision: {
      block: ($block == "true"),
      deny: ($deny == "true"),
      mode: $mode,
      fail_closed: ($fail_closed == "true")
    },
    metrics: {
      raw_violations: $raw_violations,
      effective_violations: $effective_violations,
      actionable_violations: $actionable_violations,
      excepted_violations: $excepted_violations,
      exceptions_loaded: $exception_count
    },
    artifacts: {
      decision_file: $decision_file,
      env_file: $env_file
    }
  }')"
