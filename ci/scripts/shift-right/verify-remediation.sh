#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/remediation_verify.jsonl"
ENV_FILE="${OUTPUT_DIR}/remediation_verify.env"
STATE_DIR="${OUTPUT_DIR}/runtime-state"
STATE_FILE="${STATE_DIR}/runtime-state.jsonl"
SUMMARY_FILE="${STATE_DIR}/remediation-summary.json"
DRIFT_DECISION_FILE="${OUTPUT_DIR}/opa_drift_decision.json"
PROWLER_DECISION_FILE="${OUTPUT_DIR}/opa_prowler_decision.json"
CUSTODIAN_ENV_FILE="${OUTPUT_DIR}/custodian.env"

mkdir -p "$OUTPUT_DIR" "$STATE_DIR"
: > "$STATE_FILE"

sr_init_guard "shift-right/verify-remediation" "$AUDIT_FILE"
sr_require_command jq timeout
sr_require_nonempty_file "$DRIFT_DECISION_FILE" "opa drift decision"
sr_require_nonempty_file "$PROWLER_DECISION_FILE" "opa prowler decision"

OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
OPA_DRIFT_L3_COUNT="${OPA_DRIFT_L3_COUNT:-0}"
OPA_PROWLER_L3_COUNT="${OPA_PROWLER_L3_COUNT:-0}"
OPA_REQUIRES_AUTO_REMEDIATION="${OPA_REQUIRES_AUTO_REMEDIATION:-false}"
OPA_PROWLER_REQUIRES_AUTO_REMEDIATION="${OPA_PROWLER_REQUIRES_AUTO_REMEDIATION:-false}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-unknown}"
OPA_PROWLER_CORRELATION_ID="${OPA_PROWLER_CORRELATION_ID:-unknown}"
VERIFICATION_MAX_RETRIES="${VERIFICATION_MAX_RETRIES:-3}"
VERIFICATION_TIMEOUT_SECONDS="${VERIFICATION_TIMEOUT_SECONDS:-30}"
REMEDIATION_FAILED_STATE="false"
REMEDIATION_SKIP_REASON_STATE=""

write_verify_env_file() {
  {
    echo "REMEDIATION_FAILED=${REMEDIATION_FAILED_STATE}"
    echo "REMEDIATION_SKIP_REASON=${REMEDIATION_SKIP_REASON_STATE}"
  } > "$ENV_FILE"
}

trap write_verify_env_file EXIT
write_verify_env_file

_env_key() {
  local file="$1" key="$2" default="${3:-}"
  local val
  val="$(grep -m1 "^${key}=" "$file" 2>/dev/null | cut -d'=' -f2-)" || true
  printf '%s' "${val:-$default}"
}

CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-true}"
CUSTODIAN_EXECUTED="${CUSTODIAN_EXECUTED:-false}"
if [[ -f "$CUSTODIAN_ENV_FILE" ]]; then
  CUSTODIAN_DRY_RUN="$(_env_key "$CUSTODIAN_ENV_FILE" "CUSTODIAN_DRY_RUN" "$CUSTODIAN_DRY_RUN")"
  CUSTODIAN_EXECUTED="$(_env_key "$CUSTODIAN_ENV_FILE" "CUSTODIAN_EXECUTED" "$CUSTODIAN_EXECUTED")"
else
  sr_audit "WARN" "custodian_env_missing" "custodian env artifact missing; using dotenv fallback values" "$(sr_build_details \
    --arg custodian_env_file "$CUSTODIAN_ENV_FILE" \
    --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
    --arg custodian_executed "$CUSTODIAN_EXECUTED" \
    '{custodian_env_file:$custodian_env_file, custodian_dry_run:($custodian_dry_run=="true"), custodian_executed:($custodian_executed=="true")}')"
fi

_emit_runtime_state() {
  local finding_id="$1"
  local policy="$2"
  local severity="$3"
  local status="$4"
  local remediation_attempted="$5"
  local verification_passed="$6"
  local resource_id="$7"
  local correlation_id="$8"
  local reason="${9:-}"

  jq -cn \
    --arg finding_id "$finding_id" \
    --arg policy "$policy" \
    --arg severity "$severity" \
    --arg status "$status" \
    --argjson remediation_attempted "$remediation_attempted" \
    --argjson verification_passed "$verification_passed" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg resource_id "$resource_id" \
    --arg correlation_id "$correlation_id" \
    --arg reason "$reason" \
    '{
      finding_id: $finding_id,
      policy: $policy,
      severity: $severity,
      status: $status,
      remediation_attempted: $remediation_attempted,
      verification_passed: $verification_passed,
      timestamp: $timestamp,
      resource_id: $resource_id,
      correlation_id: $correlation_id,
      reason: $reason
    }' >> "$STATE_FILE"
}

collect_candidates() {
  jq -cn \
    --slurpfile drift "$DRIFT_DECISION_FILE" \
    --slurpfile prowler "$PROWLER_DECISION_FILE" \
    '
      def effective($doc): ($doc.result.effective_violations // $doc.result.violations // []);

      (
        [effective($drift[0])[] | select((.requires_remediation // false) == true)
          | {
              source: "drift",
              finding_id: ("drift:" + (.resource_id // "unknown") + ":" + (.custodian_policy // "none")),
              resource_id: (.resource_id // "unknown"),
              severity: (.severity // "LOW"),
              policy: (.custodian_policy // ""),
              verification_script: (.verification_script // ""),
              correlation_id: (.correlation_id // "unknown")
            }
        ]
        +
        [effective($prowler[0])[] | select((.requires_remediation // false) == true)
          | {
              source: "prowler",
              finding_id: ("prowler:" + (.check_id // "unknown") + ":" + (.resource_id // "unknown")),
              resource_id: (.resource_id // "unknown"),
              severity: (.severity // "LOW"),
              policy: (.custodian_policy // ""),
              verification_script: (.verification_script // ""),
              correlation_id: (.correlation_id // "unknown")
            }
        ]
      )
    '
}

CANDIDATES_JSON="$(collect_candidates)"
CANDIDATE_COUNT="$(jq -r 'length' <<< "$CANDIDATES_JSON")"

if [[ "$OPA_REQUIRES_AUTO_REMEDIATION" != "true" && "$OPA_PROWLER_REQUIRES_AUTO_REMEDIATION" != "true" ]]; then
  REMEDIATION_FAILED_STATE="false"
  REMEDIATION_SKIP_REASON_STATE="no_auto_remediation_required"
  write_verify_env_file

  jq -cn --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{timestamp:$timestamp, total_candidates:0, verified:0, failed:0, skipped:true, skip_reason:"no_auto_remediation_required"}' > "$SUMMARY_FILE"

  sr_audit "INFO" "skip" "no L3 auto-remediation required" "$(sr_build_details \
    --argjson candidates "$CANDIDATE_COUNT" \
    --argjson l3_drift "$OPA_DRIFT_L3_COUNT" \
    --argjson l3_prowler "$OPA_PROWLER_L3_COUNT" \
    '{candidates:$candidates, l3_drift:$l3_drift, l3_prowler:$l3_prowler, remediation_model:"L0-L3"}')"
  exit 0
fi

if [[ "$CUSTODIAN_DRY_RUN" == "true" ]]; then
  REMEDIATION_FAILED_STATE="false"
  REMEDIATION_SKIP_REASON_STATE="custodian_dry_run"
  write_verify_env_file

  jq -cn --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson candidates "$CANDIDATE_COUNT" '{timestamp:$timestamp, total_candidates:$candidates, verified:0, failed:0, skipped:true, skip_reason:"custodian_dry_run"}' > "$SUMMARY_FILE"

  sr_audit "WARN" "dry_run_skip" "custodian dry-run, verification skipped" "$(sr_build_details --argjson candidates "$CANDIDATE_COUNT" '{candidates:$candidates}')"
  exit 0
fi

if [[ "$CANDIDATE_COUNT" -eq 0 ]]; then
  REMEDIATION_FAILED_STATE="false"
  REMEDIATION_SKIP_REASON_STATE="no_runtime_candidates"
  write_verify_env_file

  jq -cn --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{timestamp:$timestamp, total_candidates:0, verified:0, failed:0, skipped:true, skip_reason:"no_runtime_candidates"}' > "$SUMMARY_FILE"

  sr_audit "INFO" "skip" "no runtime remediation candidates found" '{}'
  exit 0
fi

if [[ "$CUSTODIAN_EXECUTED" != "true" ]]; then
  REMEDIATION_FAILED_STATE="false"
  REMEDIATION_SKIP_REASON_STATE="custodian_not_executed"
  write_verify_env_file

  jq -cn --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson candidates "$CANDIDATE_COUNT" '{timestamp:$timestamp, total_candidates:$candidates, verified:0, failed:0, skipped:true, skip_reason:"custodian_not_executed"}' > "$SUMMARY_FILE"

  sr_audit "WARN" "skip" "custodian did not execute, verification skipped" "$(sr_build_details --argjson candidates "$CANDIDATE_COUNT" '{candidates:$candidates}')"
  exit 0
fi

sr_audit "INFO" "verify_start" "starting post-remediation verification" "$(sr_build_details \
  --argjson drift_critical "$OPA_DRIFT_CRITICAL_COUNT" \
  --argjson prowler_critical "$OPA_PROWLER_CRITICAL_COUNT" \
  --argjson candidates "$CANDIDATE_COUNT" \
  '{drift_critical:$drift_critical, prowler_critical:$prowler_critical, candidates:$candidates}')"

verified_count=0
failed_count=0

while IFS= read -r candidate; do
  [[ -z "$candidate" ]] && continue

  finding_id="$(jq -r '.finding_id' <<< "$candidate")"
  policy="$(jq -r '.policy' <<< "$candidate")"
  severity="$(jq -r '.severity' <<< "$candidate")"
  resource_id="$(jq -r '.resource_id' <<< "$candidate")"
  verification_script="$(jq -r '.verification_script' <<< "$candidate")"
  correlation_id="$(jq -r '.correlation_id' <<< "$candidate")"

  _emit_runtime_state "$finding_id" "$policy" "$severity" "DETECTED" false false "$resource_id" "$correlation_id" "finding_detected"
  _emit_runtime_state "$finding_id" "$policy" "$severity" "DECIDED" false false "$resource_id" "$correlation_id" "runtime_remediation_decided"

  if [[ -z "$policy" || "$policy" == "null" ]]; then
    _emit_runtime_state "$finding_id" "$policy" "$severity" "FAILED" true false "$resource_id" "$correlation_id" "missing_custodian_policy"
    failed_count=$((failed_count + 1))
    continue
  fi

  if [[ -z "$verification_script" || "$verification_script" == "null" ]]; then
    _emit_runtime_state "$finding_id" "$policy" "$severity" "FAILED" true false "$resource_id" "$correlation_id" "missing_verification_script"
    failed_count=$((failed_count + 1))
    continue
  fi

  if verification/run_verification.sh \
      --script "$verification_script" \
      --resource-id "$resource_id" \
      --finding-id "$finding_id" \
      --policy "$policy" \
      --severity "$severity" \
      --correlation-id "$correlation_id" \
      --max-retries "$VERIFICATION_MAX_RETRIES" \
      --timeout-seconds "$VERIFICATION_TIMEOUT_SECONDS"; then
    verified_count=$((verified_count + 1))
  else
    failed_count=$((failed_count + 1))
  fi
done < <(jq -c '.[]' <<< "$CANDIDATES_JSON")

if [[ "$failed_count" -gt 0 ]]; then
  remediation_failed=true
else
  remediation_failed=false
fi

REMEDIATION_FAILED_STATE="${remediation_failed}"
REMEDIATION_SKIP_REASON_STATE=""
write_verify_env_file

jq -cn \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson total_candidates "$CANDIDATE_COUNT" \
  --argjson verified "$verified_count" \
  --argjson failed "$failed_count" \
  --arg remediation_failed "$remediation_failed" \
  '{
    timestamp: $timestamp,
    total_candidates: $total_candidates,
    verified: $verified,
    failed: $failed,
    remediation_failed: ($remediation_failed == "true")
  }' > "$SUMMARY_FILE"

sr_audit "INFO" "stage_complete" "post-remediation verification completed" "$(sr_build_details \
  --argjson total_candidates "$CANDIDATE_COUNT" \
  --argjson verified "$verified_count" \
  --argjson failed "$failed_count" \
  --arg remediation_failed "$remediation_failed" \
  --arg state_file "$STATE_FILE" \
  --arg summary_file "$SUMMARY_FILE" \
  '{
    total_candidates: $total_candidates,
    verified: $verified,
    failed: $failed,
    remediation_failed: ($remediation_failed == "true"),
    artifacts: {state_file:$state_file, summary_file:$summary_file}
  }')"

exit 0
