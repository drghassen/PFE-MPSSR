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
sr_require_file "$CUSTODIAN_ENV_FILE" "custodian env"

OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
OPA_REQUIRES_AUTO_REMEDIATION="${OPA_REQUIRES_AUTO_REMEDIATION:-false}"
OPA_PROWLER_REQUIRES_AUTO_REMEDIATION="${OPA_PROWLER_REQUIRES_AUTO_REMEDIATION:-false}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-unknown}"
OPA_PROWLER_CORRELATION_ID="${OPA_PROWLER_CORRELATION_ID:-unknown}"
VERIFICATION_MAX_RETRIES="${VERIFICATION_MAX_RETRIES:-3}"
VERIFICATION_TIMEOUT_SECONDS="${VERIFICATION_TIMEOUT_SECONDS:-30}"

_env_key() {
  local file="$1" key="$2" default="${3:-}"
  local val
  val="$(grep -m1 "^${key}=" "$file" 2>/dev/null | cut -d'=' -f2-)" || true
  printf '%s' "${val:-$default}"
}

CUSTODIAN_DRY_RUN="$(_env_key "$CUSTODIAN_ENV_FILE" "CUSTODIAN_DRY_RUN" "true")"
CUSTODIAN_EXECUTED="$(_env_key "$CUSTODIAN_ENV_FILE" "CUSTODIAN_EXECUTED" "false")"

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
  {
    echo "REMEDIATION_FAILED=false"
    echo "REMEDIATION_SKIP_REASON=no_auto_remediation_required"
  } > "$ENV_FILE"

  jq -cn --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{timestamp:$timestamp, total_candidates:0, verified:0, failed:0, skipped:true, skip_reason:"no_auto_remediation_required"}' > "$SUMMARY_FILE"

  sr_audit "INFO" "skip" "auto-remediation not required" "$(sr_build_details --argjson candidates "$CANDIDATE_COUNT" '{candidates:$candidates}')"
  exit 0
fi

if [[ "$CUSTODIAN_DRY_RUN" == "true" ]]; then
  {
    echo "REMEDIATION_FAILED=false"
    echo "REMEDIATION_SKIP_REASON=custodian_dry_run"
  } > "$ENV_FILE"

  jq -cn --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson candidates "$CANDIDATE_COUNT" '{timestamp:$timestamp, total_candidates:$candidates, verified:0, failed:0, skipped:true, skip_reason:"custodian_dry_run"}' > "$SUMMARY_FILE"

  sr_audit "WARN" "dry_run_skip" "custodian dry-run, verification skipped" "$(sr_build_details --argjson candidates "$CANDIDATE_COUNT" '{candidates:$candidates}')"
  exit 0
fi

if [[ "$CANDIDATE_COUNT" -eq 0 ]]; then
  {
    echo "REMEDIATION_FAILED=false"
    echo "REMEDIATION_SKIP_REASON=no_runtime_candidates"
  } > "$ENV_FILE"

  jq -cn --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{timestamp:$timestamp, total_candidates:0, verified:0, failed:0, skipped:true, skip_reason:"no_runtime_candidates"}' > "$SUMMARY_FILE"

  sr_audit "INFO" "skip" "no runtime remediation candidates found" '{}'
  exit 0
fi

if [[ "$CUSTODIAN_EXECUTED" != "true" ]]; then
  {
    echo "REMEDIATION_FAILED=false"
    echo "REMEDIATION_SKIP_REASON=custodian_not_executed"
  } > "$ENV_FILE"

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

{
  echo "REMEDIATION_FAILED=${remediation_failed}"
  echo "REMEDIATION_SKIP_REASON="
} > "$ENV_FILE"

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
