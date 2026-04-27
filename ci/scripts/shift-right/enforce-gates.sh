#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/shift_right_enforcement_audit.jsonl"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/enforcement" "$AUDIT_FILE"

OPA_PROWLER_BLOCK="${OPA_PROWLER_BLOCK:-false}"
OPA_DRIFT_BLOCK="${OPA_DRIFT_BLOCK:-false}"
OPA_DRIFT_DENY="${OPA_DRIFT_DENY:-false}"
CORRELATION_CRITICAL_CONFIRMED="${CORRELATION_CRITICAL_CONFIRMED:-0}"
CORRELATION_HIGH_CONFIRMED="${CORRELATION_HIGH_CONFIRMED:-0}"
OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"

sr_audit "INFO" "stage_start" "evaluating final shift-right enforcement gates" "$(jq -cn \
  --arg opa_prowler_block "$OPA_PROWLER_BLOCK" \
  --arg opa_drift_block "$OPA_DRIFT_BLOCK" \
  --arg opa_drift_deny "$OPA_DRIFT_DENY" \
  --arg opa_custodian_policies "$OPA_CUSTODIAN_POLICIES" \
  --argjson correlation_critical_confirmed "$CORRELATION_CRITICAL_CONFIRMED" \
  --argjson correlation_high_confirmed "$CORRELATION_HIGH_CONFIRMED" \
  '{opa_prowler_block:$opa_prowler_block,opa_drift_block:$opa_drift_block,opa_drift_deny:$opa_drift_deny,opa_custodian_policies:$opa_custodian_policies,correlation_critical_confirmed:$correlation_critical_confirmed,correlation_high_confirmed:$correlation_high_confirmed}')"

if [[ "$CORRELATION_CRITICAL_CONFIRMED" -gt 0 ]]; then
  sr_fail "critical cross-signal correlation detected; enforcement blocks pipeline" 1 "$(jq -cn --argjson correlation_critical_confirmed "$CORRELATION_CRITICAL_CONFIRMED" '{correlation_critical_confirmed:$correlation_critical_confirmed}')"
fi

if [[ "$OPA_PROWLER_BLOCK" == "true" ]]; then
  sr_fail "OPA prowler gate blocked the pipeline" 1 '{}'
fi

if [[ "$OPA_DRIFT_DENY" == "true" ]]; then
  sr_fail "OPA drift explicit deny triggered" 1 '{}'
fi

if [[ "$OPA_DRIFT_BLOCK" == "true" ]]; then
  sr_fail "OPA drift gate blocked the pipeline; remediation must be wired before this stage can pass" 1 "$(jq -cn --arg opa_custodian_policies "$OPA_CUSTODIAN_POLICIES" '{opa_custodian_policies:$opa_custodian_policies}')"
fi

sr_audit "INFO" "stage_complete" "all shift-right enforcement gates passed" '{}'
