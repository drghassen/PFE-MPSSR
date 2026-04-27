#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/shift_right_enforcement_audit.jsonl"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/enforcement" "$AUDIT_FILE"

OPA_DRIFT_BLOCK="${OPA_DRIFT_BLOCK:-false}"
OPA_DRIFT_DENY="${OPA_DRIFT_DENY:-false}"
OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"

sr_audit "INFO" "stage_start" "evaluating final shift-right enforcement gates" "$(jq -cn \
  --arg opa_drift_block "$OPA_DRIFT_BLOCK" \
  --arg opa_drift_deny "$OPA_DRIFT_DENY" \
  --arg opa_custodian_policies "$OPA_CUSTODIAN_POLICIES" \
  '{opa_drift_block:$opa_drift_block,opa_drift_deny:$opa_drift_deny,opa_custodian_policies:$opa_custodian_policies}')"

if [[ "$OPA_DRIFT_DENY" == "true" ]]; then
  sr_fail "OPA drift explicit deny triggered" 1 '{}'
fi

if [[ "$OPA_DRIFT_BLOCK" == "true" ]]; then
  sr_fail "OPA drift gate blocked the pipeline; remediation must be wired before this stage can pass" 1 "$(jq -cn --arg opa_custodian_policies "$OPA_CUSTODIAN_POLICIES" '{opa_custodian_policies:$opa_custodian_policies}')"
fi

sr_audit "INFO" "stage_complete" "all shift-right enforcement gates passed" '{}'
