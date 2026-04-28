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
OPA_PROWLER_BLOCK="${OPA_PROWLER_BLOCK:-false}"
OPA_PROWLER_DENY="${OPA_PROWLER_DENY:-false}"
OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
REMEDIATION_FAILED="${REMEDIATION_FAILED:-false}"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-true}"

TOTAL_CRITICAL=$((OPA_DRIFT_CRITICAL_COUNT + OPA_PROWLER_CRITICAL_COUNT))

sr_audit "INFO" "stage_start" "evaluating final shift-right enforcement gates" "$(jq -cn \
  --arg opa_drift_block "$OPA_DRIFT_BLOCK" \
  --arg opa_drift_deny "$OPA_DRIFT_DENY" \
  --arg opa_custodian_policies "$OPA_CUSTODIAN_POLICIES" \
  --arg opa_prowler_block "$OPA_PROWLER_BLOCK" \
  --arg opa_prowler_deny "$OPA_PROWLER_DENY" \
  --argjson opa_drift_critical_count "$OPA_DRIFT_CRITICAL_COUNT" \
  --argjson opa_prowler_critical_count "$OPA_PROWLER_CRITICAL_COUNT" \
  --argjson total_critical "$TOTAL_CRITICAL" \
  --arg remediation_failed "$REMEDIATION_FAILED" \
  --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
  '{
    opa_drift_block:$opa_drift_block,
    opa_drift_deny:$opa_drift_deny,
    opa_custodian_policies:$opa_custodian_policies,
    opa_prowler_block:$opa_prowler_block,
    opa_prowler_deny:$opa_prowler_deny,
    opa_drift_critical_count:$opa_drift_critical_count,
    opa_prowler_critical_count:$opa_prowler_critical_count,
    total_critical:$total_critical,
    remediation_failed:($remediation_failed == "true"),
    custodian_dry_run:($custodian_dry_run == "true")
  }')"

if [[ "$OPA_DRIFT_DENY" == "true" ]]; then
  sr_fail "OPA drift explicit deny" 1 '{}'
fi

if [[ "$OPA_PROWLER_DENY" == "true" ]]; then
  sr_fail "OPA prowler explicit deny" 1 '{}'
fi

if [[ "$TOTAL_CRITICAL" -gt 0 && "$REMEDIATION_FAILED" == "true" ]]; then
  sr_fail "CRITICAL findings unresolved after remediation — human escalation required" 1 "$(jq -cn \
    --argjson total_critical "$TOTAL_CRITICAL" \
    --arg remediation_failed "$REMEDIATION_FAILED" \
    '{total_critical:$total_critical, remediation_failed:($remediation_failed == "true")}')"
fi

if [[ "$TOTAL_CRITICAL" -gt 0 && "$CUSTODIAN_DRY_RUN" == "true" ]]; then
  sr_audit "WARN" "critical_findings_dry_run" "CRITICAL findings detected; custodian in dry-run — not blocking" "$(jq -cn \
    --argjson total_critical "$TOTAL_CRITICAL" \
    '{total_critical:$total_critical}')"
fi

sr_audit "INFO" "all_gates_passed" "all shift-right enforcement gates evaluated" "$(jq -cn \
  --arg opa_drift_block "$OPA_DRIFT_BLOCK" \
  --arg opa_prowler_block "$OPA_PROWLER_BLOCK" \
  --argjson total_critical "$TOTAL_CRITICAL" \
  --arg remediation_failed "$REMEDIATION_FAILED" \
  --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
  '{
    opa_drift_block:$opa_drift_block,
    opa_prowler_block:$opa_prowler_block,
    total_critical:$total_critical,
    remediation_failed:($remediation_failed == "true"),
    custodian_dry_run:($custodian_dry_run == "true")
  }')"
