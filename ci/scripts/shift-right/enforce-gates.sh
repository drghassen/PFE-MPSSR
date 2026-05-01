#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/shift_right_enforcement_audit.jsonl"
GATE_ENV_FILE="${OUTPUT_DIR}/gate.env"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/enforcement" "$AUDIT_FILE"

GATE_STATUS="INIT"
GATE_REASON="init"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-true}"
CUSTODIAN_EXECUTED="${CUSTODIAN_EXECUTED:-false}"
RECONCILIATION_TICKET_CREATED="${RECONCILIATION_TICKET_CREATED:-false}"
TOTAL_L0=0
TOTAL_L1=0
TOTAL_L2=0
TOTAL_L3=0

write_gate_env_file() {
  {
    echo "GATE_STATUS=${GATE_STATUS}"
    echo "GATE_REASON=${GATE_REASON}"
    echo "GATE_TOTAL_L0=${TOTAL_L0}"
    echo "GATE_TOTAL_L1=${TOTAL_L1}"
    echo "GATE_TOTAL_L2=${TOTAL_L2}"
    echo "GATE_TOTAL_L3=${TOTAL_L3}"
    echo "GATE_CUSTODIAN_DRY_RUN=${CUSTODIAN_DRY_RUN}"
    echo "GATE_CUSTODIAN_EXECUTED=${CUSTODIAN_EXECUTED}"
    echo "GATE_RECONCILIATION_TICKET_CREATED=${RECONCILIATION_TICKET_CREATED}"
  } > "$GATE_ENV_FILE"
}

trap write_gate_env_file EXIT
write_gate_env_file

CUSTODIAN_ENV_FILE="${OUTPUT_DIR}/custodian.env"
REMEDIATION_ENV_FILE="${OUTPUT_DIR}/remediation_verify.env"
RECONCILIATION_ENV_FILE="${OUTPUT_DIR}/reconciliation_ticket.env"

sr_require_file "$REMEDIATION_ENV_FILE" "remediation_verify.env (output of verify-remediation stage)"
sr_require_file "$RECONCILIATION_ENV_FILE" "reconciliation_ticket.env (output of reconciliation-ticket stage)"

_env_key() {
  local file="$1" key="$2" default="${3:-}"
  local val
  val="$(grep -m1 "^${key}=" "$file" 2>/dev/null | cut -d'=' -f2-)" || true
  printf '%s' "${val:-$default}"
}

if [[ -f "$CUSTODIAN_ENV_FILE" ]]; then
  CUSTODIAN_EXECUTED="$(_env_key "$CUSTODIAN_ENV_FILE" "CUSTODIAN_EXECUTED" "$CUSTODIAN_EXECUTED")"
  CUSTODIAN_DRY_RUN="$(_env_key "$CUSTODIAN_ENV_FILE" "CUSTODIAN_DRY_RUN" "$CUSTODIAN_DRY_RUN")"
else
  sr_audit "WARN" "custodian_env_missing" \
    "custodian.env artifact missing; using dotenv/runtime env fallback values" \
    "$(sr_build_details \
      --arg custodian_env_file "$CUSTODIAN_ENV_FILE" \
      --arg custodian_executed "$CUSTODIAN_EXECUTED" \
      --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
      '{custodian_env_file:$custodian_env_file,custodian_executed:($custodian_executed=="true"),custodian_dry_run:($custodian_dry_run=="true")}' )"
fi

REMEDIATION_FAILED="$(_env_key "$REMEDIATION_ENV_FILE" "REMEDIATION_FAILED" "false")"
RECONCILIATION_TICKET_CREATED="$(_env_key "$RECONCILIATION_ENV_FILE" "RECONCILIATION_TICKET_CREATED" "false")"
RECONCILIATION_TICKET_REQUIRED="$(_env_key "$RECONCILIATION_ENV_FILE" "RECONCILIATION_TICKET_REQUIRED" "false")"

OPA_DRIFT_DENY="${OPA_DRIFT_DENY:-false}"
OPA_PROWLER_DENY="${OPA_PROWLER_DENY:-false}"
OPA_DRIFT_L0_COUNT="${OPA_DRIFT_L0_COUNT:-0}"
OPA_DRIFT_L1_COUNT="${OPA_DRIFT_L1_COUNT:-0}"
OPA_DRIFT_L2_COUNT="${OPA_DRIFT_L2_COUNT:-0}"
OPA_DRIFT_L3_COUNT="${OPA_DRIFT_L3_COUNT:-0}"
OPA_PROWLER_L0_COUNT="${OPA_PROWLER_L0_COUNT:-0}"
OPA_PROWLER_L1_COUNT="${OPA_PROWLER_L1_COUNT:-0}"
OPA_PROWLER_L2_COUNT="${OPA_PROWLER_L2_COUNT:-0}"
OPA_PROWLER_L3_COUNT="${OPA_PROWLER_L3_COUNT:-0}"
SOFT_PASS_EXIT_CODE="${SOFT_PASS_EXIT_CODE:-2}"

if ! [[ "$SOFT_PASS_EXIT_CODE" =~ ^[0-9]+$ ]] || (( SOFT_PASS_EXIT_CODE < 0 || SOFT_PASS_EXIT_CODE > 255 )); then
  sr_fail "invalid SOFT_PASS_EXIT_CODE (expected integer 0..255)" 1 \
    "$(sr_build_details --arg soft_pass_exit_code "$SOFT_PASS_EXIT_CODE" '{soft_pass_exit_code:$soft_pass_exit_code}')"
fi

TOTAL_L3=$((OPA_DRIFT_L3_COUNT + OPA_PROWLER_L3_COUNT))
TOTAL_L2=$((OPA_DRIFT_L2_COUNT + OPA_PROWLER_L2_COUNT))
TOTAL_L1=$((OPA_DRIFT_L1_COUNT + OPA_PROWLER_L1_COUNT))
TOTAL_L0=$((OPA_DRIFT_L0_COUNT + OPA_PROWLER_L0_COUNT))

sr_audit "INFO" "stage_start" "evaluating final shift-right enforcement gates" "$(sr_build_details \
  --arg opa_drift_deny "$OPA_DRIFT_DENY" \
  --arg opa_prowler_deny "$OPA_PROWLER_DENY" \
  --argjson total_l0 "$TOTAL_L0" \
  --argjson total_l1 "$TOTAL_L1" \
  --argjson total_l2 "$TOTAL_L2" \
  --argjson total_l3 "$TOTAL_L3" \
  --arg custodian_executed "$CUSTODIAN_EXECUTED" \
  --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
  --arg remediation_failed "$REMEDIATION_FAILED" \
  --arg reconciliation_ticket_created "$RECONCILIATION_TICKET_CREATED" \
  --arg reconciliation_ticket_required "$RECONCILIATION_TICKET_REQUIRED" \
  '{opa_drift_deny:($opa_drift_deny=="true"), opa_prowler_deny:($opa_prowler_deny=="true"), total_l0:$total_l0, total_l1:$total_l1, total_l2:$total_l2, total_l3:$total_l3, custodian_executed:($custodian_executed=="true"), custodian_dry_run:($custodian_dry_run=="true"), remediation_failed:($remediation_failed=="true"), reconciliation_ticket_created:($reconciliation_ticket_created=="true"), reconciliation_ticket_required:($reconciliation_ticket_required=="true")}')"

if [[ "$OPA_DRIFT_DENY" == "true" ]]; then
  GATE_STATUS="HARD_FAIL"
  GATE_REASON="opa_drift_deny"
  sr_fail "OPA drift explicit deny" 1 "$(sr_build_details --arg reason "$GATE_REASON" '{reason:$reason}')"
fi

if [[ "$OPA_PROWLER_DENY" == "true" ]]; then
  GATE_STATUS="HARD_FAIL"
  GATE_REASON="opa_prowler_deny"
  sr_fail "OPA prowler explicit deny" 1 "$(sr_build_details --arg reason "$GATE_REASON" '{reason:$reason}')"
fi

if [[ "$CUSTODIAN_DRY_RUN" == "false" \
   && "$CUSTODIAN_EXECUTED" == "true" \
   && "$REMEDIATION_FAILED" == "true" ]]; then
  GATE_STATUS="HARD_FAIL"
  GATE_REASON="l3_verification_failed"
  sr_fail "L3 auto-remediation executed but verification failed" 1 \
    "$(sr_build_details --argjson total_l3 "$TOTAL_L3" '{total_l3:$total_l3, remediation_failed:true}')"
fi

if [[ "$TOTAL_L3" -gt 0 && "$RECONCILIATION_TICKET_CREATED" != "true" ]]; then
  GATE_STATUS="HARD_FAIL"
  GATE_REASON="l3_ticket_missing"
  sr_fail "L3 findings require reconciliation ticket - not created" 1 \
    "$(sr_build_details --argjson total_l3 "$TOTAL_L3" --arg ticket_created "$RECONCILIATION_TICKET_CREATED" '{total_l3:$total_l3, reconciliation_ticket_created:($ticket_created=="true")}')"
fi

GATE_STATUS="SOFT_PASS"
GATE_REASON="terminal_state_unresolved"

if [[ "$TOTAL_L3" -gt 0 && "$CUSTODIAN_DRY_RUN" == "true" ]]; then
  GATE_STATUS="SOFT_PASS"
  GATE_REASON="l3_custodian_dry_run"
fi

if [[ "$TOTAL_L3" -gt 0 \
   && "$CUSTODIAN_DRY_RUN" == "false" \
   && "$CUSTODIAN_EXECUTED" == "false" ]]; then
  GATE_STATUS="SOFT_PASS"
  GATE_REASON="l3_custodian_not_executed"
fi

if [[ "$TOTAL_L3" -eq 0 \
   && "$TOTAL_L2" -gt 0 \
   && "$RECONCILIATION_TICKET_CREATED" != "true" ]]; then
  GATE_STATUS="SOFT_PASS"
  GATE_REASON="l2_ticket_not_created"
fi

if [[ "$TOTAL_L3" -eq 0 \
   && "$TOTAL_L2" -gt 0 \
   && "$RECONCILIATION_TICKET_CREATED" == "true" ]]; then
  GATE_STATUS="PASS"
  GATE_REASON="l2_workflow_complete"
fi

if [[ "$TOTAL_L3" -eq 0 && "$TOTAL_L2" -eq 0 ]]; then
  GATE_STATUS="PASS"
  GATE_REASON="no_actionable_findings"
fi

if [[ "$TOTAL_L3" -gt 0 \
   && "$CUSTODIAN_DRY_RUN" == "false" \
   && "$CUSTODIAN_EXECUTED" == "true" \
   && "$REMEDIATION_FAILED" != "true" \
   && "$RECONCILIATION_TICKET_CREATED" == "true" ]]; then
  GATE_STATUS="PASS"
  GATE_REASON="l3_verified_workflow_complete"
fi

write_gate_env_file

sr_audit "INFO" "stage_complete" "shift-right enforcement gate evaluation complete" "$(sr_build_details \
  --arg gate_status "$GATE_STATUS" \
  --arg gate_reason "$GATE_REASON" \
  --argjson total_l0 "$TOTAL_L0" \
  --argjson total_l1 "$TOTAL_L1" \
  --argjson total_l2 "$TOTAL_L2" \
  --argjson total_l3 "$TOTAL_L3" \
  --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
  --arg custodian_executed "$CUSTODIAN_EXECUTED" \
  --arg reconciliation_ticket_created "$RECONCILIATION_TICKET_CREATED" \
  '{gate_status:$gate_status, gate_reason:$gate_reason, total_l0:$total_l0, total_l1:$total_l1, total_l2:$total_l2, total_l3:$total_l3, custodian_dry_run:($custodian_dry_run=="true"), custodian_executed:($custodian_executed=="true"), reconciliation_ticket_created:($reconciliation_ticket_created=="true")}')"

if [[ "$GATE_STATUS" == "SOFT_PASS" ]]; then
  sr_audit "ERROR" "soft_pass_terminal" "soft-pass terminal state reached; operator action required" "$(sr_build_details \
    --arg gate_reason "$GATE_REASON" \
    --argjson total_l2 "$TOTAL_L2" \
    --argjson total_l3 "$TOTAL_L3" \
    --arg soft_pass_exit_code "$SOFT_PASS_EXIT_CODE" \
    '{gate_reason:$gate_reason, total_l2:$total_l2, total_l3:$total_l3, soft_pass_exit_code:($soft_pass_exit_code|tonumber)}')"
  echo "SOFT_PASS: ${GATE_REASON}. Exit code=${SOFT_PASS_EXIT_CODE}" >&2
  exit "$SOFT_PASS_EXIT_CODE"
fi

exit 0
