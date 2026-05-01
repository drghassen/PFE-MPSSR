#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/shift_right_enforcement_audit.jsonl"
GATE_ENV_FILE="${OUTPUT_DIR}/gate.env"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/enforcement" "$AUDIT_FILE"

GATE_STATUS="INIT"
TOTAL_CRITICAL="${TOTAL_CRITICAL:-0}"
BLOCK_ACTIVE="${BLOCK_ACTIVE:-false}"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-true}"
CUSTODIAN_EXECUTED="${CUSTODIAN_EXECUTED:-false}"
RECONCILIATION_TICKET_CREATED="${RECONCILIATION_TICKET_CREATED:-false}"

write_gate_env_file() {
  {
    echo "GATE_STATUS=${GATE_STATUS}"
    echo "GATE_TOTAL_CRITICAL=${TOTAL_CRITICAL}"
    echo "GATE_BLOCK_ACTIVE=${BLOCK_ACTIVE}"
    echo "GATE_CUSTODIAN_DRY_RUN=${CUSTODIAN_DRY_RUN}"
    echo "GATE_CUSTODIAN_EXECUTED=${CUSTODIAN_EXECUTED}"
    echo "GATE_RECONCILIATION_TICKET_CREATED=${RECONCILIATION_TICKET_CREATED}"
  } > "$GATE_ENV_FILE"
}

trap write_gate_env_file EXIT
write_gate_env_file

# ── Artifact validation ────────────────────────────────────────────────────
# These .env files MUST exist before we can make any gate decision.
# If they are absent an upstream stage crashed silently — that is fail-open.
# We fail hard here rather than guess what upstream did.
CUSTODIAN_ENV_FILE="${OUTPUT_DIR}/custodian.env"
REMEDIATION_ENV_FILE="${OUTPUT_DIR}/remediation_verify.env"
RECONCILIATION_ENV_FILE="${OUTPUT_DIR}/reconciliation_ticket.env"

sr_require_file "$REMEDIATION_ENV_FILE" "remediation_verify.env (output of verify-remediation stage)"
sr_require_file "$RECONCILIATION_ENV_FILE" "reconciliation_ticket.env (output of reconciliation-ticket stage)"

# ── Safe key reader ────────────────────────────────────────────────────────
# Never source .env files from CI artifacts directly — that executes arbitrary
# shell code. Read each key explicitly with grep + cut instead.
_env_key() {
  local file="$1" key="$2" default="${3:-}"
  local val
  val="$(grep -m1 "^${key}=" "$file" 2>/dev/null | cut -d'=' -f2-)" || true
  printf '%s' "${val:-$default}"
}

# ── Read state from upstream artifacts ────────────────────────────────────
CUSTODIAN_EXECUTED="${CUSTODIAN_EXECUTED:-false}"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-true}"
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
      '{custodian_env_file:$custodian_env_file,custodian_executed:($custodian_executed=="true"),custodian_dry_run:($custodian_dry_run=="true")}')"
fi
REMEDIATION_FAILED="$( _env_key "$REMEDIATION_ENV_FILE" "REMEDIATION_FAILED"  "false")"
RECONCILIATION_TICKET_CREATED="$(_env_key "$RECONCILIATION_ENV_FILE" "RECONCILIATION_TICKET_CREATED" "false")"
RECONCILIATION_TICKET_REQUIRED="$(_env_key "$RECONCILIATION_ENV_FILE" "RECONCILIATION_TICKET_REQUIRED" "false")"

# ── OPA decision variables (passed via GitLab CI dotenv artifacts) ─────────
OPA_DRIFT_BLOCK="${OPA_DRIFT_BLOCK:-false}"
OPA_DRIFT_DENY="${OPA_DRIFT_DENY:-false}"
OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"
OPA_PROWLER_BLOCK="${OPA_PROWLER_BLOCK:-false}"
OPA_PROWLER_DENY="${OPA_PROWLER_DENY:-false}"
OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
SOFT_PASS_EXIT_CODE="${SOFT_PASS_EXIT_CODE:-2}"

if ! [[ "$SOFT_PASS_EXIT_CODE" =~ ^[0-9]+$ ]] || (( SOFT_PASS_EXIT_CODE < 0 || SOFT_PASS_EXIT_CODE > 255 )); then
  sr_fail "invalid SOFT_PASS_EXIT_CODE (expected integer 0..255)" 1 \
    "$(sr_build_details --arg soft_pass_exit_code "$SOFT_PASS_EXIT_CODE" '{soft_pass_exit_code:$soft_pass_exit_code}')"
fi

TOTAL_CRITICAL=$((OPA_DRIFT_CRITICAL_COUNT + OPA_PROWLER_CRITICAL_COUNT))

# BLOCK_ACTIVE=true  → OPA found issues that require a Custodian response.
# DENY is a separate, stronger signal: it means halt immediately, no remediation.
BLOCK_ACTIVE="false"
if [[ "$OPA_DRIFT_BLOCK" == "true" || "$OPA_PROWLER_BLOCK" == "true" ]]; then
  BLOCK_ACTIVE="true"
fi

sr_audit "INFO" "stage_start" "evaluating final shift-right enforcement gates" "$(sr_build_details \
  --arg opa_drift_block         "$OPA_DRIFT_BLOCK" \
  --arg opa_drift_deny          "$OPA_DRIFT_DENY" \
  --arg opa_prowler_block       "$OPA_PROWLER_BLOCK" \
  --arg opa_prowler_deny        "$OPA_PROWLER_DENY" \
  --argjson opa_drift_critical  "$OPA_DRIFT_CRITICAL_COUNT" \
  --argjson opa_prowler_critical "$OPA_PROWLER_CRITICAL_COUNT" \
  --argjson total_critical      "$TOTAL_CRITICAL" \
  --arg block_active            "$BLOCK_ACTIVE" \
  --arg custodian_executed      "$CUSTODIAN_EXECUTED" \
  --arg custodian_dry_run       "$CUSTODIAN_DRY_RUN" \
  --arg remediation_failed      "$REMEDIATION_FAILED" \
  --arg reconciliation_ticket_created "$RECONCILIATION_TICKET_CREATED" \
  --arg reconciliation_ticket_required "$RECONCILIATION_TICKET_REQUIRED" \
  '{
    opa_drift_block:          ($opa_drift_block    == "true"),
    opa_drift_deny:           ($opa_drift_deny     == "true"),
    opa_prowler_block:        ($opa_prowler_block  == "true"),
    opa_prowler_deny:         ($opa_prowler_deny   == "true"),
    opa_drift_critical:       $opa_drift_critical,
    opa_prowler_critical:     $opa_prowler_critical,
    total_critical:           $total_critical,
    block_active:             ($block_active        == "true"),
    custodian_executed:       ($custodian_executed  == "true"),
    custodian_dry_run:        ($custodian_dry_run   == "true"),
    remediation_failed:       ($remediation_failed  == "true"),
    reconciliation_ticket_created:  ($reconciliation_ticket_created == "true"),
    reconciliation_ticket_required: ($reconciliation_ticket_required == "true")
  }')"

# ══════════════════════════════════════════════════════════════════════════════
# HARD FAIL — exit 1
#
# These states are unacceptable regardless of dry-run mode.
# ══════════════════════════════════════════════════════════════════════════════

# An explicit OPA deny means a governance rule was broken. No remediation is
# attempted: the violation must be reviewed and resolved manually.
if [[ "$OPA_DRIFT_DENY" == "true" ]]; then
  sr_fail "OPA drift explicit deny — pipeline blocked; human review required" 1 \
    "$(sr_build_details --arg reason "OPA_DRIFT_DENY" '{reason:$reason}')"
fi

if [[ "$OPA_PROWLER_DENY" == "true" ]]; then
  sr_fail "OPA Prowler explicit deny — pipeline blocked; human review required" 1 \
    "$(sr_build_details --arg reason "OPA_PROWLER_DENY" '{reason:$reason}')"
fi

# Live remediation ran (not dry-run, Custodian actually executed) and the
# post-remediation verification says resources are still non-compliant.
# Passing green here would hide the fact that the environment is broken.
if [[ "$CUSTODIAN_DRY_RUN" == "false" \
   && "$CUSTODIAN_EXECUTED" == "true" \
   && "$REMEDIATION_FAILED" == "true" ]]; then
  sr_fail "Live Custodian remediation ran but verification failed — non-compliant resources remain" 1 \
    "$(sr_build_details \
      --argjson total_critical "$TOTAL_CRITICAL" \
      --arg custodian_dry_run  "$CUSTODIAN_DRY_RUN" \
      '{
        total_critical:     $total_critical,
        custodian_dry_run:  ($custodian_dry_run == "true"),
        remediation_failed: true
      }')"
fi

# Critical findings must produce an IaC reconciliation ticket.
if [[ "$TOTAL_CRITICAL" -gt 0 && "$RECONCILIATION_TICKET_CREATED" != "true" ]]; then
  sr_fail "critical findings detected but reconciliation ticket was not created" 1 \
    "$(sr_build_details \
      --argjson total_critical "$TOTAL_CRITICAL" \
      --arg ticket_created "$RECONCILIATION_TICKET_CREATED" \
      --arg ticket_required "$RECONCILIATION_TICKET_REQUIRED" \
      '{
        total_critical: $total_critical,
        reconciliation_ticket_created: ($ticket_created == "true"),
        reconciliation_ticket_required: ($ticket_required == "true")
      }')"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SOFT_PASS — GATE_STATUS=SOFT_PASS written to gate.env, then terminal exit code
# is controlled by SOFT_PASS_EXIT_CODE (default: 2 for strong CI signal).
#
# OPA has findings that need Custodian action, but Custodian is not yet acting
# (dry-run enabled, or no policy YAML found). The pipeline does NOT fail:
# blocking CI during the Custodian rollout phase would break all deployments.
# But the state is explicitly recorded so the operator cannot miss it.
# ══════════════════════════════════════════════════════════════════════════════
GATE_STATUS="PASS"

# Scenario A: OPA block is active and Custodian is in dry-run.
# Custodian reported what it would do but changed nothing.
if [[ "$BLOCK_ACTIVE" == "true" && "$CUSTODIAN_DRY_RUN" == "true" ]]; then
  GATE_STATUS="SOFT_PASS"
  sr_audit "WARN" "soft_pass_dry_run" \
    "OPA block active but Custodian is in dry-run — real remediation not performed" \
    "$(sr_build_details \
      --arg opa_drift_block    "$OPA_DRIFT_BLOCK" \
      --arg opa_prowler_block  "$OPA_PROWLER_BLOCK" \
      --argjson total_critical "$TOTAL_CRITICAL" \
      '{
        opa_drift_block:    ($opa_drift_block   == "true"),
        opa_prowler_block:  ($opa_prowler_block == "true"),
        total_critical:     $total_critical,
        action_required:    "set CUSTODIAN_DRY_RUN=false to enable live remediation"
      }')"
fi

# Scenario B: OPA block is active, dry-run is off, but Custodian did not execute.
# This usually means the policy YAML file is missing or the image is unavailable.
if [[ "$BLOCK_ACTIVE" == "true" \
   && "$CUSTODIAN_DRY_RUN" == "false" \
   && "$CUSTODIAN_EXECUTED" == "false" ]]; then
  GATE_STATUS="SOFT_PASS"
  sr_audit "WARN" "soft_pass_not_executed" \
    "OPA block active, dry-run disabled, but Custodian did not execute — check policy YAML files" \
    "$(sr_build_details \
      --arg opa_drift_block    "$OPA_DRIFT_BLOCK" \
      --arg opa_prowler_block  "$OPA_PROWLER_BLOCK" \
      --argjson total_critical "$TOTAL_CRITICAL" \
      '{
        opa_drift_block:    ($opa_drift_block   == "true"),
        opa_prowler_block:  ($opa_prowler_block == "true"),
        total_critical:     $total_critical,
        action_required:    "verify policy YAML files exist in CUSTODIAN_POLICIES_DIR"
      }')"
fi

# ── Write gate result artifact ─────────────────────────────────────────────
# This file is read by downstream stages (e.g. escalation logic).
write_gate_env_file

sr_audit "INFO" "stage_complete" "shift-right enforcement gate evaluation complete" "$(sr_build_details \
  --arg gate_status        "$GATE_STATUS" \
  --arg block_active       "$BLOCK_ACTIVE" \
  --argjson total_critical "$TOTAL_CRITICAL" \
  --arg custodian_dry_run  "$CUSTODIAN_DRY_RUN" \
  --arg custodian_executed "$CUSTODIAN_EXECUTED" \
  --arg reconciliation_ticket_created "$RECONCILIATION_TICKET_CREATED" \
  '{
    gate_status:        $gate_status,
    block_active:       ($block_active        == "true"),
    total_critical:     $total_critical,
    custodian_dry_run:  ($custodian_dry_run   == "true"),
    custodian_executed: ($custodian_executed  == "true"),
    reconciliation_ticket_created: ($reconciliation_ticket_created == "true")
  }')"

if [[ "$GATE_STATUS" == "SOFT_PASS" ]]; then
  sr_audit "ERROR" "soft_pass_terminal" "soft-pass terminal state reached; operator action required" "$(sr_build_details \
    --argjson total_critical "$TOTAL_CRITICAL" \
    --arg soft_pass_exit_code "$SOFT_PASS_EXIT_CODE" \
    --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
    --arg custodian_executed "$CUSTODIAN_EXECUTED" \
    '{
      total_critical: $total_critical,
      soft_pass_exit_code: ($soft_pass_exit_code | tonumber),
      custodian_dry_run: ($custodian_dry_run == "true"),
      custodian_executed: ($custodian_executed == "true"),
      action_required: "review critical findings and remediation path"
    }')"
  echo "SOFT_PASS: unresolved critical findings/remediation path. Exit code=${SOFT_PASS_EXIT_CODE}" >&2
  exit "$SOFT_PASS_EXIT_CODE"
fi

exit 0
