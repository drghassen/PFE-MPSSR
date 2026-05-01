#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/custodian_audit.jsonl"
ENV_FILE="${OUTPUT_DIR}/custodian.env"
CUSTODIAN_OUTPUT_DIR="${OUTPUT_DIR}/custodian-output"
mkdir -p "$OUTPUT_DIR" "$CUSTODIAN_OUTPUT_DIR"

sr_init_guard "shift-right/custodian-autofix" "$AUDIT_FILE"

# ── Input variables ────────────────────────────────────────────────────────
# OPA_CUSTODIAN_POLICIES: comma-separated list of policy names to run,
#   produced by the OPA drift decision stage.
# CUSTODIAN_DRY_RUN: when "true", passes --dryrun to Custodian — actions are
#   evaluated and logged but no Azure resource is modified.
# CUSTODIAN_POLICIES_DIR: directory containing policy YAML files.
OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"
OPA_PROWLER_CUSTODIAN_POLICIES="${OPA_PROWLER_CUSTODIAN_POLICIES:-}"
OPA_CORRELATION_ID="${OPA_CORRELATION_ID:-unknown}"
REMEDIATION_MODE="${REMEDIATION_MODE:-enforced}"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-}"
CUSTODIAN_POLICIES_DIR="${CUSTODIAN_POLICIES_DIR:-shift-right/custodian/policies}"
ACTUALLY_EXECUTED="false"
TRIGGERED_JOINED=""
EXECUTED_JOINED=""
FAILED_JOINED=""
CUSTODIAN_DRY_RUN_EFFECTIVE="${CUSTODIAN_DRY_RUN:-true}"

write_env_file() {
  {
    echo "CUSTODIAN_EXECUTED=${ACTUALLY_EXECUTED}"
    echo "CUSTODIAN_POLICIES_TRIGGERED=${TRIGGERED_JOINED}"
    echo "CUSTODIAN_POLICIES_EXECUTED=${EXECUTED_JOINED}"
    echo "CUSTODIAN_DRY_RUN=${CUSTODIAN_DRY_RUN_EFFECTIVE}"
    echo "CUSTODIAN_POLICIES_FAILED=${FAILED_JOINED}"
    echo "CUSTODIAN_CORRELATION_ID=${OPA_CORRELATION_ID}"
  } > "$ENV_FILE"
}

trap write_env_file EXIT
write_env_file

if [[ -z "$CUSTODIAN_DRY_RUN" ]]; then
  case "$REMEDIATION_MODE" in
    advisory) CUSTODIAN_DRY_RUN="true" ;;
    enforced) CUSTODIAN_DRY_RUN="false" ;;
    *)
      sr_fail "invalid REMEDIATION_MODE (expected advisory|enforced)" 1 \
        "$(jq -cn --arg remediation_mode "$REMEDIATION_MODE" '{remediation_mode:$remediation_mode}')"
      ;;
  esac
fi
CUSTODIAN_DRY_RUN_EFFECTIVE="$CUSTODIAN_DRY_RUN"

ALL_CUSTODIAN_POLICIES="$(jq -nr \
  --arg drift "$OPA_CUSTODIAN_POLICIES" \
  --arg prowler "$OPA_PROWLER_CUSTODIAN_POLICIES" \
  '[($drift|split(",")[]?), ($prowler|split(",")[]?)]
   | map(gsub("^\\s+|\\s+$";""))
   | map(select(length > 0))
   | unique
   | join(",")')"

# ── Early exit: nothing to do ──────────────────────────────────────────────
# If OPA produced no CRITICAL policy names, Custodian has no work to do.
if [[ -z "$ALL_CUSTODIAN_POLICIES" ]]; then
  sr_audit "INFO" "skip" "no CRITICAL custodian policies triggered" \
    "$(sr_build_details \
      --arg  policies      "$OPA_CUSTODIAN_POLICIES" \
      --arg  prowler_policies "$OPA_PROWLER_CUSTODIAN_POLICIES" \
      --arg  correlation_id "$OPA_CORRELATION_ID" \
      '{policies:$policies, prowler_policies:$prowler_policies, remediation_scope:"CRITICAL_ONLY", correlation_id:$correlation_id}')"
  exit 0
fi

# ── Azure credential mapping ───────────────────────────────────────────────
# Cloud Custodian uses AZURE_* env vars.
# Terraform uses ARM_* env vars. Both sets of credentials are the same service
# principal. We map ARM_* → AZURE_* so one CI secret set covers both tools.
# Only override AZURE_* if they are not already set.
: "${AZURE_TENANT_ID:=${ARM_TENANT_ID:-}}"
: "${AZURE_CLIENT_ID:=${ARM_CLIENT_ID:-}}"
: "${AZURE_CLIENT_SECRET:=${ARM_CLIENT_SECRET:-}}"
: "${AZURE_SUBSCRIPTION_ID:=${ARM_SUBSCRIPTION_ID:-}}"

export AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_SUBSCRIPTION_ID

# Only require credentials when we are actually going to execute Custodian.
# In a pure "no-op skip" branch above we already exited, so reaching here
# means at least one policy will be attempted.
sr_require_env AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_SUBSCRIPTION_ID

sr_require_command custodian jq

sr_audit "INFO" "execution_start" "custodian autofix starting" \
  "$(sr_build_details \
    --arg  custodian_dry_run      "$CUSTODIAN_DRY_RUN" \
    --arg  remediation_mode       "$REMEDIATION_MODE" \
    --arg  custodian_policies_dir "$CUSTODIAN_POLICIES_DIR" \
    --arg  opa_policies           "$ALL_CUSTODIAN_POLICIES" \
    --arg  correlation_id         "$OPA_CORRELATION_ID" \
    '{
      custodian_dry_run:       ($custodian_dry_run == "true"),
      remediation_mode:        $remediation_mode,
      custodian_policies_dir:  $custodian_policies_dir,
      opa_policies:            $opa_policies,
      remediation_scope:       "CRITICAL_ONLY",
      correlation_id:          $correlation_id
    }')"

# ── Parse triggered policies ───────────────────────────────────────────────
triggered_policies=()
if [[ -n "$ALL_CUSTODIAN_POLICIES" ]]; then
  IFS=',' read -r -a raw_policies <<< "$ALL_CUSTODIAN_POLICIES"
  for raw in "${raw_policies[@]}"; do
    name="${raw//[[:space:]]/}"
    [[ -n "$name" ]] && triggered_policies+=("$name")
  done
fi

# ── Execute each triggered policy ─────────────────────────────────────────
actually_executed_policies=()
failed_policies=()

for policy_name in "${triggered_policies[@]}"; do
  policy_file="${CUSTODIAN_POLICIES_DIR}/${policy_name}.yml"

  if [[ ! -f "$policy_file" ]]; then
    sr_audit "WARN" "policy_file_missing" \
      "policy YAML not found for '${policy_name}' — skipping" \
      "$(sr_build_details \
        --arg policy "$policy_name" \
        --arg file   "$policy_file" \
        '{policy:$policy, file:$file}')"
    continue
  fi

  policy_out="${CUSTODIAN_OUTPUT_DIR}/${policy_name}"
  mkdir -p "$policy_out"

  # Build the custodian command.
  # --cache-period 0: disable the Azure metadata cache to ensure we always
  #   query live resource state, not stale data from a previous run.
  # --dryrun: when CUSTODIAN_DRY_RUN=true, Custodian evaluates filters and
  #   reports matches but executes no actions. No Azure resource is modified.
  custodian_cmd=(
    custodian run
    --output-dir "$policy_out"
    --cache-period 0
  )
  [[ "$CUSTODIAN_DRY_RUN" == "true" ]] && custodian_cmd+=(--dryrun)
  custodian_cmd+=("$policy_file")

  sr_audit "INFO" "custodian_policy_start" "running policy '${policy_name}'" \
    "$(sr_build_details \
      --arg policy     "$policy_name" \
      --arg file       "$policy_file" \
      --arg output_dir "$policy_out" \
      --arg dry_run    "$CUSTODIAN_DRY_RUN" \
      --arg correlation_id "$OPA_CORRELATION_ID" \
      '{
        policy:     $policy,
        file:       $file,
        output_dir: $output_dir,
        dry_run:    ($dry_run == "true"),
        correlation_id: $correlation_id
      }')"

  custodian_exit=0
  if "${custodian_cmd[@]}" 2>&1 | tee "${policy_out}/run.log"; then
    actually_executed_policies+=("$policy_name")
    sr_audit "INFO" "custodian_policy_ok" "policy '${policy_name}' completed" \
      "$(sr_build_details \
        --arg policy  "$policy_name" \
        --arg log     "${policy_out}/run.log" \
        '{policy:$policy, log:$log}')"
  else
    custodian_exit=$?
    failed_policies+=("$policy_name")
    sr_audit "ERROR" "custodian_policy_failed" \
      "policy '${policy_name}' exited with code ${custodian_exit}" \
      "$(sr_build_details \
        --arg  policy "$policy_name" \
        --argjson rc  "$custodian_exit" \
        --arg  log    "${policy_out}/run.log" \
        '{policy:$policy, exit_code:$rc, log:$log}')"
  fi
done

# ── Fail if any policy run failed ─────────────────────────────────────────
# We fail after all policies have been attempted (not on first failure) so
# that audit logs are complete for every policy that was triggered.
IFS=',' TRIGGERED_JOINED="${triggered_policies[*]:-}"
IFS=',' EXECUTED_JOINED="${actually_executed_policies[*]:-}"
IFS=',' FAILED_JOINED="${failed_policies[*]:-}"

if ((${#failed_policies[@]} > 0)); then
  sr_fail "Custodian policy execution failed for: ${FAILED_JOINED}" 1 \
    "$(sr_build_details \
      --arg failed "$FAILED_JOINED" \
      '{failed_policies:($failed | split(","))}')"
fi

# ── Write output artifact ──────────────────────────────────────────────────
# CUSTODIAN_EXECUTED=true only when at least one policy actually ran.
# This is the value that enforce-gates.sh reads to distinguish "ran + result"
# from "triggered but skipped due to missing YAML".
((${#actually_executed_policies[@]} > 0)) && ACTUALLY_EXECUTED="true"
write_env_file

sr_audit "INFO" "stage_complete" "custodian autofix complete" \
  "$(sr_build_details \
    --arg  executed        "$ACTUALLY_EXECUTED" \
    --arg  triggered       "$TRIGGERED_JOINED" \
    --arg  executed_list   "$EXECUTED_JOINED" \
    --arg  custodian_dry_run "$CUSTODIAN_DRY_RUN" \
    '{
      custodian_executed:        ($executed     == "true"),
      policies_triggered:        $triggered,
      policies_executed:         $executed_list,
      custodian_dry_run:         ($custodian_dry_run == "true")
    }')"

exit 0
