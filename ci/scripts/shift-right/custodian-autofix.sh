#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/custodian_audit.jsonl"
ENV_FILE="${OUTPUT_DIR}/custodian.env"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/custodian-autofix" "$AUDIT_FILE"

OPA_CUSTODIAN_POLICIES="${OPA_CUSTODIAN_POLICIES:-}"
OPA_DRIFT_MEDIUM_COUNT="${OPA_DRIFT_MEDIUM_COUNT:-0}"
OPA_DRIFT_LOW_COUNT="${OPA_DRIFT_LOW_COUNT:-0}"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-true}"
CUSTODIAN_POLICIES_DIR="${CUSTODIAN_POLICIES_DIR:-shift-right/custodian/policies}"

TOTAL_MEDIUM_LOW=$((OPA_DRIFT_MEDIUM_COUNT + OPA_DRIFT_LOW_COUNT))

if [[ -z "$OPA_CUSTODIAN_POLICIES" && "$TOTAL_MEDIUM_LOW" -eq 0 ]]; then
  {
    echo "CUSTODIAN_EXECUTED=false"
    echo "CUSTODIAN_POLICIES_TRIGGERED="
    echo "CUSTODIAN_DRY_RUN=${CUSTODIAN_DRY_RUN}"
  } > "$ENV_FILE"

  sr_audit "INFO" "skip" "no custodian policies and no medium/low findings" "$(sr_build_details \
    --arg policies "$OPA_CUSTODIAN_POLICIES" \
    --argjson drift_medium "$OPA_DRIFT_MEDIUM_COUNT" \
    --argjson drift_low "$OPA_DRIFT_LOW_COUNT" \
    '{
      policies: $policies,
      drift_medium: $drift_medium,
      drift_low: $drift_low
    }')"
  exit 0
fi

if [[ "$CUSTODIAN_DRY_RUN" == "true" ]]; then
  sr_audit "INFO" "dry_run_mode" "custodian dry-run mode enabled" "$(sr_build_details \
    --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
    --arg custodian_policies_dir "$CUSTODIAN_POLICIES_DIR" \
    '{
      custodian_dry_run: ($custodian_dry_run == "true"),
      custodian_policies_dir: $custodian_policies_dir
    }')"
fi

triggered_policies=()
if [[ -n "$OPA_CUSTODIAN_POLICIES" ]]; then
  IFS=',' read -r -a raw_policies <<< "$OPA_CUSTODIAN_POLICIES"
  for raw_policy in "${raw_policies[@]}"; do
    policy_name="${raw_policy//[[:space:]]/}"
    if [[ -z "$policy_name" ]]; then
      continue
    fi

    triggered_policies+=("$policy_name")

    sr_audit "INFO" "custodian_policy_triggered" "custodian policy routed by OPA" "$(sr_build_details \
      --arg policy_name "$policy_name" \
      --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
      --arg custodian_policies_dir "$CUSTODIAN_POLICIES_DIR" \
      '{
        policy_name: $policy_name,
        custodian_dry_run: ($custodian_dry_run == "true"),
        custodian_policies_dir: $custodian_policies_dir
      }')"

    # ── TODO Phase 2 — Cloud Custodian Integration ────────────────────────────
    # Prerequisites:
    #   1. Custodian image must be available in the pipeline (add to prowler-tools
    #      Dockerfile or create a dedicated custodian image)
    #   2. Policy YAML files must exist at ${CUSTODIAN_POLICIES_DIR}/{policy_name}.yml
    #      Policy names come from OPA drift custodian mapping (drift_custodian.rego):
    #        enforce-storage-tls
    #        deny-public-storage
    #        enforce-nsg-no-open-inbound
    #        enforce-keyvault-access-policy
    #        enforce-keyvault-network-acls
    #        enforce-vm-no-password-auth
    #        enforce-sql-password-rotation
    #        enforce-nsg-rule-deny-all
    #
    # Implementation per policy:
    #   custodian run \
    #     --output-dir .cloudsentinel/custodian-output \
    #     --cache-period 0 \
    #     "${CUSTODIAN_POLICIES_DIR}/${policy_name}.yml"
    #
    # Azure auth: Custodian uses the same ARM_* env vars as Terraform.
    # Dry run: use --dryrun flag when CUSTODIAN_DRY_RUN=true
    # ─────────────────────────────────────────────────────────────────────────
  done
fi

TRIGGERED_JOINED=""
if ((${#triggered_policies[@]} > 0)); then
  IFS=',' TRIGGERED_JOINED="${triggered_policies[*]}"
fi

{
  echo "CUSTODIAN_EXECUTED=true"
  echo "CUSTODIAN_POLICIES_TRIGGERED=${TRIGGERED_JOINED}"
  echo "CUSTODIAN_DRY_RUN=${CUSTODIAN_DRY_RUN}"
} > "$ENV_FILE"

sr_audit "INFO" "stage_complete" "custodian autofix placeholder completed" "$(sr_build_details \
  --arg policies "$OPA_CUSTODIAN_POLICIES" \
  --arg triggered "$TRIGGERED_JOINED" \
  --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
  '{
    policies_from_opa: $policies,
    policies_triggered: $triggered,
    custodian_dry_run: ($custodian_dry_run == "true")
  }')"

exit 0
