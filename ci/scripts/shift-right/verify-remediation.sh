#!/usr/bin/env bash
set -euo pipefail

source ci/scripts/shift-right/lib/pipeline-guard.sh

OUTPUT_DIR=".cloudsentinel"
AUDIT_FILE="${OUTPUT_DIR}/remediation_verify.jsonl"
ENV_FILE="${OUTPUT_DIR}/remediation_verify.env"
mkdir -p "$OUTPUT_DIR"

sr_init_guard "shift-right/verify-remediation" "$AUDIT_FILE"

OPA_DRIFT_CRITICAL_COUNT="${OPA_DRIFT_CRITICAL_COUNT:-0}"
OPA_PROWLER_CRITICAL_COUNT="${OPA_PROWLER_CRITICAL_COUNT:-0}"
OPA_REQUIRES_AUTO_REMEDIATION="${OPA_REQUIRES_AUTO_REMEDIATION:-false}"
OPA_REMEDIATION_SCOPE="${OPA_REMEDIATION_SCOPE:-CRITICAL_ONLY}"
CUSTODIAN_DRY_RUN="${CUSTODIAN_DRY_RUN:-true}"

if [[ "$OPA_REQUIRES_AUTO_REMEDIATION" != "true" ]]; then
  {
    echo "REMEDIATION_FAILED=false"
    echo "REMEDIATION_SKIP_REASON=no_auto_remediation_required"
  } > "$ENV_FILE"

  sr_audit "INFO" "skip" "auto-remediation not required; verification skipped" "$(sr_build_details \
    --arg requires_auto_remediation "$OPA_REQUIRES_AUTO_REMEDIATION" \
    --arg remediation_scope "$OPA_REMEDIATION_SCOPE" \
    '{
      requires_auto_remediation: ($requires_auto_remediation == "true"),
      remediation_scope: $remediation_scope
    }')"
  exit 0
fi

if [[ "$CUSTODIAN_DRY_RUN" == "true" ]]; then
  {
    echo "REMEDIATION_FAILED=false"
    echo "REMEDIATION_SKIP_REASON=custodian_dry_run"
  } > "$ENV_FILE"

  sr_audit "WARN" "dry_run_skip" "custodian ran in dry-run mode, skipping verify" "$(sr_build_details \
    --arg custodian_dry_run "$CUSTODIAN_DRY_RUN" \
    '{custodian_dry_run: ($custodian_dry_run == "true")}')"
  exit 0
fi

sr_audit "INFO" "verify_start" "starting post-remediation verification" "$(sr_build_details \
  --argjson drift_critical "$OPA_DRIFT_CRITICAL_COUNT" \
  --argjson prowler_critical "$OPA_PROWLER_CRITICAL_COUNT" \
  '{
    drift_critical: $drift_critical,
    prowler_critical: $prowler_critical
  }')"

# ── TODO Phase 2 — Re-scan Verification ──────────────────────────────────
# After Custodian runs, verify the targeted resources are now compliant.
# Strategy options:
#
# Option A — Targeted Terraform re-plan (precise, slow):
#   Run terraform plan -refresh-only -target=<drifted_address> for each
#   remediated resource. If exit code is 0, resource is clean.
#
# Option B — Prowler targeted check re-run (for posture findings):
#   prowler azure --checks <check_id> --subscription-ids <id>
#   If finding is now PASS, remediation succeeded.
#
# Option C — Azure CLI direct verification (fast, simple):
#   Query the specific resource attribute that was remediated.
#   Compare against expected value from Terraform state.
#
# On verification failure: set REMEDIATION_FAILED=true
# This variable is read by the escalate stage rule in the pipeline.
# ─────────────────────────────────────────────────────────────────────────

{
  echo "REMEDIATION_FAILED=false"
  echo "REMEDIATION_SKIP_REASON=phase2_verification_placeholder"
} > "$ENV_FILE"

sr_audit "INFO" "stage_complete" "verification placeholder completed" "$(sr_build_details \
  '{
    remediation_failed: false,
    placeholder: true
  }')"

exit 0
