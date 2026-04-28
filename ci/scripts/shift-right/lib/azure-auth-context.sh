#!/usr/bin/env bash
# Sourced by shift-right scripts requiring Azure authentication.
# Requires: pipeline-guard.sh must be sourced before this file.
#
# Responsibilities:
#   - Normalize CI variable naming: ARM_* (Terraform/GitLab) → AZURE_* (Prowler)
#   - Validate credentials before any scanner invocation (fail-fast)
#   - Emit structured audit events (no secret values ever logged)
#   - Enforce sp-env as the only CI-grade auth mode
#
# Extension point for GitLab OIDC / Workload Identity Federation:
#   Add an `oidc` case in azure_auth_init that calls azure_auth_init_oidc.
#   Remove sp-env once OIDC is fully provisioned.

# ---------------------------------------------------------------------------
# _azure_auth_normalize_sp_env
# Bridges Terraform ARM_ naming to Prowler AZURE_ naming (internal).
# Priority: existing AZURE_* > ARM_* fallback.
# Prowler --sp-env-auth reads AZURE_CLIENT_ID / AZURE_TENANT_ID /
# AZURE_CLIENT_SECRET directly from the process environment.
# ---------------------------------------------------------------------------
_azure_auth_normalize_sp_env() {
  AZURE_CLIENT_ID="${AZURE_CLIENT_ID:-${ARM_CLIENT_ID:-}}"
  AZURE_TENANT_ID="${AZURE_TENANT_ID:-${ARM_TENANT_ID:-}}"
  AZURE_CLIENT_SECRET="${AZURE_CLIENT_SECRET:-${ARM_CLIENT_SECRET:-}}"
  export AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_CLIENT_SECRET
}

# ---------------------------------------------------------------------------
# _azure_auth_audit_sp_env <subscription_ids>
# Emits a structured auth-context audit event.
# Secret values are NEVER included — only IDs and presence flag.
# ---------------------------------------------------------------------------
_azure_auth_audit_sp_env() {
  local subscription_ids="${1:-}"
  sr_audit "INFO" "auth_context_resolved" \
    "azure sp-env credentials resolved and validated" \
    "$(sr_build_details \
      --arg auth_mode    "sp-env" \
      --arg tenant_id    "${AZURE_TENANT_ID}" \
      --arg client_id    "${AZURE_CLIENT_ID}" \
      --arg subscriptions "$subscription_ids" \
      '{
        auth_mode:       $auth_mode,
        tenant_id:       $tenant_id,
        client_id:       $client_id,
        subscriptions:   $subscriptions,
        secret_present:  (env.AZURE_CLIENT_SECRET != ""),
        az_login_used:   false
      }')"
}

# ---------------------------------------------------------------------------
# azure_auth_init <auth_mode> <subscription_ids>
# Public entry point. Call this before any Azure/Prowler invocation.
#
# sp-env   → normalize ARM_*→AZURE_*, validate, audit  [CI-grade, stateless]
# az-cli   → rejected in CI; fails with actionable error
# others   → blocked; audit WARN + hard fail
#
# OIDC extension point: add `oidc` case below calling azure_auth_init_oidc.
# ---------------------------------------------------------------------------
azure_auth_init() {
  local auth_mode="${1:?azure_auth_init: auth_mode is required}"
  local subscription_ids="${2:-}"

  case "$auth_mode" in
    sp-env)
      _azure_auth_normalize_sp_env
      sr_require_env AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_CLIENT_SECRET
      _azure_auth_audit_sp_env "$subscription_ids"
      ;;

    # ── OIDC extension point ────────────────────────────────────────────────
    # oidc)
    #   azure_auth_init_oidc "$subscription_ids"
    #   ;;

    az-cli | managed-identity | browser)
      # These modes depend on ambient state (~/.azure cache, instance metadata,
      # browser session). They are non-reproducible and unsafe in headless CI.
      sr_fail \
        "auth mode '${auth_mode}' is not allowed in CI pipelines (stateful/ambient)" 1 \
        "$(sr_build_details --arg auth_mode "$auth_mode" \
          '{
            auth_mode:      $auth_mode,
            reason:         "stateful or ambient credentials break reproducibility",
            required_mode:  "sp-env",
            migration_path: "set PROWLER_AZURE_AUTH_MODE=sp-env and define ARM_CLIENT_ID/ARM_TENANT_ID/ARM_CLIENT_SECRET in GitLab CI/CD variables"
          }')"
      ;;

    *)
      sr_fail "unsupported azure auth mode: ${auth_mode}" 1 \
        "$(sr_build_details --arg auth_mode "$auth_mode" \
          '{
            auth_mode: $auth_mode,
            allowed:   ["sp-env"]
          }')"
      ;;
  esac
}
