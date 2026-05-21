#!/usr/bin/env bash
# Post-remediation verification dispatcher.
# Dispatches by --policy name; performs inline Azure CLI re-checks.
# Unknown policies exit 0 (VERIFY_SKIP) — we never block what we cannot verify.
set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-.cloudsentinel}"
STATE_DIR="${OUTPUT_DIR}/runtime-state"
STATE_FILE="${RUNTIME_STATE_FILE:-${STATE_DIR}/runtime-state.jsonl}"

mkdir -p "$STATE_DIR"

RESOURCE_ID=""
FINDING_ID=""
POLICY=""
SEVERITY="LOW"
CORRELATION_ID="unknown"
MAX_RETRIES="${VERIFICATION_MAX_RETRIES:-3}"
TIMEOUT_SECONDS="${VERIFICATION_TIMEOUT_SECONDS:-30}"
ATTEMPTED="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resource-id)     RESOURCE_ID="${2:-}";          shift 2 ;;
    --finding-id)      FINDING_ID="${2:-}";           shift 2 ;;
    --policy)          POLICY="${2:-}";               shift 2 ;;
    --severity)        SEVERITY="${2:-LOW}";          shift 2 ;;
    --correlation-id)  CORRELATION_ID="${2:-unknown}"; shift 2 ;;
    --max-retries)     MAX_RETRIES="${2:-3}";         shift 2 ;;
    --timeout-seconds) TIMEOUT_SECONDS="${2:-30}";   shift 2 ;;
    --script)          shift 2 ;;  # accepted for backward compat; policy dispatcher is used instead
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$RESOURCE_ID" || -z "$FINDING_ID" || -z "$POLICY" ]]; then
  echo "required args: --resource-id --finding-id --policy" >&2
  exit 2
fi

# ── State emitter ─────────────────────────────────────────────────────────────

_emit_state() {
  local status="$1" passed="$2" attempt="$3" reason="${4:-}"
  jq -cn \
    --arg  finding_id          "$FINDING_ID" \
    --arg  policy              "$POLICY" \
    --arg  severity            "$SEVERITY" \
    --arg  status              "$status" \
    --argjson remediation_attempted "$ATTEMPTED" \
    --argjson verification_passed   "$passed" \
    --arg  timestamp           "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg  resource_id         "$RESOURCE_ID" \
    --arg  correlation_id      "$CORRELATION_ID" \
    --argjson attempt          "$attempt" \
    --arg  reason              "$reason" \
    '{
      finding_id:           $finding_id,
      policy:               $policy,
      severity:             $severity,
      status:               $status,
      remediation_attempted: $remediation_attempted,
      verification_passed:  $verification_passed,
      timestamp:            $timestamp,
      resource_id:          $resource_id,
      correlation_id:       $correlation_id,
      attempt:              $attempt,
      reason:               $reason
    }' >> "$STATE_FILE"
}

# ── Per-policy inline verifiers ───────────────────────────────────────────────
# Each function uses $RESOURCE_ID from the outer scope.
# Exit 0 = remediated; 1 = still drifted; 2 = az CLI error (treated as failure).

_require_az() {
  if ! command -v az >/dev/null 2>&1; then
    echo "az CLI not found" >&2; return 2
  fi
}

# enforce-nsg-no-open-inbound
# Passes when no inbound Allow rule with wildcard source remains on the NSG.
_verify_nsg_no_open_inbound() {
  _require_az || return 2
  local open_count
  open_count="$(az network nsg show --ids "$RESOURCE_ID" \
    --query "securityRules[?direction=='Inbound' && access=='Allow' \
      && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' \
       || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='Any')] \
      | length(@)" \
    -o tsv 2>/dev/null)" || { echo "az nsg query failed for $RESOURCE_ID" >&2; return 2; }
  if [[ -z "$open_count" ]]; then
    echo "az nsg query returned empty result for $RESOURCE_ID" >&2; return 2
  fi
  if [[ "$open_count" == "0" ]]; then return 0; fi
  echo "NSG still has $open_count wildcard inbound Allow rule(s) for $RESOURCE_ID" >&2
  return 1
}

# enforce-nsg-rule-deny-all
# Passes when the NSG has at least one inbound Deny rule with wildcard source,
# confirming the DenyAll baseline rule was successfully inserted.
_verify_nsg_rule_deny_all() {
  _require_az || return 2
  local deny_count
  deny_count="$(az network nsg show --ids "$RESOURCE_ID" \
    --query "securityRules[?direction=='Inbound' && access=='Deny' \
      && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0')] \
      | length(@)" \
    -o tsv 2>/dev/null)" || { echo "az nsg query failed for $RESOURCE_ID" >&2; return 2; }
  if [[ -z "$deny_count" ]]; then
    echo "az nsg query returned empty result for $RESOURCE_ID" >&2; return 2
  fi
  if [[ "$deny_count" -gt 0 ]]; then return 0; fi
  echo "NSG missing DenyAll inbound rule for $RESOURCE_ID" >&2
  return 1
}

# deny-public-storage
# Passes when allowBlobPublicAccess=false AND networkRuleSet.defaultAction=Deny.
_verify_deny_public_storage() {
  _require_az || return 2
  local public_access default_action
  public_access="$(az storage account show --ids "$RESOURCE_ID" \
    --query 'allowBlobPublicAccess' -o tsv 2>/dev/null)" \
    || { echo "az storage query failed for $RESOURCE_ID" >&2; return 2; }
  default_action="$(az storage account show --ids "$RESOURCE_ID" \
    --query 'networkRuleSet.defaultAction' -o tsv 2>/dev/null)" \
    || { echo "az storage query failed for $RESOURCE_ID" >&2; return 2; }
  if [[ "${public_access,,}" == "false" && "${default_action^^}" == "DENY" ]]; then
    return 0
  fi
  echo "storage not private for $RESOURCE_ID (allowBlobPublicAccess=${public_access}, defaultAction=${default_action})" >&2
  return 1
}

# enforce-storage-tls
# Passes when minimumTlsVersion=TLS1_2.
_verify_enforce_storage_tls() {
  _require_az || return 2
  local tls_version
  tls_version="$(az storage account show --ids "$RESOURCE_ID" \
    --query 'minimumTlsVersion' -o tsv 2>/dev/null)" \
    || { echo "az storage query failed for $RESOURCE_ID" >&2; return 2; }
  if [[ "$tls_version" == "TLS1_2" ]]; then return 0; fi
  echo "minimumTlsVersion is '${tls_version}' (want TLS1_2) for $RESOURCE_ID" >&2
  return 1
}

# enforce-storage-container-private
# Passes when properties.publicAccess is None (or null/empty in CLI TSV output).
_verify_storage_container_private() {
  _require_az || return 2
  local public_access
  public_access="$(az resource show --ids "$RESOURCE_ID" \
    --query 'properties.publicAccess' -o tsv 2>/dev/null)" \
    || { echo "az storage container query failed for $RESOURCE_ID" >&2; return 2; }

  if [[ -z "$public_access" || "$public_access" == "None" ]]; then
    return 0
  fi
  echo "storage container still public for $RESOURCE_ID (publicAccess=${public_access})" >&2
  return 1
}

# enforce-sql-no-public-network
# Passes when SQL logical server has zero firewall rules (including no
# AllowAllWindowsAzureIps / 0.0.0.0 bypass rule).
_verify_sql_no_public_network() {
  _require_az || return 2
  local fw_count
  fw_count="$(az sql server firewall-rule list --ids "$RESOURCE_ID" \
    --query 'length(@)' -o tsv 2>/dev/null)" \
    || { echo "az sql firewall rule list failed for $RESOURCE_ID" >&2; return 2; }

  if [[ -z "$fw_count" ]]; then
    echo "az sql firewall query returned empty result for $RESOURCE_ID" >&2
    return 2
  fi

  if [[ "$fw_count" == "0" ]]; then
    return 0
  fi
  echo "sql server still has $fw_count firewall rule(s) for $RESOURCE_ID" >&2
  return 1
}

# enforce-keyvault-purge-protection
# Passes when both enableSoftDelete=true AND enablePurgeProtection=true.
_verify_keyvault_purge_protection() {
  _require_az || return 2
  local soft_delete purge_protection
  soft_delete="$(az keyvault show --id "$RESOURCE_ID" \
    --query 'properties.enableSoftDelete' -o tsv 2>/dev/null)" \
    || { echo "az keyvault query failed for $RESOURCE_ID" >&2; return 2; }
  purge_protection="$(az keyvault show --id "$RESOURCE_ID" \
    --query 'properties.enablePurgeProtection' -o tsv 2>/dev/null)" \
    || { echo "az keyvault query failed for $RESOURCE_ID" >&2; return 2; }
  if [[ "${soft_delete,,}" == "true" && "${purge_protection,,}" == "true" ]]; then
    return 0
  fi
  echo "keyvault missing purge protection for $RESOURCE_ID (softDelete=${soft_delete}, purgeProtection=${purge_protection})" >&2
  return 1
}

# enforce-appservice-https
# Passes when httpsOnly=true on the App Service.
_verify_appservice_https() {
  _require_az || return 2
  local https_only
  https_only="$(az webapp show --ids "$RESOURCE_ID" \
    --query 'httpsOnly' -o tsv 2>/dev/null)" \
    || { echo "az webapp query failed for $RESOURCE_ID" >&2; return 2; }
  if [[ "${https_only,,}" == "true" ]]; then return 0; fi
  echo "app service httpsOnly is '${https_only}' (want true) for $RESOURCE_ID" >&2
  return 1
}

# enforce-sql-threat-detection
# Passes when the Default security alert policy is Enabled on the SQL server.
_verify_sql_threat_detection() {
  _require_az || return 2
  local state
  state="$(az sql server threat-policy show --ids "$RESOURCE_ID" \
    --query 'state' -o tsv 2>/dev/null)" \
    || { echo "az sql threat-policy query failed for $RESOURCE_ID" >&2; return 2; }
  if [[ -z "$state" ]]; then
    echo "az sql threat-policy returned empty result for $RESOURCE_ID" >&2; return 2
  fi
  if [[ "${state^^}" == "ENABLED" ]]; then return 0; fi
  echo "sql threat detection state is '${state}' (want Enabled) for $RESOURCE_ID" >&2
  return 1
}

# ── Policy dispatcher ─────────────────────────────────────────────────────────

_is_known_policy() {
  case "$1" in
    enforce-nsg-no-open-inbound|\
    prowler:network_security_group_unrestricted_inbound_access*|\
    enforce-nsg-rule-deny-all|\
    deny-public-storage|\
    prowler:storage_default_network_access_rule_is_denied|\
    prowler:storage_container_public_access_level_is_disabled|\
    prowler:storage_container_public_access_level_is_private|\
    enforce-storage-container-private|\
    enforce-storage-tls|\
    enforce-sql-no-public-network|\
    enforce-keyvault-purge-protection|\
    prowler:keyvault_soft_delete_is_enabled|\
    enforce-appservice-https|\
    prowler:app_ensure_https_is_enforced|\
    enforce-sql-threat-detection|\
    prowler:sqlserver_threat_detection_types_all)
      return 0 ;;
    *) return 1 ;;
  esac
}

# Runs the appropriate inline verifier for POLICY.
# Exit codes: 0=pass, 1=still drifted, 2=az error.
_run_check() {
  case "$POLICY" in
    enforce-nsg-no-open-inbound|\
    prowler:network_security_group_unrestricted_inbound_access*)
      _verify_nsg_no_open_inbound ;;
    enforce-nsg-rule-deny-all)
      _verify_nsg_rule_deny_all ;;
    deny-public-storage|\
    prowler:storage_default_network_access_rule_is_denied)
      _verify_deny_public_storage ;;
    prowler:storage_container_public_access_level_is_disabled|\
    prowler:storage_container_public_access_level_is_private|\
    enforce-storage-container-private)
      _verify_storage_container_private ;;
    enforce-storage-tls)
      _verify_enforce_storage_tls ;;
    enforce-sql-no-public-network)
      _verify_sql_no_public_network ;;
    enforce-keyvault-purge-protection|\
    prowler:keyvault_soft_delete_is_enabled)
      _verify_keyvault_purge_protection ;;
    enforce-appservice-https|\
    prowler:app_ensure_https_is_enforced)
      _verify_appservice_https ;;
    enforce-sql-threat-detection|\
    prowler:sqlserver_threat_detection_types_all)
      _verify_sql_threat_detection ;;
  esac
}

# ── Main ──────────────────────────────────────────────────────────────────────

# Export variables and functions so they survive the bash -c subshell used by timeout.
export RESOURCE_ID POLICY
export -f _require_az \
          _verify_nsg_no_open_inbound \
          _verify_nsg_rule_deny_all \
          _verify_deny_public_storage \
          _verify_enforce_storage_tls \
          _verify_storage_container_private \
          _verify_sql_no_public_network \
          _run_check

_emit_state "REMEDIATION_ATTEMPTED" false 0 "verification_started"

# Unknown policy: no registered inline verifier — cannot assert verification passed.
# Exit 3 (VERIFY_SKIP) is semantically distinct from 0 (verified), 1 (drift remains),
# and 2 (az error). Callers must NOT count exit 3 as a successful verification.
if ! _is_known_policy "$POLICY"; then
  echo "policy '${POLICY}' has no registered inline verifier (VERIFY_SKIP)" >&2
  _emit_state "VERIFY_SKIP" false 0 "verify_skip_unknown_policy"
  exit 3
fi

attempt=1
while [[ "$attempt" -le "$MAX_RETRIES" ]]; do
  if timeout "$TIMEOUT_SECONDS" bash -c '_run_check'; then
    _emit_state "REMEDIATION_VERIFIED" true "$attempt" "verification_passed"
    exit 0
  fi

  if [[ "$attempt" -lt "$MAX_RETRIES" ]]; then
    sleep 2
  fi
  attempt=$((attempt + 1))
done

_emit_state "FAILED" false "$MAX_RETRIES" "verification_failed_after_retries"
exit 1
