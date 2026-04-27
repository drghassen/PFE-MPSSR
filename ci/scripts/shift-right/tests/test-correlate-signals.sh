#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CloudSentinel — Smoke test for ci/scripts/shift-right/correlate-signals.sh
#
# Tests four cases using fixture data (no live Azure calls):
#   TC1 — both inputs absent/empty   → valid empty report, 0 correlations
#   TC2 — matching resource UID      → 1 correlation detected (direct match)
#   TC3 — matching resource type prefix → 1 correlation detected (semantic match)
#   TC4 — no match                   → 0 correlations
#
# Run from the repo root:
#   bash ci/scripts/shift-right/tests/test-correlate-signals.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
CORRELATE_SCRIPT="${REPO_ROOT}/ci/scripts/shift-right/correlate-signals.sh"
MAPPINGS_SRC="${REPO_ROOT}/ci/scripts/shift-right/correlation_mappings.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0

_pass() { echo -e "  ${GREEN}${BOLD}PASS${NC} $*"; ((PASS++)) || true; }
_fail() { echo -e "  ${RED}${BOLD}FAIL${NC} $*"; ((FAIL++)) || true; }

# ── Test harness helpers ───────────────────────────────────────────────────────

# Set up an isolated temp directory that mirrors the repo structure the script
# expects. Overrides paths via the env vars correlate-signals.sh supports.
_setup() {
  TEST_DIR="$(mktemp -d)"
  mkdir -p \
    "${TEST_DIR}/.cloudsentinel" \
    "${TEST_DIR}/shift-right/drift-engine/output" \
    "${TEST_DIR}/ci/scripts/shift-right"
  cp "${MAPPINGS_SRC}" "${TEST_DIR}/ci/scripts/shift-right/correlation_mappings.json"

  # Override path env vars used by correlate-signals.sh
  export PROWLER_FINDINGS_PATH="${TEST_DIR}/.cloudsentinel/prowler_generic_findings.json"
  export DRIFT_REPORT_PATH="${TEST_DIR}/shift-right/drift-engine/output/drift-report.json"
  export OPA_PROWLER_DECISION_PATH="${TEST_DIR}/.cloudsentinel/opa_prowler_decision.json"
  export OPA_DRIFT_DECISION_PATH="${TEST_DIR}/.cloudsentinel/opa_drift_decision.json"
  export CORRELATION_MAPPINGS_PATH="${TEST_DIR}/ci/scripts/shift-right/correlation_mappings.json"
  export CORRELATION_OUTPUT_DIR="${TEST_DIR}/.cloudsentinel"
}

_teardown() {
  rm -rf "${TEST_DIR:-}"
  unset PROWLER_FINDINGS_PATH DRIFT_REPORT_PATH OPA_PROWLER_DECISION_PATH \
        OPA_DRIFT_DECISION_PATH CORRELATION_MAPPINGS_PATH CORRELATION_OUTPUT_DIR
}

_run_script() {
  (cd "${TEST_DIR}" && bash "${CORRELATE_SCRIPT}") 2>&1
}

_assert_correlation_count() {
  local expected="$1"
  local report="${TEST_DIR}/.cloudsentinel/correlation_report.json"
  local actual
  if [[ ! -f "${report}" ]]; then
    _fail "correlation_report.json was not written"
    return
  fi
  if ! actual="$(jq '.meta.correlations_found' "${report}" 2>/dev/null)"; then
    _fail "correlation_report.json is not valid JSON"
    return
  fi
  if [[ "${actual}" == "${expected}" ]]; then
    _pass "correlations_found=${actual} (expected ${expected})"
  else
    _fail "correlations_found=${actual}, expected ${expected}"
    echo "    Report:"
    cat "${report}" | jq '.' 2>/dev/null || cat "${report}"
  fi
}

_assert_env_var() {
  local var="$1"
  local expected="$2"
  local env_file="${TEST_DIR}/.cloudsentinel/correlation.env"
  if [[ ! -f "${env_file}" ]]; then
    _fail "correlation.env was not written"
    return
  fi
  local actual
  actual="$(grep "^${var}=" "${env_file}" | cut -d= -f2 || echo "NOT_FOUND")"
  if [[ "${actual}" == "${expected}" ]]; then
    _pass "${var}=${actual} (expected ${expected})"
  else
    _fail "${var}=${actual}, expected ${expected}"
  fi
}

# ── Fixture writers ────────────────────────────────────────────────────────────

_write_empty_prowler() {
  echo '{"findings": []}' > "${PROWLER_FINDINGS_PATH}"
}

_write_empty_drift() {
  jq -n '{
    schema_version: "1.0",
    ocsf: { version: "1.0", class_uid: 2001, category_uid: 2, type_uid: 200101,
            time: "2024-01-01T00:00:00Z", severity_id: 0, severity: "Informational" },
    cloudsentinel: { run_id: "test", engine: "drift-engine", engine_version: "1.0.0",
                     terraform_workspace: "default", terraform_working_dir: "/tmp",
                     started_at: "2024-01-01T00:00:00Z", finished_at: "2024-01-01T00:01:00Z",
                     duration_ms: 60000 },
    drift: { detected: false, exit_code: 0,
             summary: { resources_changed: 0, resources_by_action: {}, provider_names: [] },
             items: [] },
    terraform: { version: "1.5.0", init: {}, plan: {} },
    errors: []
  }' > "${DRIFT_REPORT_PATH}"
}

_write_uid_match_prowler() {
  # A Critical finding on a storage account resource (identified by ARM UID)
  jq -n '{
    findings: [{
      title: "Prowler: azure_storage_account_https_only",
      severity: "Critical",
      date: "2024-01-01",
      description: "Storage account does not enforce HTTPS",
      mitigation: "Enable HTTPS-only",
      references: "",
      unique_id_from_tool: "prowler:azure_storage_account_https_only:/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage",
      vuln_id_from_tool: "prowler:azure_storage_account_https_only",
      component_name: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage"
    }]
  }' > "${PROWLER_FINDINGS_PATH}"
}

_write_uid_match_drift() {
  # Drift item whose resource_id matches the prowler component_name exactly
  jq -n '{
    schema_version: "1.0",
    ocsf: { version: "1.0", class_uid: 2001, category_uid: 2, type_uid: 200101,
            time: "2024-01-01T00:00:00Z", severity_id: 4, severity: "High" },
    cloudsentinel: { run_id: "test", engine: "drift-engine", engine_version: "1.0.0",
                     terraform_workspace: "default", terraform_working_dir: "/tmp",
                     started_at: "2024-01-01T00:00:00Z", finished_at: "2024-01-01T00:01:00Z",
                     duration_ms: 60000 },
    drift: {
      detected: true, exit_code: 2,
      summary: { resources_changed: 1, resources_by_action: { update: 1 }, provider_names: ["registry.terraform.io/hashicorp/azurerm"] },
      items: [{
        address: "azurerm_storage_account.mystorage",
        mode: "managed",
        type: "azurerm_storage_account",
        name: "mystorage",
        provider_name: "registry.terraform.io/hashicorp/azurerm",
        actions: ["update"],
        resource_id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage",
        changed_paths: ["min_tls_version"],
        drifted: true
      }]
    },
    terraform: { version: "1.5.0", init: {}, plan: {} },
    errors: []
  }' > "${DRIFT_REPORT_PATH}"
}

_write_opa_drift_high() {
  # OPA drift decision with one HIGH effective violation
  jq -n '{
    result: {
      allow: false,
      deny: [],
      effective_violations: [{
        resource_id: "azurerm_storage_account.mystorage",
        severity: "HIGH",
        reason: "TLS version changed",
        action_required: "schedule_review"
      }]
    }
  }' > "${OPA_DRIFT_DECISION_PATH}"
}

_write_type_match_prowler() {
  # A High finding where the check_id prefix matches azurerm_storage_account.
  # component_name is different from any drift address/resource_id — only the
  # type-prefix mapping should fire.
  jq -n '{
    findings: [{
      title: "Prowler: azure_storage_account_default_action",
      severity: "High",
      date: "2024-01-01",
      description: "Storage public access not restricted",
      mitigation: "Set default action to Deny",
      references: "",
      unique_id_from_tool: "prowler:azure_storage_account_default_action:otherstorage",
      vuln_id_from_tool: "prowler:azure_storage_account_default_action",
      component_name: "otherstorage"
    }]
  }' > "${PROWLER_FINDINGS_PATH}"
}

_write_type_match_drift() {
  # Drift item with type azurerm_storage_account — but address/resource_id
  # do NOT match the prowler component_name.  Only type-prefix matching fires.
  jq -n '{
    schema_version: "1.0",
    ocsf: { version: "1.0", class_uid: 2001, category_uid: 2, type_uid: 200101,
            time: "2024-01-01T00:00:00Z", severity_id: 4, severity: "High" },
    cloudsentinel: { run_id: "test", engine: "drift-engine", engine_version: "1.0.0",
                     terraform_workspace: "default", terraform_working_dir: "/tmp",
                     started_at: "2024-01-01T00:00:00Z", finished_at: "2024-01-01T00:01:00Z",
                     duration_ms: 60000 },
    drift: {
      detected: true, exit_code: 2,
      summary: { resources_changed: 1, resources_by_action: { update: 1 }, provider_names: ["registry.terraform.io/hashicorp/azurerm"] },
      items: [{
        address: "azurerm_storage_account.differentname",
        mode: "managed",
        type: "azurerm_storage_account",
        name: "differentname",
        provider_name: "registry.terraform.io/hashicorp/azurerm",
        actions: ["update"],
        resource_id: "some-arm-id-that-does-not-match",
        changed_paths: ["allow_blob_public_access"],
        drifted: true
      }]
    },
    terraform: { version: "1.5.0", init: {}, plan: {} },
    errors: []
  }' > "${DRIFT_REPORT_PATH}"
}

_write_no_match_prowler() {
  # A finding about a Key Vault — should not match a storage drift item.
  jq -n '{
    findings: [{
      title: "Prowler: azure_keyvault_rbac_enabled",
      severity: "Medium",
      date: "2024-01-01",
      description: "Key Vault RBAC not enabled",
      mitigation: "Enable RBAC",
      references: "",
      unique_id_from_tool: "prowler:azure_keyvault_rbac_enabled:/subscriptions/s/rg/kv/myvault",
      vuln_id_from_tool: "prowler:azure_keyvault_rbac_enabled",
      component_name: "/subscriptions/s/rg/kv/myvault"
    }]
  }' > "${PROWLER_FINDINGS_PATH}"
}

_write_no_match_drift() {
  # Drift on an NSG — no type prefix overlap with azure_keyvault_rbac_enabled,
  # and no direct UID match.
  jq -n '{
    schema_version: "1.0",
    ocsf: { version: "1.0", class_uid: 2001, category_uid: 2, type_uid: 200101,
            time: "2024-01-01T00:00:00Z", severity_id: 5, severity: "Critical" },
    cloudsentinel: { run_id: "test", engine: "drift-engine", engine_version: "1.0.0",
                     terraform_workspace: "default", terraform_working_dir: "/tmp",
                     started_at: "2024-01-01T00:00:00Z", finished_at: "2024-01-01T00:01:00Z",
                     duration_ms: 60000 },
    drift: {
      detected: true, exit_code: 2,
      summary: { resources_changed: 1, resources_by_action: { update: 1 }, provider_names: ["registry.terraform.io/hashicorp/azurerm"] },
      items: [{
        address: "azurerm_network_security_group.my_nsg",
        mode: "managed",
        type: "azurerm_network_security_group",
        name: "my_nsg",
        provider_name: "registry.terraform.io/hashicorp/azurerm",
        actions: ["update"],
        resource_id: "/subscriptions/s/rg/nsg/my_nsg",
        changed_paths: ["security_rule"],
        drifted: true
      }]
    },
    terraform: { version: "1.5.0", init: {}, plan: {} },
    errors: []
  }' > "${DRIFT_REPORT_PATH}"
}

# ── TC1: both inputs empty → valid empty report ────────────────────────────────
echo -e "\n${BLUE}${BOLD}TC1${NC} Both inputs empty → valid empty report, 0 correlations"
_setup
_write_empty_prowler
_write_empty_drift
_run_script >/dev/null 2>&1 || true
_assert_correlation_count 0
_assert_env_var "CORRELATION_COUNT" "0"
_assert_env_var "CORRELATION_CRITICAL_CONFIRMED" "0"
_teardown

# ── TC2: matching resource UID → correlation detected ─────────────────────────
echo -e "\n${BLUE}${BOLD}TC2${NC} Matching resource UID (component_name == resource_id) → 1 correlation"
_setup
_write_uid_match_prowler
_write_uid_match_drift
_write_opa_drift_high
_run_script >/dev/null 2>&1 || true
_assert_correlation_count 1

# Verify the record fields are correct
REPORT="${TEST_DIR}/.cloudsentinel/correlation_report.json"
ACTUAL_RISK="$(jq -r '.correlations[0].combined_risk' "${REPORT}" 2>/dev/null || echo "MISSING")"
# Critical (prowler) + any drift → CRITICAL_CONFIRMED
if [[ "${ACTUAL_RISK}" == "CRITICAL_CONFIRMED" ]]; then
  _pass "combined_risk=CRITICAL_CONFIRMED (Critical prowler + High drift)"
else
  _fail "combined_risk=${ACTUAL_RISK}, expected CRITICAL_CONFIRMED"
fi

# Verify correlation_id is a 16-char hex string
ACTUAL_ID="$(jq -r '.correlations[0].correlation_id' "${REPORT}" 2>/dev/null || echo "")"
if [[ "${ACTUAL_ID}" =~ ^[0-9a-f]{16}$ ]]; then
  _pass "correlation_id is 16-char hex: ${ACTUAL_ID}"
else
  _fail "correlation_id has unexpected format: '${ACTUAL_ID}'"
fi

_assert_env_var "CORRELATION_CRITICAL_CONFIRMED" "1"
_teardown

# ── TC3: matching resource type prefix → correlation detected ─────────────────
echo -e "\n${BLUE}${BOLD}TC3${NC} Matching resource type prefix (azure_storage_* → azurerm_storage_account) → 1 correlation"
_setup
_write_type_match_prowler
_write_type_match_drift
# OPA drift decision for the type-match drift item (address = azurerm_storage_account.differentname)
jq -n '{
  result: {
    allow: false,
    deny: [],
    effective_violations: [{
      resource_id: "azurerm_storage_account.differentname",
      severity: "HIGH",
      reason: "Public blob access changed",
      action_required: "schedule_review"
    }]
  }
}' > "${OPA_DRIFT_DECISION_PATH}"
_run_script >/dev/null 2>&1 || true
_assert_correlation_count 1

# High prowler + High drift → HIGH_CONFIRMED
REPORT="${TEST_DIR}/.cloudsentinel/correlation_report.json"
ACTUAL_RISK="$(jq -r '.correlations[0].combined_risk' "${REPORT}" 2>/dev/null || echo "MISSING")"
if [[ "${ACTUAL_RISK}" == "HIGH_CONFIRMED" ]]; then
  _pass "combined_risk=HIGH_CONFIRMED (High prowler + High drift)"
else
  _fail "combined_risk=${ACTUAL_RISK}, expected HIGH_CONFIRMED"
fi
_teardown

# ── TC4: no match → empty correlations ────────────────────────────────────────
echo -e "\n${BLUE}${BOLD}TC4${NC} No match (keyvault finding vs NSG drift) → 0 correlations"
_setup
_write_no_match_prowler
_write_no_match_drift
_run_script >/dev/null 2>&1 || true
_assert_correlation_count 0
_assert_env_var "CORRELATION_COUNT" "0"
_teardown

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "══════════════════════════════════════"
TOTAL=$((PASS + FAIL))
if [[ "${FAIL}" -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}All ${TOTAL} assertions passed${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}${FAIL} / ${TOTAL} assertion(s) FAILED${NC}"
  exit 1
fi
