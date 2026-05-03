# =============================================================================
# CloudSentinel Remediation — Key Vault Diagnostic Settings
# Finding : azure_keyvault_logging_enabled (Prowler)
# Severity : MEDIUM
# =============================================================================
#
# PURPOSE
#   Standalone module to add/repair azurerm_monitor_diagnostic_setting for an
#   existing Key Vault without touching the vault itself, its secrets, access
#   policies, or any other resource.
#
# USAGE
#   Run this ONLY when:
#     • The root module's diagnostic setting is already in Terraform state
#       (use import below) OR
#     • You need to remediate a Key Vault managed outside this repo
#
# IMPORT (idempotency guard)
#   Before running `terraform apply`, check whether the diagnostic setting
#   already exists in Azure:
#
#     az monitor diagnostic-settings list \
#       --resource <KEY_VAULT_ID> \
#       --query "[].{name:name, id:id}" -o table
#
#   If it exists, import it first:
#
#     terraform import \
#       azurerm_monitor_diagnostic_setting.kv_audit \
#       "<KEY_VAULT_ID>|<DIAG_SETTING_NAME>"
#
#   Example:
#     terraform import \
#       azurerm_monitor_diagnostic_setting.kv_audit \
#       "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-cs-dev/providers/Microsoft.KeyVault/vaults/kv-cs-dev|kv-cs-dev-diag"
#
# =============================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.85.0"
    }
  }
  required_version = ">= 1.5.0"
}

# ---------------------------------------------------------------------------
# DATA — reference existing Key Vault (read-only, no mutation)
# ---------------------------------------------------------------------------
data "azurerm_key_vault" "target" {
  name                = var.key_vault_name
  resource_group_name = var.resource_group_name
}

# ---------------------------------------------------------------------------
# DATA — reference existing Log Analytics Workspace
# ---------------------------------------------------------------------------
data "azurerm_log_analytics_workspace" "law" {
  name                = var.log_analytics_workspace_name
  resource_group_name = var.log_analytics_workspace_rg
}

# ---------------------------------------------------------------------------
# REMEDIATION — Diagnostic Setting
#
# Key Vault exposes a single log category: AuditEvent.
# Prowler's azure_keyvault_logging_enabled check inspects the logs[] array
# of the ARM diagnostic-settings response — it does NOT inspect categoryGroups[].
# Explicitly setting category = "AuditEvent" satisfies the check and makes
# intent auditable.
# ---------------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "kv_audit" {
  name = var.diagnostic_setting_name

  # Reference the existing vault — we never import or recreate it here.
  target_resource_id = data.azurerm_key_vault.target.id

  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.law.id

  # Explicit AuditEvent: covers all control-plane operations on the vault
  # (secret/key/certificate CRUD, access policy changes, purge, backup, etc.)
  enabled_log {
    category = "AuditEvent"
  }

  # AllMetrics: request latency, availability, saturation counters
  enabled_metric {
    category = "AllMetrics"
  }

  lifecycle {
    # Prevent destroy; only allow in-place updates.
    # Deletion would silently remove audit logging — a regression.
    prevent_destroy = true
  }
}
