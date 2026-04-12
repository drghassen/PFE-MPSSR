# ==============================================================================
# CloudSentinel — Tests unitaires Shift-Right Drift Policy
# ==============================================================================
# Run: opa test policies/opa/ -v
# Coverage: 18 tests across 5 groups
# ==============================================================================

package cloudsentinel.shiftright.drift

import future.keywords.if
import future.keywords.in

# ──────────────────────────────────────────────────────────────────────────────
# Groupe 1 — Defaults et fail-safe (valide P0.1)
# ──────────────────────────────────────────────────────────────────────────────

# P0.1 : input vide → violations doit être [] (pas undefined)
test_empty_input_returns_empty_violations if {
	result := violations with input as {}
	result == []
}

# P0.1 : findings null → violations doit être []
test_null_findings_returns_empty_violations if {
	result := violations with input as {"findings": null}
	result == []
}

# P0.1 : findings vide → violations doit être []
test_empty_findings_returns_empty_violations if {
	result := violations with input as {"findings": []}
	result == []
}

# P0.1 : findings vide → compliant doit être []
test_empty_findings_returns_empty_compliant if {
	result := compliant with input as {"findings": []}
	result == []
}

# ──────────────────────────────────────────────────────────────────────────────
# Groupe 2 — Classification de sévérité
# ──────────────────────────────────────────────────────────────────────────────

# NSG security_rule → CRITICAL
test_nsg_security_rule_drift_is_critical if {
	result := evaluate_drift({
		"address": "azurerm_network_security_group.test_nsg",
		"type": "azurerm_network_security_group",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["security_rule"],
		"actions": ["update"],
	})
	result.severity == "CRITICAL"
}

# NSG rule access → CRITICAL
test_nsg_rule_access_drift_is_critical if {
	result := evaluate_drift({
		"address": "azurerm_network_security_rule.deny_all",
		"type": "azurerm_network_security_rule",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["access"],
		"actions": ["update"],
	})
	result.severity == "CRITICAL"
}

# VM admin_password → CRITICAL
test_vm_admin_password_drift_is_critical if {
	result := evaluate_drift({
		"address": "azurerm_linux_virtual_machine.vm",
		"type": "azurerm_linux_virtual_machine",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["admin_password"],
		"actions": ["update"],
	})
	result.severity == "CRITICAL"
}

# SQL server password → CRITICAL
test_sql_server_password_drift_is_critical if {
	result := evaluate_drift({
		"address": "azurerm_sql_server.sql",
		"type": "azurerm_sql_server",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["administrator_login_password"],
		"actions": ["update"],
	})
	result.severity == "CRITICAL"
}

# Key Vault access_policy → HIGH
test_keyvault_access_policy_drift_is_high if {
	result := evaluate_drift({
		"address": "azurerm_key_vault.kv",
		"type": "azurerm_key_vault",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["access_policy"],
		"actions": ["update"],
	})
	result.severity == "HIGH"
}

# Storage min_tls_version → HIGH
test_storage_tls_drift_is_high if {
	result := evaluate_drift({
		"address": "azurerm_storage_account.sa",
		"type": "azurerm_storage_account",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["min_tls_version"],
		"actions": ["update"],
	})
	result.severity == "HIGH"
}

# Diagnostic setting enabled_log → MEDIUM
test_diagnostic_setting_drift_is_medium if {
	result := evaluate_drift({
		"address": "azurerm_monitor_diagnostic_setting.diag",
		"type": "azurerm_monitor_diagnostic_setting",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["enabled_log"],
		"actions": ["update"],
	})
	result.severity == "MEDIUM"
}

# Log analytics retention → LOW
test_log_analytics_retention_drift_is_low if {
	result := evaluate_drift({
		"address": "azurerm_log_analytics_workspace.law",
		"type": "azurerm_log_analytics_workspace",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["retention_in_days"],
		"actions": ["update"],
	})
	result.severity == "LOW"
}

# ──────────────────────────────────────────────────────────────────────────────
# Groupe 3 — Fallback et null-safety (valide P0.2, P0.3)
# ──────────────────────────────────────────────────────────────────────────────

# P0.3 : type non classifié avec changed_paths → LOW (PAS INFO)
test_unknown_resource_type_with_changed_paths_is_low_not_info if {
	result := evaluate_drift({
		"address": "azurerm_virtual_network.vnet",
		"type": "azurerm_virtual_network",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["address_space"],
		"actions": ["update"],
	})
	result.severity == "LOW"
	result.severity != "INFO"
}

# P0.3 : changed_paths vide → INFO (pas de drift réel)
test_finding_with_empty_changed_paths_is_info if {
	result := evaluate_drift({
		"address": "azurerm_virtual_network.vnet",
		"type": "azurerm_virtual_network",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": [],
		"actions": ["no-op"],
	})
	result.severity == "INFO"
}

# P0.2 : address manquant → LOW + manual_review (pas de silence)
test_finding_missing_address_returns_low_manual_review if {
	result := evaluate_drift({
		"type": "azurerm_storage_account",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["min_tls_version"],
	})
	result.severity == "LOW"
	result.action_required == "manual_review"
}

# P0.2 : type manquant → LOW + manual_review (pas de silence)
test_finding_missing_type_returns_low_manual_review if {
	result := evaluate_drift({
		"address": "azurerm_storage_account.sa",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["min_tls_version"],
	})
	result.severity == "LOW"
	result.action_required == "manual_review"
}

# ──────────────────────────────────────────────────────────────────────────────
# Groupe 4 — Actions
# ──────────────────────────────────────────────────────────────────────────────

# CRITICAL → immediate_review
test_critical_drift_action_is_immediate_review if {
	result := evaluate_drift({
		"address": "azurerm_network_security_group.nsg",
		"type": "azurerm_network_security_group",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["security_rule"],
		"actions": ["update"],
	})
	result.action_required == "immediate_review"
}

# HIGH + storage → auto_remediate
test_high_storage_drift_action_is_auto_remediate if {
	result := evaluate_drift({
		"address": "azurerm_storage_account.sa",
		"type": "azurerm_storage_account",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["min_tls_version"],
		"actions": ["update"],
	})
	result.action_required == "auto_remediate"
}

# LOW → monitor
test_low_drift_action_is_monitor if {
	result := evaluate_drift({
		"address": "azurerm_log_analytics_workspace.law",
		"type": "azurerm_log_analytics_workspace",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["retention_in_days"],
		"actions": ["update"],
	})
	result.action_required == "monitor"
}

# ──────────────────────────────────────────────────────────────────────────────
# Groupe 5 — Custodian mapping (valide P1.3)
# ──────────────────────────────────────────────────────────────────────────────

# Storage + min_tls_version → enforce-storage-tls
test_storage_tls_has_custodian_policy if {
	result := evaluate_drift({
		"address": "azurerm_storage_account.sa",
		"type": "azurerm_storage_account",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["min_tls_version"],
		"actions": ["update"],
	})
	result.custodian_policy == "enforce-storage-tls"
}

# Storage + allow_blob_public_access → deny-public-storage
test_storage_public_blob_has_custodian_policy if {
	result := evaluate_drift({
		"address": "azurerm_storage_account.sa",
		"type": "azurerm_storage_account",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["allow_blob_public_access"],
		"actions": ["update"],
	})
	result.custodian_policy == "deny-public-storage"
}

# NSG + security_rule → enforce-nsg-no-open-inbound (P1.3)
test_nsg_has_custodian_policy if {
	result := evaluate_drift({
		"address": "azurerm_network_security_group.nsg",
		"type": "azurerm_network_security_group",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["security_rule"],
		"actions": ["update"],
	})
	result.custodian_policy == "enforce-nsg-no-open-inbound"
}

# Type inconnu → custodian_policy = null
test_unknown_type_has_null_custodian_policy if {
	result := evaluate_drift({
		"address": "azurerm_virtual_network.vnet",
		"type": "azurerm_virtual_network",
		"provider_name": "registry.terraform.io/hashicorp/azurerm",
		"changed_paths": ["address_space"],
		"actions": ["update"],
	})
	result.custodian_policy == null
}
