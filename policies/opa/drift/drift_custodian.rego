# ==============================================================================
# Shift-Right Drift — Cloud Custodian policy mapping
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# FIX: P1.3 — Custodian policies pour tous les types critiques et high.
# NOTE: Les fichiers YAML Custodian correspondants seront créés en Phase P2.
# Ces identifiants servent de référence pour le mapping OPA → Cloud Custodian.
# Structure en chaîne else pour éviter eval_conflict_error (une seule valeur possible).

# NSG — CRITICAL
get_custodian_policy(finding) := "enforce-nsg-no-open-inbound" if {
	object.get(finding, "type", "") == "azurerm_network_security_group"
	"security_rule" in object.get(finding, "changed_paths", [])
} else := "enforce-nsg-rule-deny-all" if {
	# NSG rule — CRITICAL
	object.get(finding, "type", "") == "azurerm_network_security_rule"
	"access" in object.get(finding, "changed_paths", [])
} else := "enforce-vm-no-password-auth" if {
	# VM — CRITICAL
	object.get(finding, "type", "") == "azurerm_linux_virtual_machine"
	"admin_password" in object.get(finding, "changed_paths", [])
} else := "enforce-sql-password-rotation" if {
	# SQL — CRITICAL
	object.get(finding, "type", "") == "azurerm_sql_server"
	"administrator_login_password" in object.get(finding, "changed_paths", [])
} else := "enforce-keyvault-access-policy" if {
	# Key Vault access_policy — HIGH
	object.get(finding, "type", "") == "azurerm_key_vault"
	"access_policy" in object.get(finding, "changed_paths", [])
} else := "enforce-keyvault-network-acls" if {
	# Key Vault network_acls — HIGH
	object.get(finding, "type", "") == "azurerm_key_vault"
	"network_acls" in object.get(finding, "changed_paths", [])
} else := "enforce-storage-tls" if {
	# Storage TLS — HIGH
	object.get(finding, "type", "") == "azurerm_storage_account"
	"min_tls_version" in object.get(finding, "changed_paths", [])
} else := "deny-public-storage" if {
	# Storage public blob — HIGH
	object.get(finding, "type", "") == "azurerm_storage_account"
	"allow_blob_public_access" in object.get(finding, "changed_paths", [])
} else := null # Fallback : type non couvert → null (pas de remédiation automatique connue)
