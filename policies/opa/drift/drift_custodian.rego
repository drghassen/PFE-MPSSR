# ==============================================================================
# Shift-Right Drift - Cloud Custodian policy mapping
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# Custodian mappings are intentionally restricted to CRITICAL drift categories.
# Non-critical findings are handled by notification and DefectDojo, then Terraform fix.
get_custodian_policy(finding) := "enforce-nsg-no-open-inbound" if {
	object.get(finding, "type", "") == "azurerm_network_security_group"
	changed_paths_has_key(finding, "security_rule")
} else := "enforce-nsg-rule-deny-all" if {
	object.get(finding, "type", "") == "azurerm_network_security_rule"
	changed_paths_has_key(finding, "access")
} else := "enforce-sql-no-public-network" if {
	object.get(finding, "type", "") in {"azurerm_sql_server", "azurerm_mssql_server"}
	_public_network_drift(finding)
} else := "enforce-storage-container-private" if {
	object.get(finding, "type", "") == "azurerm_storage_container"
	changed_paths_has_key(finding, "container_access_type")
} else := null

_public_network_drift(finding) if {
	changed_paths_has_key(finding, "public_network_access_enabled")
}

_public_network_drift(finding) if {
	changed_paths_has_key(finding, "public_network_access")
}
