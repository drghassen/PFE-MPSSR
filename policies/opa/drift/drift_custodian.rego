# ==============================================================================
# Shift-Right Drift - Cloud Custodian policy mapping
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# Custodian mappings are intentionally restricted to CRITICAL drift categories.
# Non-critical findings are handled by notification and DefectDojo, then Terraform fix.
get_custodian_policy(finding) := "enforce-nsg-no-open-inbound" if {
	object.get(finding, "type", "") == "azurerm_network_security_group"
	"security_rule" in object.get(finding, "changed_paths", [])
} else := "enforce-nsg-rule-deny-all" if {
	object.get(finding, "type", "") == "azurerm_network_security_rule"
	"access" in object.get(finding, "changed_paths", [])
} else := "enforce-vm-no-password-auth" if {
	object.get(finding, "type", "") == "azurerm_linux_virtual_machine"
	"admin_password" in object.get(finding, "changed_paths", [])
} else := "enforce-sql-password-rotation" if {
	object.get(finding, "type", "") == "azurerm_sql_server"
	"administrator_login_password" in object.get(finding, "changed_paths", [])
} else := null
