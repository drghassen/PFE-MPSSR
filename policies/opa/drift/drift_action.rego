# ==============================================================================
# Shift-Right Drift — action per severity
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ==============================================================================
# Action routing semantics (Phase 1)
# ------------------------------------------------------------------------------
# Shift-Right must route findings to operational outcomes, not only allow/deny:
# - CRITICAL                            -> emergency_alert
# - HIGH + azurerm_storage_account      -> auto_remediate_with_alert
# - HIGH (other resource types)         -> alert_and_ticket
# - MEDIUM / LOW                        -> auto_remediate
# - INFO                                -> none
#
# Cloud Custodian remediation execution is Phase 2; routing is implemented now.
# ==============================================================================

determine_action(severity, finding) := "emergency_alert" if {
	severity == "CRITICAL"
} else := "auto_remediate_with_alert" if {
	severity == "HIGH"
	object.get(finding, "type", "") == "azurerm_storage_account"
} else := "alert_and_ticket" if {
	severity == "HIGH"
} else := "auto_remediate" if {
	severity == "MEDIUM"
} else := "auto_remediate" if {
	severity == "LOW"
} else := "none"
