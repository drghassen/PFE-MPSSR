# ==============================================================================
# Shift-Right Drift — action per severity
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ==============================================================================
# Détermination de l'Action (else-if chain)
# ==============================================================================

determine_action(severity, finding) := "immediate_review" if {
	severity == "CRITICAL"
} else := "auto_remediate" if {
	severity == "HIGH"
	object.get(finding, "type", "") == "azurerm_storage_account"
} else := "schedule_review" if {
	severity == "HIGH"
} else := "schedule_review" if {
	severity == "MEDIUM"
} else := "monitor" if {
	severity == "LOW"
} else := "none"
