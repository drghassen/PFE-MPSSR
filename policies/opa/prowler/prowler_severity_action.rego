# ==============================================================================
# Shift-Right Prowler — severity normalization and action mapping
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

normalize_severity(value) := "CRITICAL" if {
	upper(value) == "CRITICAL"
} else := "HIGH" if {
	upper(value) == "HIGH"
} else := "MEDIUM" if {
	upper(value) == "MEDIUM"
} else := "LOW" if {
	upper(value) == "LOW"
} else := "INFO" if {
	upper(value) == "INFO"
} else := "LOW"

# Runtime posture routing semantics:
# - CRITICAL -> emergency_alert
# - HIGH     -> alert_and_ticket
# - MEDIUM   -> auto_remediate
# - LOW      -> auto_remediate
# - INFO     -> none
determine_action(severity) := "emergency_alert" if {
	severity == "CRITICAL"
} else := "alert_and_ticket" if {
	severity == "HIGH"
} else := "auto_remediate" if {
	severity == "MEDIUM"
} else := "auto_remediate" if {
	severity == "LOW"
} else := "none"
