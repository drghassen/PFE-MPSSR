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
# - CRITICAL -> runtime_remediation
# - HIGH     -> ticket_and_notify
# - MEDIUM   -> ticket_and_notify
# - LOW      -> notify
# - INFO     -> none
determine_action(severity) := "runtime_remediation" if {
	severity == "CRITICAL"
} else := "ticket_and_notify" if {
	severity == "HIGH"
} else := "ticket_and_notify" if {
	severity == "MEDIUM"
} else := "notify" if {
	severity == "LOW"
} else := "none"
