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

# Enforcement strategy for runtime posture:
# - CRITICAL/HIGH are actionable and block in enforcement mode.
# - MEDIUM/LOW are monitor in this phase and do not block.
# - INFO is compliant/no-op.
determine_action(severity) := "immediate_review" if {
	severity == "CRITICAL"
} else := "schedule_review" if {
	severity == "HIGH"
} else := "monitor" if {
	severity == "MEDIUM"
} else := "monitor" if {
	severity == "LOW"
} else := "none"
