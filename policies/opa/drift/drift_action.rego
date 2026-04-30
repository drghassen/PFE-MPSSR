# ==============================================================================
# Shift-Right Drift — action per severity
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ==============================================================================
# Action routing semantics
# ------------------------------------------------------------------------------
# Shift-Right routes findings to neutral decision categories:
# - CRITICAL -> runtime_remediation
# - HIGH     -> ticket_and_notify
# - MEDIUM   -> ticket_and_notify
# - LOW      -> notify
# - INFO     -> none
#
# Cloud Custodian remediation execution is Phase 2; routing is implemented now.
# ==============================================================================

determine_action(severity, _finding) := "runtime_remediation" if {
	severity == "CRITICAL"
} else := "ticket_and_notify" if {
	severity == "HIGH"
} else := "ticket_and_notify" if {
	severity == "MEDIUM"
} else := "notify" if {
	severity == "LOW"
} else := "manual_review" if {
	severity == "UNKNOWN"
} else := "none"
