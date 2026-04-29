# ==============================================================================
# CloudSentinel — Shift-Right Prowler Policy (context & defaults)
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

default violations := []
default compliant := []

correlation_id := id if {
	id := object.get(input, "correlation_id", "")
	trim(id, " \t\r\n") != ""
} else := "unknown"
