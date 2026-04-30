# ==============================================================================
# Shift-Right Drift — human-readable reason strings
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# FIX: P1.4 — json.marshal() pour les arrays (propre vs %v Go-style)
# + object.get() pour null-safety sur finding.type
build_reason(severity, finding) := sprintf("%s drift on %s: %s", [
	severity,
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "CRITICAL"
} else := sprintf("High-severity drift on %s requiring remediation: %s", [
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "HIGH"
} else := sprintf("Configuration drift on %s: %s", [
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "MEDIUM"
} else := sprintf("Low-impact drift on %s: %s", [
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "LOW"
} else := sprintf("Unknown drift classification on %s requires manual review: %s", [
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "UNKNOWN"
} else := "Drift within acceptable bounds"
