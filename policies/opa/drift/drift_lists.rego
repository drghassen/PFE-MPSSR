# ==============================================================================
# Shift-Right Drift — violations / compliant entry lists
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ==============================================================================
# Entry Points
# ==============================================================================

violations := [decision |
	finding := input.findings[_]
	decision := evaluate_drift(finding)
	decision.severity != "INFO"
]

compliant := [info |
	finding := input.findings[_]
	decision := evaluate_drift(finding)
	decision.severity == "INFO"
	info := {
		"resource_id": object.get(finding, "address", "UNKNOWN"),
		"status": "COMPLIANT",
		"correlation_id": decision.correlation_id,
	}
]
