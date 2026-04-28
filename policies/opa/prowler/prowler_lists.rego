# ==============================================================================
# Shift-Right Prowler — violations / compliant lists
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

violations := [decision |
	finding := input.findings[_]
	decision := evaluate_prowler_finding(finding)
	decision.severity != "INFO"
]

compliant := [info |
	finding := input.findings[_]
	decision := evaluate_prowler_finding(finding)
	decision.severity == "INFO"
	info := {
		"resource_id": object.get(finding, "resource_id", "UNKNOWN"),
		"status": "COMPLIANT",
	}
]
