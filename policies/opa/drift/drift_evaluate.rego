# ==============================================================================
# Shift-Right Drift - evaluate_drift (core decision per finding)
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

evaluate_drift(finding) := decision if {
	_has_required_fields(finding)

	severity := determine_severity(finding)
	response_type := determine_action(severity, finding)
	correlation_id := _resolve_correlation_id(finding)
	requires_remediation := _requires_remediation(response_type)

	decision := {
		"resource_id": object.get(finding, "address", "UNKNOWN"),
		"resource_type": object.get(finding, "type", "UNKNOWN"),
		"provider": object.get(finding, "provider_name", "UNKNOWN"),
		"severity": severity,
		"reason": build_reason(severity, finding),
		"action_required": response_type,
		"response_type": response_type,
		"requires_remediation": requires_remediation,
		"changed_paths": object.get(finding, "changed_paths", []),
		"custodian_policy": _custodian_policy_for_response(response_type, finding),
		"correlation_id": correlation_id,
		"original_actions": object.get(finding, "actions", []),
	}
} else := decision if {
	decision := _malformed_finding_decision(finding)
}

_has_required_fields(finding) if {
	object.get(finding, "address", "") != ""
	object.get(finding, "type", "") != ""
	object.get(finding, "provider_name", "") != ""
}

_requires_remediation(response_type) := true if {
	response_type == "runtime_remediation"
} else := false

_custodian_policy_for_response(response_type, finding) := policy if {
	response_type == "runtime_remediation"
	policy := get_custodian_policy(finding)
} else := null

_resolve_correlation_id(finding) := cid if {
	cid := object.get(finding, "correlation_id", "")
	is_string(cid)
	cid != ""
} else := cid if {
	cid := _input_correlation_id
	is_string(cid)
	cid != ""
} else := "unknown"

_input_correlation_id := cid if {
	is_object(input)
	cid := object.get(input, "correlation_id", "")
} else := ""

_malformed_finding_decision(finding) := {
	"resource_id": object.get(finding, "address", "UNKNOWN"),
	"resource_type": object.get(finding, "type", "UNKNOWN"),
	"provider": object.get(finding, "provider_name", "UNKNOWN"),
	"severity": "LOW",
	"action_required": "manual_review",
	"response_type": "manual_review",
	"requires_remediation": false,
	"custodian_policy": null,
	"correlation_id": _resolve_correlation_id(finding),
	"changed_paths": object.get(finding, "changed_paths", []),
	"reason": "Finding with missing mandatory fields - requires manual review",
	"original_actions": object.get(finding, "actions", []),
}
