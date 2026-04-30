# ==============================================================================
# Shift-Right Drift - evaluate_drift (core decision per finding)
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

evaluate_drift(finding) := decision if {
	_has_required_fields(finding)

	severity := determine_severity(finding)
	base_response := determine_action(severity, finding)
	candidate_policy := get_custodian_policy(finding)
	runtime_requested := base_response == "runtime_remediation"
	runtime_supported := _runtime_supported(base_response, candidate_policy)
	response_type := _response_type(base_response, runtime_supported)
	correlation_id := _resolve_correlation_id(finding)
	requires_remediation := _requires_remediation(response_type)
	manual_review_required := _manual_review_required(response_type, severity)

	decision := {
		"resource_id": object.get(finding, "address", "UNKNOWN"),
		"resource_type": object.get(finding, "type", "UNKNOWN"),
		"provider": object.get(finding, "provider_name", "UNKNOWN"),
		"severity": severity,
		"reason": build_reason(severity, finding),
		"action_required": response_type,
		"response_type": response_type,
		"manual_review_required": manual_review_required,
		"requires_remediation": requires_remediation,
		"changed_paths": object.get(finding, "changed_paths", []),
		"custodian_policy": _custodian_policy_for_response(response_type, candidate_policy),
		"capability_supported": _capability_supported(runtime_requested, runtime_supported),
		"verification_script": _verification_script_for_response(response_type, candidate_policy),
		"capability_key": candidate_policy,
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

_response_type(base_response, runtime_supported) := "runtime_remediation" if {
	base_response == "runtime_remediation"
	runtime_supported
} else := "manual_review" if {
	base_response == "runtime_remediation"
	not runtime_supported
} else := base_response

_capability_supported(runtime_requested, runtime_supported) := true if {
	not runtime_requested
} else := runtime_supported

_runtime_supported(base_response, candidate_policy) := true if {
	base_response == "runtime_remediation"
	policy_remediation_supported(candidate_policy)
} else := false

_custodian_policy_for_response(response_type, candidate_policy) := candidate_policy if {
	response_type == "runtime_remediation"
} else := null

_verification_script_for_response(response_type, candidate_policy) := script if {
	response_type == "runtime_remediation"
	script := policy_verification_script(candidate_policy)
} else := ""

_manual_review_required(response_type, severity) := true if {
	response_type == "manual_review"
} else if {
	severity == "UNKNOWN"
} else := false

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
	"manual_review_required": true,
	"requires_remediation": false,
	"custodian_policy": null,
	"capability_supported": false,
	"verification_script": "",
	"capability_key": "",
	"correlation_id": _resolve_correlation_id(finding),
	"changed_paths": object.get(finding, "changed_paths", []),
	"reason": "Finding with missing mandatory fields - requires manual review",
	"original_actions": object.get(finding, "actions", []),
}
