# ==============================================================================
# Shift-Right Prowler - evaluate_prowler_finding (core decision per finding)
# ============================================================================== 

package cloudsentinel.shiftright.prowler

import rego.v1

evaluate_prowler_finding(finding) := decision if {
	_has_required_fields(finding)

	check_id := object.get(finding, "check_id", "UNKNOWN")
	severity := normalize_severity(object.get(finding, "severity", "LOW"))
	base_response := determine_action(severity)
	correlation_id := _resolve_correlation_id(finding)
	cap_supported := check_remediation_supported(check_id)
	candidate_policy := check_custodian_policy(check_id)
	runtime_supported := _runtime_supported(base_response, cap_supported, candidate_policy)
	response_type := _response_type(base_response, runtime_supported)

	decision := {
		"check_id": check_id,
		"resource_id": object.get(finding, "resource_id", "UNKNOWN"),
		"resource_type": object.get(finding, "resource_type", "unknown"),
		"provider": object.get(finding, "provider", "azure"),
		"region": object.get(finding, "region", "global"),
		"severity": severity,
		"reason": object.get(finding, "status_detail", "Prowler finding"),
		"action_required": response_type,
		"response_type": response_type,
		"manual_review_required": response_type == "manual_review",
		"requires_remediation": response_type == "runtime_remediation",
		"capability_supported": _capability_supported(base_response, runtime_supported),
		"custodian_policy": _custodian_policy_for_response(response_type, candidate_policy),
		"verification_script": _verification_script_for_response(response_type, check_id),
		"status_code": object.get(finding, "status_code", "FAIL"),
		"title": object.get(finding, "title", "Prowler finding"),
		"correlation_id": correlation_id,
	}
} else := {
	"check_id": object.get(finding, "check_id", "UNKNOWN"),
	"resource_id": object.get(finding, "resource_id", "UNKNOWN"),
	"resource_type": object.get(finding, "resource_type", "unknown"),
	"provider": object.get(finding, "provider", "azure"),
	"region": object.get(finding, "region", "global"),
	"severity": "LOW",
	"reason": "Finding with missing mandatory fields - requires manual review",
	"action_required": "manual_review",
	"response_type": "manual_review",
	"manual_review_required": true,
	"requires_remediation": false,
	"capability_supported": false,
	"custodian_policy": null,
	"verification_script": "",
	"status_code": object.get(finding, "status_code", "FAIL"),
	"title": object.get(finding, "title", "Prowler finding"),
	"correlation_id": _resolve_correlation_id(finding),
}

_has_required_fields(finding) if {
	object.get(finding, "check_id", "") != ""
	object.get(finding, "resource_id", "") != ""
}

_response_type(base_response, runtime_supported) := "runtime_remediation" if {
	base_response == "runtime_remediation"
	runtime_supported
} else := "manual_review" if {
	base_response == "runtime_remediation"
	not runtime_supported
} else := base_response

_capability_supported(base_response, runtime_supported) := true if {
	base_response != "runtime_remediation"
} else := runtime_supported

_runtime_supported(base_response, cap_supported, candidate_policy) := true if {
	base_response == "runtime_remediation"
	cap_supported
	candidate_policy != null
} else := false

_custodian_policy_for_response(response_type, candidate_policy) := candidate_policy if {
	response_type == "runtime_remediation"
} else := null

_verification_script_for_response(response_type, check_id) := script if {
	response_type == "runtime_remediation"
	script := check_verification_script(check_id)
} else := ""

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
