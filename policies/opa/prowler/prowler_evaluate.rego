# ==============================================================================
# Shift-Right Prowler - evaluate_prowler_finding (core decision per finding)
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

evaluate_prowler_finding(finding) := decision if {
	_has_required_fields(finding)

	severity := normalize_severity(object.get(finding, "severity", "LOW"))
	response_type := determine_action(severity)
	correlation_id := _resolve_correlation_id(finding)

	decision := {
		"check_id": object.get(finding, "check_id", "UNKNOWN"),
		"resource_id": object.get(finding, "resource_id", "UNKNOWN"),
		"resource_type": object.get(finding, "resource_type", "unknown"),
		"provider": object.get(finding, "provider", "azure"),
		"region": object.get(finding, "region", "global"),
		"severity": severity,
		"reason": object.get(finding, "status_detail", "Prowler finding"),
		"action_required": response_type,
		"response_type": response_type,
		"requires_remediation": response_type == "runtime_remediation",
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
	"requires_remediation": false,
	"status_code": object.get(finding, "status_code", "FAIL"),
	"title": object.get(finding, "title", "Prowler finding"),
	"correlation_id": _resolve_correlation_id(finding),
}

_has_required_fields(finding) if {
	object.get(finding, "check_id", "") != ""
	object.get(finding, "resource_id", "") != ""
}

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
