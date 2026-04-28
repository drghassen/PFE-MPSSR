# ==============================================================================
# Shift-Right Prowler — evaluate_prowler_finding (core decision per finding)
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

evaluate_prowler_finding(finding) := decision if {
	finding.check_id
	finding.resource_id

	severity := normalize_severity(object.get(finding, "severity", "LOW"))
	action := determine_action(severity)

	decision := {
		"check_id": finding.check_id,
		"resource_id": finding.resource_id,
		"resource_type": object.get(finding, "resource_type", "unknown"),
		"provider": object.get(finding, "provider", "azure"),
		"region": object.get(finding, "region", "global"),
		"severity": severity,
		"reason": object.get(finding, "status_detail", "Prowler finding"),
		"action_required": action,
		"status_code": object.get(finding, "status_code", "FAIL"),
		"title": object.get(finding, "title", "Prowler finding"),
	}
}

evaluate_prowler_finding(finding) := {
	"check_id": object.get(finding, "check_id", "UNKNOWN"),
	"resource_id": object.get(finding, "resource_id", "UNKNOWN"),
	"resource_type": object.get(finding, "resource_type", "unknown"),
	"provider": object.get(finding, "provider", "azure"),
	"region": object.get(finding, "region", "global"),
	"severity": "LOW",
	"reason": "Finding with missing mandatory fields — requires manual review",
	"action_required": "manual_review",
	"status_code": object.get(finding, "status_code", "FAIL"),
	"title": object.get(finding, "title", "Prowler finding"),
} if {
	not finding.check_id
}

evaluate_prowler_finding(finding) := {
	"check_id": object.get(finding, "check_id", "UNKNOWN"),
	"resource_id": object.get(finding, "resource_id", "UNKNOWN"),
	"resource_type": object.get(finding, "resource_type", "unknown"),
	"provider": object.get(finding, "provider", "azure"),
	"region": object.get(finding, "region", "global"),
	"severity": "LOW",
	"reason": "Finding with missing mandatory fields — requires manual review",
	"action_required": "manual_review",
	"status_code": object.get(finding, "status_code", "FAIL"),
	"title": object.get(finding, "title", "Prowler finding"),
} if {
	finding.check_id
	not finding.resource_id
}
