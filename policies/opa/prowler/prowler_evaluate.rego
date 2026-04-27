# ==============================================================================
# Shift-Right Prowler — evaluate_finding (per-finding severity and action)
#
# Maps each DefectDojo Generic Findings record produced by run-prowler.sh into
# a normalized violation object consumed by prowler_decision.rego.
# Mirrors the evaluate_drift() pattern from policies/opa/drift/.
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

# Normalize DefectDojo/Prowler severity strings to CloudSentinel standard.
normalize_severity(s) := mapped if {
	m := {
		"critical": "CRITICAL",
		"high":     "HIGH",
		"medium":   "MEDIUM",
		"low":      "LOW",
		"info":     "INFO",
	}
	mapped := m[lower(s)]
} else := "MEDIUM"

# Action per severity — mirrors drift_action.rego ladder.
determine_action(severity) := action if {
	m := {
		"CRITICAL": "immediate_review",
		"HIGH":     "schedule_review",
		"MEDIUM":   "schedule_review",
		"LOW":      "monitor",
		"INFO":     "none",
	}
	action := object.get(m, severity, "monitor")
}

# Transform one Generic Findings record into a normalized violation object.
evaluate_finding(f) := v if {
	severity := normalize_severity(object.get(f, "severity", "medium"))
	v := {
		"unique_id":        object.get(f, "unique_id_from_tool", "unknown"),
		"check_id":         object.get(f, "vuln_id_from_tool", "unknown"),
		"resource":         object.get(f, "component_name", "unknown"),
		"title":            object.get(f, "title", ""),
		"severity":         severity,
		"action_required":  determine_action(severity),
	}
}
