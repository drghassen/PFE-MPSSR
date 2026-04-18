# ==============================================================================
# Shift-Right Drift — deny rules (degraded mode, input, exceptions hygiene)
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ==============================================================================
# DEGRADED MODE & STRICT INPUT VALIDATION (ZERO TRUST)
# ==============================================================================

is_degraded if {
	object.get(input, "meta", {}).mode == "DEGRADED"
}

deny contains msg if {
	is_degraded
	not object.get(object.get(input, "meta", {}), "allow_degraded", false)
	msg := {
		"code": "DEGRADED_MODE",
		"message": "Decision blocked: degraded mode"
	}
}

deny contains msg if {
	not object.get(input, "environment", "")
	msg := "Missing environment in input"
}

deny contains msg if {
	not object.get(input, "repo", "")
	msg := "Missing repo in input"
}

deny contains msg if {
	not object.get(input, "branch", "")
	msg := "Missing branch in input"
}

deny contains msg if {
	some ex in object.get(_drift_exceptions_store, "exceptions", [])
	not ex.repos
	not ex.branches
	not object.get(object.get(input, "meta", {}), "allow_legacy_exceptions", false)
	msg := "Unscoped exception detected"
}

deny contains msg if {
	some ex in object.get(_drift_exceptions_store, "exceptions", [])
	ex.expires_at
	time.now_ns() > time.parse_rfc3339_ns(ex.expires_at)
	msg := "Expired exception"
}
