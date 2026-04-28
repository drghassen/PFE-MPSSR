# ==============================================================================
# Shift-Right Prowler — deny rules (degraded mode, strict input, exceptions)
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

is_degraded if {
	object.get(input, "meta", {}).mode == "DEGRADED"
}

missing_or_blank(field) if {
	object.get(input, field, null) == null
}

missing_or_blank(field) if {
	val := object.get(input, field, "")
	is_string(val)
	trim(val, " \t\r\n") == ""
}

deny contains msg if {
	is_degraded
	not object.get(object.get(input, "meta", {}), "allow_degraded", false)
	msg := {
		"code": "DEGRADED_MODE",
		"message": "Decision blocked: degraded mode",
	}
}

deny contains msg if {
	missing_or_blank("environment")
	msg := "Missing environment in input"
}

deny contains msg if {
	missing_or_blank("repo")
	msg := "Missing repo in input"
}

deny contains msg if {
	missing_or_blank("branch")
	msg := "Missing branch in input"
}

deny contains msg if {
	some ex in object.get(_prowler_exceptions_store, "exceptions", [])
	not ex.repos
	not ex.branches
	not object.get(object.get(input, "meta", {}), "allow_legacy_exceptions", false)
	msg := "Unscoped exception detected"
}

deny contains msg if {
	some ex in object.get(_prowler_exceptions_store, "exceptions", [])
	ex.expires_at
	time.now_ns() > time.parse_rfc3339_ns(ex.expires_at)
	msg := "Expired exception"
}
