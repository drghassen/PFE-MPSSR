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

# ── Sensor identity guard ─────────────────────────────────────────────────────
# Reject any input that does not originate from the Prowler sensor.
# Drift findings sent to this OPA (by misconfiguration or injection) would
# silently fall through _malformed_finding_decision() as L1/manual_review —
# a fail-open that must be caught here before evaluation begins.

deny contains msg if {
	src := object.get(input, "source", "")
	src != "prowler"
	msg := sprintf("sensor_mismatch: expected source 'prowler', got '%v'", [src])
}

deny contains msg if {
	scan := object.get(input, "scan_type", "")
	scan != "shift-right-prowler"
	msg := sprintf("sensor_mismatch: expected scan_type 'shift-right-prowler', got '%v'", [scan])
}

# ─────────────────────────────────────────────────────────────────────────────

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

