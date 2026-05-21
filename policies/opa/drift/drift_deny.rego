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

# ── Sensor identity guard ─────────────────────────────────────────────────────
# Reject any input that does not originate from the drift engine.
# Prowler findings sent to this OPA (by misconfiguration or injection) would
# silently fall through _malformed_finding_decision() as L1/manual_review —
# a fail-open that must be caught here before evaluation begins.

deny contains msg if {
	src := object.get(input, "source", "")
	src != "drift-engine"
	msg := sprintf("sensor_mismatch: expected source 'drift-engine', got '%v'", [src])
}

deny contains msg if {
	scan := object.get(input, "scan_type", "")
	scan != "shift-right-drift"
	msg := sprintf("sensor_mismatch: expected scan_type 'shift-right-drift', got '%v'", [scan])
}

# ─────────────────────────────────────────────────────────────────────────────

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
	some ex in _drift_exceptions_list
	not ex.repos
	not ex.branches
	not object.get(object.get(input, "meta", {}), "allow_legacy_exceptions", false)
	msg := "Unscoped exception detected"
}

# NOTE: expired exceptions are intentionally NOT a deny condition.
# An expired exception is a normal DefectDojo lifecycle artefact. It is already
# excluded from valid_drift_exception (via _is_expired) so it cannot suppress any
# violation. Blocking the pipeline on stale metadata would cause an indefinite
# false-positive gate. Expiry counts are surfaced in drift_exception_summary for
# governance observability without pipeline impact.
