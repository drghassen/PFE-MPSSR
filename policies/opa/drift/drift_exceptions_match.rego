# ==============================================================================
# Shift-Right Drift — exception matching, effective violations, metrics
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ── Extraction des IDs compatibles (v2/legacy) ──
get_resource_type(ex) := t if {
	t := object.get(ex, ["resource", "type"], "")
	t != ""
} else := t if {
	t := ex.resource_type
}

get_resource_id(ex) := id if {
	id := object.get(ex, ["resource", "address"], "")
	id != ""
} else := id if {
	id := ex.resource_id
}

# ── Matching exception ↔ violation ──
_drift_exception_matches(ex, v) if {
	get_resource_type(ex) == v.resource_type
	get_resource_id(ex) == v.resource_id
}

# ── Prédicat : la violation est-elle couverte par une exception valide ? ──
_is_excepted_violation(v) if {
	some ex in _drift_exceptions_list
	valid_drift_exception(ex)
	_drift_exception_matches(ex, v)
}

# ── Partial match diagnostics — mirrors shift-left gate_exceptions_match.rego ──
# Surfaces near-miss exceptions (same resource_type, wrong resource_id) so that
# operators can diagnose stale exceptions after resource rename/move.
_drift_resource_type_mismatch(ex, v) if {
	get_resource_type(ex) != v.resource_type
}

_drift_resource_id_mismatch(ex, v) if {
	get_resource_id(ex) != v.resource_id
}

drift_partial_mismatch_reasons(ex, v) := reasons if {
	reasons := array.concat(
		[m | _drift_resource_type_mismatch(ex, v); m := sprintf("resource_type mismatch: exception='%s' violation='%s'", [get_resource_type(ex), v.resource_type])],
		[m | _drift_resource_id_mismatch(ex, v); m := sprintf("resource_id mismatch: exception='%s' violation='%s'", [get_resource_id(ex), v.resource_id])],
	)
}

# Near-miss audit: valid exceptions that share resource_type with a violation but do not match fully.
drift_partial_matches_audit[item] if {
	some v in violations
	some ex in active_valid_drift_exceptions
	get_resource_type(ex) == v.resource_type
	not _drift_exception_matches(ex, v)
	item := {
		"exception_id": _drift_exception_id(ex),
		"violation_resource_id": v.resource_id,
		"mismatch_reasons": drift_partial_mismatch_reasons(ex, v),
	}
}

# ── Violations effectives = violations brutes moins les exceptées ──
# Exposé séparément pour ne pas casser le contrat violations[] existant.
effective_violations := [v |
	some v in violations
	not _is_excepted_violation(v)
]

excepted_violations := [v |
	some v in violations
	_is_excepted_violation(v)
]

# ── Métriques d'exceptions pour audit et traçabilité ──
drift_exception_summary := {
	"total_exceptions_loaded": count(_drift_exceptions_list),
	"valid_exceptions": count([ex |
		some ex in _drift_exceptions_list
		valid_drift_exception(ex)
	]),
	"expired_exceptions": count([ex |
		some ex in _drift_exceptions_list
		_drift_exception_is_expired(ex)
	]),
	"excepted_violations": count(excepted_violations),
}

l0_count := count([v |
	some v in effective_violations
	v.remediation_level == "L0"
])

l1_count := count([v |
	some v in effective_violations
	v.remediation_level == "L1"
])

l2_count := count([v |
	some v in effective_violations
	v.remediation_level == "L2"
])

l3_count := count([v |
	some v in effective_violations
	v.remediation_level == "L3"
])

block_reason := "deny" if {
	count(deny) > 0
} else := "auto_remediation_required" if {
	count(deny) == 0
	l3_count > 0
} else := "ticket_and_notify_required" if {
	count(deny) == 0
	l3_count == 0
	l2_count > 0
} else := "manual_review_only" if {
	count(deny) == 0
	l2_count == 0
	l3_count == 0
	count([v |
		some v in effective_violations
		object.get(v, "manual_review_required", false)
	]) > 0
} else := "none"
