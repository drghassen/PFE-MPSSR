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
	some ex in object.get(_drift_exceptions_store, "exceptions", [])
	valid_drift_exception(ex)
	_drift_exception_matches(ex, v)
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
	"total_exceptions_loaded": count(object.get(_drift_exceptions_store, "exceptions", [])),
	"valid_exceptions": count([ex |
		some ex in object.get(_drift_exceptions_store, "exceptions", [])
		valid_drift_exception(ex)
	]),
	"expired_exceptions": count([ex |
		some ex in object.get(_drift_exceptions_store, "exceptions", [])
		_is_expired(ex)
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
