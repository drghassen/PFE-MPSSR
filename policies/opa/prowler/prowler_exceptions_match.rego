# ==============================================================================
# Shift-Right Prowler — exception matching and metrics
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

_prowler_exception_matches(ex, v) if {
	ex.check_id == v.check_id
	ex.resource_id == v.resource_id
	lower(ex.resource_type) == lower(v.resource_type)
}

_is_excepted_violation(v) if {
	some ex in object.get(_prowler_exceptions_store, "exceptions", [])
	valid_prowler_exception(ex)
	_prowler_exception_matches(ex, v)
}

# ── Partial match diagnostics — mirrors drift_exceptions_match.rego pattern ──
# Near-miss exceptions: same check_id, but resource_id or resource_type differs.
# Helps operators debug stale exceptions after resource rename.
_prowler_check_id_mismatch(ex, v) if {
	ex.check_id != v.check_id
}

_prowler_resource_id_mismatch(ex, v) if {
	ex.resource_id != v.resource_id
}

_prowler_resource_type_mismatch(ex, v) if {
	lower(ex.resource_type) != lower(v.resource_type)
}

prowler_partial_mismatch_reasons(ex, v) := array.concat(
	array.concat(
		[m | _prowler_check_id_mismatch(ex, v); m := sprintf("check_id mismatch: exception='%s' violation='%s'", [ex.check_id, v.check_id])],
		[m | _prowler_resource_id_mismatch(ex, v); m := sprintf("resource_id mismatch: exception='%s' violation='%s'", [ex.resource_id, v.resource_id])],
	),
	[m | _prowler_resource_type_mismatch(ex, v); m := sprintf("resource_type mismatch: exception='%s' violation='%s'", [ex.resource_type, v.resource_type])],
)

# Near-miss audit: valid exceptions that share check_id with a violation but do not fully match.
prowler_partial_matches_audit[item] if {
	some v in violations
	some ex in active_valid_prowler_exceptions
	ex.check_id == v.check_id
	not _prowler_exception_matches(ex, v)
	item := {
		"exception_id": _prowler_exception_id(ex),
		"violation_resource_id": v.resource_id,
		"mismatch_reasons": prowler_partial_mismatch_reasons(ex, v),
	}
}

effective_violations := [v |
	some v in violations
	not _is_excepted_violation(v)
]

excepted_violations := [v |
	some v in violations
	_is_excepted_violation(v)
]

prowler_exception_summary := {
	"total_exceptions_loaded": count(object.get(_prowler_exceptions_store, "exceptions", [])),
	"valid_exceptions": count([ex |
		some ex in object.get(_prowler_exceptions_store, "exceptions", [])
		valid_prowler_exception(ex)
	]),
	"expired_exceptions": count([ex |
		some ex in object.get(_prowler_exceptions_store, "exceptions", [])
		_prowler_exception_is_expired(ex)
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
