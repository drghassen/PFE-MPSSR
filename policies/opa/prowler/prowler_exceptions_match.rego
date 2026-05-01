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
