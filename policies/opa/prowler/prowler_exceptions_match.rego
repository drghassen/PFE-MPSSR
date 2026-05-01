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
