package cloudsentinel.gate

import rego.v1

# Exception validation rules and ID sets (module 5/8)

valid_exception_definition(ex) if {
	exception_id(ex) != ""
	regex.match("^[a-f0-9]{64}$", exception_id(ex))
	allowed_tools[exception_tool(ex)]
	exception_rule(ex) != ""
	exception_resource(ex) != ""
	exception_occurrence_file(ex) != ""
	exception_occurrence_line(ex) >= 0
	exception_occurrence_hash_valid(ex)
	not exception_has_wildcard(ex)
	severity_rank[exception_severity(ex)] >= 1
	exception_requested_by(ex) != ""
	exception_approved_by(ex) != ""
	exception_requested_by(ex) != exception_approved_by(ex)
	allowed_decisions[exception_decision(ex)]
	exception_source(ex) == "defectdojo"
	exception_status(ex) == "approved"
	exception_timestamp_fields_parse(ex)
	approved_ns := time.parse_rfc3339_ns(exception_approved_at(ex))
	expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
	approved_ns <= time.now_ns()
	approved_ns < expires_ns
	not exception_is_expired(ex)
}

exception_status_not_approved_ids[ex_id] if {
	ex := exceptions_store[_]
	exception_status(ex) != "approved"
	ex_id := exception_id(ex)
}

exception_missing_approved_by_ids[ex_id] if {
	ex := exceptions_store[_]
	exception_approved_by(ex) == ""
	ex_id := exception_id(ex)
}

exception_missing_approved_at_ids[ex_id] if {
	ex := exceptions_store[_]
	exception_approved_at(ex) == ""
	ex_id := exception_id(ex)
}

invalid_enabled_exception_ids[ex_id] if {
	ex := exceptions_store[_]
	ex_id := exception_id(ex)
	ex_id != ""
	not valid_exception_definition(ex)
	not exception_is_expired(ex)
}

expired_enabled_exception_ids[ex_id] if {
	ex := exceptions_store[_]
	ex_id := exception_id(ex)
	ex_id != ""
	exception_is_expired(ex)
}

legacy_exception_after_sunset[ex_id] if {
	ex_id := ""
	false
}

active_valid_enabled_exceptions := [ex |
	ex := exceptions_store[_]
	valid_exception_definition(ex)
]
