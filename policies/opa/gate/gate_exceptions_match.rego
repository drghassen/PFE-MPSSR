package cloudsentinel.gate

import rego.v1

# Exception matching, effective findings, metrics, scanner gate (module 6/8)

candidate_exceptions_for_finding(f) := [ex |
	ex := active_valid_enabled_exceptions[_]
	exception_tool(ex) == finding_tool(f)
]

exception_matches_finding(ex, f) if {
	exception_tool(ex) == finding_tool(f)
	exception_rule(ex) == finding_rule_id(f)
	exception_resource(ex) == lower(trim_space(finding_resource_id(f)))
	exception_occurrence_file(ex) == lower(trim_space(finding_occurrence_file(f)))
	exception_occurrence_line(ex) == finding_occurrence_line(f)
	exception_scope_matches_repo(ex)
	exception_scope_matches_env(ex)
	exception_scope_matches_branch(ex)
}

applied_exception_ids[ex_id] if {
	f := failed_findings[_]
	ex := candidate_exceptions_for_finding(f)[_]
	exception_matches_finding(ex, f)
	ex_id := exception_id(ex)
}

applied_exception_audit[item] if {
	f := failed_findings[_]
	ex := candidate_exceptions_for_finding(f)[_]
	exception_matches_finding(ex, f)
	item := {
		"exception_id": exception_id(ex),
		"scope_type": "strict_tool_rule_resource",
		"commit_sha": trim_space(object.get(git_meta, "commit", "")),
		"rule_id": exception_rule(ex),
		"matching_method": "tool_rule_resource_exact",
		"break_glass": false,
	}
}

_resource_mismatch(ex, f) if {
	exception_resource(ex) != lower(trim_space(finding_resource_id(f)))
}

_occurrence_mismatch(ex, f) if {
	exception_occurrence_file(ex) != lower(trim_space(finding_occurrence_file(f)))
}

_occurrence_mismatch(ex, f) if {
	exception_occurrence_line(ex) != finding_occurrence_line(f)
}

_repo_mismatch(ex) if {
	not exception_scope_matches_repo(ex)
}

_env_mismatch(ex) if {
	not exception_scope_matches_env(ex)
}

_branch_mismatch(ex) if {
	not exception_scope_matches_branch(ex)
}

partial_mismatch_reasons(ex, f) := array.concat(
	array.concat(
		array.concat(
			[m | _resource_mismatch(ex, f); m := sprintf("Resource path mismatch: exception='%s' finding='%s'", [exception_resource(ex), lower(trim_space(finding_resource_id(f)))])],
			[m | _occurrence_mismatch(ex, f); m := sprintf("Occurrence mismatch: exception='%s:%v' finding='%s:%v'", [exception_occurrence_file(ex), exception_occurrence_line(ex), lower(trim_space(finding_occurrence_file(f))), finding_occurrence_line(f)])],
		),
		[m | _repo_mismatch(ex); m := sprintf("Scope repo mismatch: expected one of %v, got '%s'", [object.get(object.get(ex, "scope", {}), "repos", []), lower(trim_space(object.get(git_meta, "repo", "")))])],
	),
	array.concat(
		[m | _env_mismatch(ex); m := sprintf("Scope environment mismatch: expected one of %v, got '%s'", [object.get(object.get(ex, "scope", {}), "environments", []), environment])],
		[m | _branch_mismatch(ex); m := sprintf("Scope branch mismatch: expected one of %v, got '%s'", [object.get(object.get(ex, "scope", {}), "branches", []), lower(trim_space(object.get(git_meta, "branch", "")))])],
	),
)

partial_matches_audit[item] if {
	f := failed_findings[_]
	ex := active_valid_enabled_exceptions[_]
	exception_tool(ex) == finding_tool(f)
	exception_rule(ex) == finding_rule_id(f)
	not exception_matches_finding(ex, f)

	item := {
		"exception_id": exception_id(ex),
		"rule_id": exception_rule(ex),
		"mismatch_reasons": partial_mismatch_reasons(ex, f),
		"expected_exception_resource": exception_resource(ex),
		"actual_finding_resource": finding_resource_id(f),
	}
}

is_excepted_finding(f) if {
	ex := candidate_exceptions_for_finding(f)[_]
	exception_matches_finding(ex, f)
}

effective_failed_findings := [f |
	f := failed_findings[_]
	not is_excepted_finding(f)
]

excepted_failed_findings := [f |
	f := failed_findings[_]
	is_excepted_finding(f)
]

effective_critical := count([f |
	f := effective_failed_findings[_]
	finding_severity_level(f) == "CRITICAL"
])

effective_high := count([f |
	f := effective_failed_findings[_]
	finding_severity_level(f) == "HIGH"
])

effective_medium := count([f |
	f := effective_failed_findings[_]
	finding_severity_level(f) == "MEDIUM"
])

effective_low := count([f |
	f := effective_failed_findings[_]
	finding_severity_level(f) == "LOW"
])

active_exceptions := [ex |
	ex := active_valid_enabled_exceptions[_]
]

active_exceptions_critical := count([ex |
	ex := active_exceptions[_]
	exception_severity(ex) == "CRITICAL"
])

active_exceptions_high := count([ex |
	ex := active_exceptions[_]
	exception_severity(ex) == "HIGH"
])

active_exceptions_medium := count([ex |
	ex := active_exceptions[_]
	exception_severity(ex) == "MEDIUM"
])

active_exceptions_low := count([ex |
	ex := active_exceptions[_]
	exception_severity(ex) == "LOW"
])

avg_approval_time_hours := 0
active_break_glass_count := 0

prod_critical_exception_violation[ex_id] if {
	environment == "prod"
	ex := active_valid_enabled_exceptions[_]
	exception_severity(ex) == "CRITICAL"
	ex_id := exception_id(ex)
}

scanner_not_run[name] if {
	not is_local
	name := required_scanners[_]
	scanner := object.get(scanners, name, {})
	object.get(scanner, "status", "NOT_RUN") == "NOT_RUN"
}
