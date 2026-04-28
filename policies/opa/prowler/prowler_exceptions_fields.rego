# ==============================================================================
# Shift-Right Prowler — exception validation
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

_prowler_exception_has_wildcard(ex) if {
	contains(object.get(ex, "check_id", ""), "*")
}

_prowler_exception_has_wildcard(ex) if {
	contains(object.get(ex, "check_id", ""), "?")
}

_prowler_exception_has_wildcard(ex) if {
	contains(object.get(ex, "resource_id", ""), "*")
}

_prowler_exception_has_wildcard(ex) if {
	contains(object.get(ex, "resource_id", ""), "?")
}

valid_env_scope(ex) if {
	envs := object.get(ex, "environments", [])
	count(envs) > 0
	input.environment in envs
}

valid_repo_scope(ex) if {
	not ex.repos
}

valid_repo_scope(ex) if {
	count(ex.repos) == 0
}

valid_repo_scope(ex) if {
	input.repo in ex.repos
}

valid_branch_scope(ex) if {
	not ex.branches
}

valid_branch_scope(ex) if {
	count(ex.branches) == 0
}

valid_branch_scope(ex) if {
	input.branch in ex.branches
}

valid_prowler_exception(ex) if {
	ex.source == "defectdojo"
	ex.status == "approved"
	ex.requested_by != ""
	ex.approved_by != ""
	ex.requested_by != ex.approved_by
	ex.check_id != ""
	ex.resource_id != ""
	time.parse_rfc3339_ns(ex.approved_at) <= time.now_ns()
	not _is_expired(ex)
	valid_env_scope(ex)
	valid_repo_scope(ex)
	valid_branch_scope(ex)
	not _prowler_exception_has_wildcard(ex)
}

_is_expired(ex) if {
	ex.expires_at
	time.now_ns() >= time.parse_rfc3339_ns(ex.expires_at)
}
