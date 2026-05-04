# ==============================================================================
# Shift-Right Prowler — exception validation
# Schema version: 2.0.0 — expires_at mandatory, approved_at < expires_at,
# diagnostic sets matching shift-left gate_exceptions_validate.rego pattern.
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

# ── Wildcard guard helpers ──

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

# ── Scope environment matching helpers ──
#
# SECURITY: unscoped exceptions (absent or empty environments list) are REJECTED.
# Every prowler exception MUST declare at least one target environment explicitly.

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

# ── Temporal helpers ──

_prowler_exception_expires_at(ex) := trim_space(object.get(ex, "expires_at", ""))

_prowler_exception_approved_at(ex) := trim_space(object.get(ex, "approved_at", ""))

_prowler_exception_is_expired(ex) if {
	_prowler_exception_expires_at(ex) != ""
	time.now_ns() >= time.parse_rfc3339_ns(_prowler_exception_expires_at(ex))
}

# ── Exception ID accessor ──
_prowler_exception_id(ex) := lower(trim_space(object.get(ex, "id", "")))

# ── Validation d'une exception prowler ──
# Criteria (12):
#   1. source == "defectdojo"
#   2. status == "approved"
#   3. requested_by non-empty
#   4. approved_by non-empty
#   5. four-eyes: requested_by != approved_by
#   6. check_id non-empty, no wildcards
#   7. resource_id non-empty, no wildcards
#   8. approved_at valid RFC3339, in the past
#   9. expires_at MANDATORY, valid RFC3339, in the future
#  10. approved_at < expires_at (temporal cross-validation)
#  11. environments non-empty, matches input.environment
#  12. repo/branch scope (optional — absent = matches all)

valid_prowler_exception(ex) if {
	# 1. Source verified
	ex.source == "defectdojo"
	# 2. Status approved
	ex.status == "approved"
	# 3-4. Identity fields non-empty
	ex.requested_by != ""
	ex.approved_by != ""
	# 5. Four-eyes principle
	ex.requested_by != ex.approved_by
	# 6. check_id non-empty
	ex.check_id != ""
	# 7. resource_id non-empty
	ex.resource_id != ""
	# 8. approved_at: valid RFC3339 in the past
	approved_ns := time.parse_rfc3339_ns(_prowler_exception_approved_at(ex))
	approved_ns <= time.now_ns()
	# 9. expires_at: MANDATORY — reject if absent or empty
	_prowler_exception_expires_at(ex) != ""
	expires_ns := time.parse_rfc3339_ns(_prowler_exception_expires_at(ex))
	# 9b. Not yet expired
	time.now_ns() < expires_ns
	# 10. approved_at strictly before expires_at
	approved_ns < expires_ns
	# 11. Environment scope strict
	valid_env_scope(ex)
	# 12. Repo/branch scope
	valid_repo_scope(ex)
	valid_branch_scope(ex)
	# No wildcards
	not _prowler_exception_has_wildcard(ex)
}

# ── Diagnostic sets (mirror gate_exceptions_validate.rego pattern) ──

# Exceptions that are enabled in the store but fail field validation (excluding expired).
invalid_enabled_prowler_exception_ids[ex_id] if {
	ex := _prowler_exceptions_store[_]
	ex_id := _prowler_exception_id(ex)
	ex_id != ""
	not valid_prowler_exception(ex)
	not _prowler_exception_is_expired(ex)
}

# Exceptions that are enabled in the store but have passed their expires_at.
expired_enabled_prowler_exception_ids[ex_id] if {
	ex := _prowler_exceptions_store[_]
	ex_id := _prowler_exception_id(ex)
	ex_id != ""
	_prowler_exception_is_expired(ex)
}

# Exceptions whose status field is not "approved".
exception_status_not_approved_prowler_ids[ex_id] if {
	ex := _prowler_exceptions_store[_]
	ex.status != "approved"
	ex_id := _prowler_exception_id(ex)
}

# Exceptions missing the approved_by field.
exception_missing_approved_by_prowler_ids[ex_id] if {
	ex := _prowler_exceptions_store[_]
	object.get(ex, "approved_by", "") == ""
	ex_id := _prowler_exception_id(ex)
}

# Exceptions missing or empty expires_at — flagged separately for visibility.
exception_missing_expires_at_prowler_ids[ex_id] if {
	ex := _prowler_exceptions_store[_]
	_prowler_exception_expires_at(ex) == ""
	ex_id := _prowler_exception_id(ex)
}

# Active (non-expired) valid exceptions — safe list for matching.
active_valid_prowler_exceptions := [ex |
	ex := _prowler_exceptions_store[_]
	valid_prowler_exception(ex)
]
