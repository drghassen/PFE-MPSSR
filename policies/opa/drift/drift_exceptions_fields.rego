# ==============================================================================
# Shift-Right Drift — exception validation (wildcards, scope, approval)
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ── Wildcard guard helpers ──
# Wildcards (* or ?) in resource_type or resource_id are not allowed in drift
# exceptions. They create overly broad exceptions that could mask real violations.
# These helpers detect wildcards so valid_drift_exception() can reject such entries.

_drift_exception_has_wildcard(ex) if {
	contains(object.get(ex, "resource_type", ""), "*")
}

_drift_exception_has_wildcard(ex) if {
	contains(object.get(ex, "resource_type", ""), "?")
}

_drift_exception_has_wildcard(ex) if {
	contains(object.get(ex, "resource_id", ""), "*")
}

_drift_exception_has_wildcard(ex) if {
	contains(object.get(ex, "resource_id", ""), "?")
}

# ── Scope environment matching helpers ──

valid_env_scope(ex) if {
	not ex.environments
} else if {
	count(ex.environments) == 0
} else if {
	input.environment in ex.environments
}

valid_repo_scope(ex) if {
	not ex.repos
} else if {
	count(ex.repos) == 0
} else if {
	input.repo in ex.repos
}

valid_branch_scope(ex) if {
	not ex.branches
} else if {
	count(ex.branches) == 0
} else if {
	input.branch in ex.branches
}

# ── Validation d'une exception drift ──
valid_drift_exception(ex) if {
	# Source vérifiée : seul DefectDojo peut émettre des exceptions
	ex.source == "defectdojo"
	# Status approuvé
	ex.status == "approved"
	# Champs identité non vides
	ex.requested_by != ""
	ex.approved_by != ""
	ex.resource_type != ""
	# Four-eyes principle : le demandeur ne peut pas être son propre approbateur
	ex.requested_by != ex.approved_by
	# Temporalité : approuvée dans le passé
	time.parse_rfc3339_ns(ex.approved_at) <= time.now_ns()

	# Expiration optionnelle
	not _is_expired(ex)

	# Scope strict
	valid_env_scope(ex)
	valid_repo_scope(ex)
	valid_branch_scope(ex)

	# Sécurité : les wildcards (* ou ?) sont interdits dans resource_type et resource_id
	not _drift_exception_has_wildcard(ex)
}

_is_expired(ex) if {
	ex.expires_at
	time.now_ns() >= time.parse_rfc3339_ns(ex.expires_at)
}
