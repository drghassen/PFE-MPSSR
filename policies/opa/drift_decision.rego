# ==============================================================================
# CloudSentinel — Shift-Right Drift Policy Decision
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ==============================================================================
# FIX: P0.1 — Defaults fail-safe pour éviter FAIL-OPEN sur input manquant
# Si input.findings est absent/null, OPA retourne [] au lieu de undefined.
# Sans ces defaults, le client Python interprète l'absence de clé comme
# "aucune violation" — comportement FAIL-OPEN silencieux.
# ==============================================================================

default violations := []
default compliant := []

# ==============================================================================
# Entry Points
# ==============================================================================

violations := [decision |
	finding := input.findings[_]
	decision := evaluate_drift(finding)
	decision.severity != "INFO"
]

compliant := [info |
	finding := input.findings[_]
	decision := evaluate_drift(finding)
	decision.severity == "INFO"
	info := {
		"resource_id": object.get(finding, "address", "UNKNOWN"),
		"status": "COMPLIANT",
	}
]

# ==============================================================================
# Fonction Principale
# ==============================================================================

# FIX: P0.2 — Clause nominale avec guards explicites sur les champs obligatoires.
# Si l'un des trois champs est absent, cette clause ne s'évalue pas et le fallback
# _malformed_finding_decision prend le relais — jamais de silence sur un finding.
evaluate_drift(finding) := decision if {
	finding.address
	finding.type
	finding.provider_name

	severity := determine_severity(finding)
	action   := determine_action(severity, finding)
	custodian := get_custodian_policy(finding)

	decision := {
		# B8: resource_id uses finding.address (Terraform resource address, e.g.
		# "azurerm_storage_account.example") — always present, stable, and matches
		# what opa_normalizer.normalize_drift_for_opa() sets as resource_id.
		# The ARM resource ID (/subscriptions/...) lives in json_normalizer output
		# but is NOT used here to avoid ambiguity with undeployed resources.
		"resource_id":      finding.address,
		"resource_type":    finding.type,
		"provider":         finding.provider_name,
		"severity":         severity,
		"reason":           build_reason(severity, finding),
		"action_required":  action,
		"changed_paths":    object.get(finding, "changed_paths", []),
		"custodian_policy": custodian,
		"original_actions": object.get(finding, "actions", []),
	}
}

# FIX: P0.2 — Fallback si address manquant
evaluate_drift(finding) := decision if {
	not finding.address
	decision := _malformed_finding_decision(finding)
}

# FIX: P0.2 — Fallback si type manquant (address présent)
evaluate_drift(finding) := decision if {
	finding.address
	not finding.type
	decision := _malformed_finding_decision(finding)
}

# FIX: P0.2 — Fallback si provider_name manquant (address et type présents)
evaluate_drift(finding) := decision if {
	finding.address
	finding.type
	not finding.provider_name
	decision := _malformed_finding_decision(finding)
}

# Un finding malformé ne doit JAMAIS être ignoré silencieusement.
# LOW + manual_review garantit sa présence dans violations[] pour traitement humain.
_malformed_finding_decision(finding) := {
	"resource_id":      object.get(finding, "address", "UNKNOWN"),
	"resource_type":    object.get(finding, "type", "UNKNOWN"),
	"provider":         object.get(finding, "provider_name", "UNKNOWN"),
	"severity":         "LOW",
	"action_required":  "manual_review",
	"custodian_policy": null,
	"changed_paths":    object.get(finding, "changed_paths", []),
	"reason":           "Finding with missing mandatory fields — requires manual review",
	"original_actions": object.get(finding, "actions", []),
}

# ==============================================================================
# Détermination de Sévérité (else-if chain)
# ==============================================================================

# FIX: P0.3 — INFO est réservé aux findings sans changed_paths (pas de drift réel).
# L'ultime fallback est LOW (conservatif), jamais INFO pour un drift actif.
determine_severity(finding) := "CRITICAL" if {
	is_critical_drift(finding)
} else := "HIGH" if {
	is_high_drift(finding)
} else := "MEDIUM" if {
	is_medium_drift(finding)
} else := "LOW" if {
	is_low_drift(finding)
} else := "INFO" if {
	# INFO uniquement si aucun changed_path → resource sans drift effectif détecté
	count(object.get(finding, "changed_paths", [])) == 0
} else := "LOW" # FIX: P0.3 — Ultime fallback conservatif pour changed_paths non classifiés

# ==============================================================================
# Règles de Classification
# ==============================================================================

is_critical_drift(finding) if {
	finding.type == "azurerm_network_security_group"
	"security_rule" in object.get(finding, "changed_paths", [])
}

is_critical_drift(finding) if {
	finding.type == "azurerm_network_security_rule"
	"access" in object.get(finding, "changed_paths", [])
}

is_critical_drift(finding) if {
	finding.type == "azurerm_linux_virtual_machine"
	"admin_password" in object.get(finding, "changed_paths", [])
}

is_critical_drift(finding) if {
	finding.type == "azurerm_sql_server"
	"administrator_login_password" in object.get(finding, "changed_paths", [])
}

is_high_drift(finding) if {
	finding.type == "azurerm_key_vault"
	"access_policy" in object.get(finding, "changed_paths", [])
}

is_high_drift(finding) if {
	finding.type == "azurerm_key_vault"
	"network_acls" in object.get(finding, "changed_paths", [])
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account"
	"min_tls_version" in object.get(finding, "changed_paths", [])
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account"
	"allow_blob_public_access" in object.get(finding, "changed_paths", [])
}

is_medium_drift(finding) if {
	finding.type == "azurerm_monitor_diagnostic_setting"
	"enabled_log" in object.get(finding, "changed_paths", [])
}

is_low_drift(finding) if {
	finding.type == "azurerm_log_analytics_workspace"
	"retention_in_days" in object.get(finding, "changed_paths", [])
}

# FIX: P0.3 — Fallback LOW pour tout drift non classifié (élimine FAIL-OPEN via INFO).
# Toute ressource avec changed_paths non vides et non couverte par les règles
# explicites est au minimum LOW — jamais INFO (qui signifierait "compliant").
is_low_drift(finding) if {
	count(object.get(finding, "changed_paths", [])) > 0
	not is_critical_drift(finding)
	not is_high_drift(finding)
	not is_medium_drift(finding)
}

# ==============================================================================
# Détermination de l'Action (else-if chain)
# ==============================================================================

determine_action(severity, finding) := "immediate_review" if {
	severity == "CRITICAL"
} else := "auto_remediate" if {
	severity == "HIGH"
	object.get(finding, "type", "") == "azurerm_storage_account"
} else := "schedule_review" if {
	severity == "HIGH"
} else := "schedule_review" if {
	severity == "MEDIUM"
} else := "monitor" if {
	severity == "LOW"
} else := "none"

# ==============================================================================
# Mapping Cloud Custodian
# ==============================================================================

# FIX: P1.3 — Custodian policies pour tous les types critiques et high.
# NOTE: Les fichiers YAML Custodian correspondants seront créés en Phase P2.
# Ces identifiants servent de référence pour le mapping OPA → Cloud Custodian.
# Structure en chaîne else pour éviter eval_conflict_error (une seule valeur possible).

# NSG — CRITICAL
get_custodian_policy(finding) := "enforce-nsg-no-open-inbound" if {
	object.get(finding, "type", "") == "azurerm_network_security_group"
	"security_rule" in object.get(finding, "changed_paths", [])
} else := "enforce-nsg-rule-deny-all" if {
	# NSG rule — CRITICAL
	object.get(finding, "type", "") == "azurerm_network_security_rule"
	"access" in object.get(finding, "changed_paths", [])
} else := "enforce-vm-no-password-auth" if {
	# VM — CRITICAL
	object.get(finding, "type", "") == "azurerm_linux_virtual_machine"
	"admin_password" in object.get(finding, "changed_paths", [])
} else := "enforce-sql-password-rotation" if {
	# SQL — CRITICAL
	object.get(finding, "type", "") == "azurerm_sql_server"
	"administrator_login_password" in object.get(finding, "changed_paths", [])
} else := "enforce-keyvault-access-policy" if {
	# Key Vault access_policy — HIGH
	object.get(finding, "type", "") == "azurerm_key_vault"
	"access_policy" in object.get(finding, "changed_paths", [])
} else := "enforce-keyvault-network-acls" if {
	# Key Vault network_acls — HIGH
	object.get(finding, "type", "") == "azurerm_key_vault"
	"network_acls" in object.get(finding, "changed_paths", [])
} else := "enforce-storage-tls" if {
	# Storage TLS — HIGH
	object.get(finding, "type", "") == "azurerm_storage_account"
	"min_tls_version" in object.get(finding, "changed_paths", [])
} else := "deny-public-storage" if {
	# Storage public blob — HIGH
	object.get(finding, "type", "") == "azurerm_storage_account"
	"allow_blob_public_access" in object.get(finding, "changed_paths", [])
} else := null # Fallback : type non couvert → null (pas de remédiation automatique connue)

# ==============================================================================
# Helpers
# ==============================================================================

# FIX: P1.4 — json.marshal() pour les arrays (propre vs %v Go-style)
# + object.get() pour null-safety sur finding.type
build_reason(severity, finding) := sprintf("%s drift on %s: %s", [
	severity,
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "CRITICAL"
} else := sprintf("High-severity drift on %s requiring remediation: %s", [
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "HIGH"
} else := sprintf("Configuration drift on %s: %s", [
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "MEDIUM"
} else := sprintf("Low-impact drift on %s: %s", [
	object.get(finding, "type", "UNKNOWN"),
	json.marshal(object.get(finding, "changed_paths", [])),
]) if {
	severity == "LOW"
} else := "Drift within acceptable bounds"

# ==============================================================================
# FIX: P1.2 — Exception handling pour drift (Phase 1 simplifiée)
# LIMITATION SCOPE : Phase 1 — 6 critères de validation.
# Phase 2 (post-soutenance) : aligner sur les 12 critères du shift-left
# (SHA256 ID, tool whitelist, no wildcard resource, severity rank map,
#  partial_mismatch_reasons, scope repo/branch/env, etc.)
# ==============================================================================

# Chargement des exceptions depuis data.drift_exceptions (document statique OPA).
# ARCHITECTURE : drift_exceptions.json est monté via --data au démarrage du serveur
# OPA (opa-server-shiftright, port 8182). data.* et le package cloudsentinel.shiftright.drift
# sont des namespaces totalement distincts — aucune interaction circulaire possible.
# SÉPARATION EXPLICITE depuis les exceptions shift-left (data.cloudsentinel.exceptions)
# qui ont un format et un cycle de vie différents.
# Si le bundle n'est pas monté, default {} est utilisé → zéro exception active (fail-safe).
default _drift_exceptions_store := {}

_drift_exceptions_store := data.cloudsentinel.drift_exceptions

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
# Empty list → universal match (exception applies to all environments).
# Non-empty list → exception must include input.environment explicitly.
_drift_exception_env_matches(ex) if {
	count(object.get(ex, "environments", [])) == 0
}

_drift_exception_env_matches(ex) if {
	count(object.get(ex, "environments", [])) > 0
	input.environment in ex.environments
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
	# Temporalité : approuvée dans le passé et non encore expirée
	time.parse_rfc3339_ns(ex.approved_at) <= time.now_ns()
	time.now_ns() < time.parse_rfc3339_ns(ex.expires_at)
	# Cohérence temporelle : approved_at doit être antérieur à expires_at
	# (évite les exceptions mal formées où l'expiration précède l'approbation)
	time.parse_rfc3339_ns(ex.approved_at) < time.parse_rfc3339_ns(ex.expires_at)
	# Scope : l'exception doit correspondre à l'environnement courant
	_drift_exception_env_matches(ex)
	# Sécurité : les wildcards (* ou ?) sont interdits dans resource_type et resource_id
	# pour éviter les exceptions trop larges qui masqueraient de vraies violations
	not _drift_exception_has_wildcard(ex)
}

# ── Matching exception ↔ violation ──
_drift_exception_matches(ex, v) if {
	ex.resource_type == v.resource_type
	ex.resource_id == v.resource_id
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

# ── Métriques d'exceptions pour audit et traçabilité ──
drift_exception_summary := {
	"total_exceptions_loaded": count(object.get(_drift_exceptions_store, "exceptions", [])),
	"valid_exceptions": count([ex |
		some ex in object.get(_drift_exceptions_store, "exceptions", [])
		valid_drift_exception(ex)
	]),
	"excepted_violations": count(violations) - count(effective_violations),
}
