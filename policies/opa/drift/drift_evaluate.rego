# ==============================================================================
# Shift-Right Drift — evaluate_drift (core decision per finding)
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

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
	action := determine_action(severity, finding)
	custodian := get_custodian_policy(finding)

	decision := {
		# B8: resource_id uses finding.address (Terraform resource address, e.g.
		# "azurerm_storage_account.example") — always present, stable, and matches
		# what opa_normalizer.normalize_drift_for_opa() sets as resource_id.
		# The ARM resource ID (/subscriptions/...) lives in json_normalizer output
		# but is NOT used here to avoid ambiguity with undeployed resources.
		"resource_id": finding.address,
		"resource_type": finding.type,
		"provider": finding.provider_name,
		"severity": severity,
		"reason": build_reason(severity, finding),
		"action_required": action,
		"changed_paths": object.get(finding, "changed_paths", []),
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
	"resource_id": object.get(finding, "address", "UNKNOWN"),
	"resource_type": object.get(finding, "type", "UNKNOWN"),
	"provider": object.get(finding, "provider_name", "UNKNOWN"),
	"severity": "LOW",
	"action_required": "manual_review",
	"custodian_policy": null,
	"changed_paths": object.get(finding, "changed_paths", []),
	"reason": "Finding with missing mandatory fields — requires manual review",
	"original_actions": object.get(finding, "actions", []),
}
