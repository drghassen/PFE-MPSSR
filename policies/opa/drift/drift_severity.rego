# ==============================================================================
# Shift-Right Drift — severity & classification rules
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

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
} else := "UNKNOWN"

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
is_unknown_drift(finding) if {
	count(object.get(finding, "changed_paths", [])) > 0
	not is_critical_drift(finding)
	not is_high_drift(finding)
	not is_medium_drift(finding)
	not is_low_drift(finding)
}
