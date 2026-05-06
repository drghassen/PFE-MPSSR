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
determine_severity(finding) := "INFO" if {
	finding.type == "output"
	not finding.provenance == "inferred_from_output"
} else := "CRITICAL" if {
	is_critical_drift(finding)
} else := "HIGH" if {
	is_high_drift(finding)
} else := "MEDIUM" if {
	is_medium_drift(finding)
} else := "LOW" if {
	is_low_drift(finding)
} else := "LOW" if {
	is_unknown_drift(finding)
} else := "INFO" if {
	# INFO uniquement si aucun changed_path → resource sans drift effectif détecté
	count(object.get(finding, "changed_paths", [])) == 0
} else := "LOW"

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

# Any drift making blob container access public is immediately exploitable.
is_critical_drift(finding) if {
	finding.type == "azurerm_storage_container"
	"container_access_type" in object.get(finding, "changed_paths", [])
}

# Any drift on a standalone key vault access policy resource = CRITICAL.
# Adding/changing permissions or object_id directly grants access to secrets.
is_critical_drift(finding) if {
	finding.type == "azurerm_key_vault_access_policy"
	count(object.get(finding, "changed_paths", [])) > 0
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

# IAM: privilege escalation via role assignment changes.
is_high_drift(finding) if {
	finding.type == "azurerm_role_assignment"
	count(object.get(finding, "changed_paths", [])) > 0
}

# Key Vault secret/key/certificate drift = exposed secrets.
is_high_drift(finding) if {
	finding.type in {"azurerm_key_vault_secret", "azurerm_key_vault_key", "azurerm_key_vault_certificate"}
	count(object.get(finding, "changed_paths", [])) > 0
}

# Managed identity drift enables impersonation of the identity's permissions.
is_high_drift(finding) if {
	finding.type == "azurerm_user_assigned_identity"
	count(object.get(finding, "changed_paths", [])) > 0
}

is_medium_drift(finding) if {
	finding.type == "azurerm_monitor_diagnostic_setting"
	"enabled_log" in object.get(finding, "changed_paths", [])
}

# Relational database servers hold sensitive data; any configuration drift is MEDIUM.
is_medium_drift(finding) if {
	finding.type in {
		"azurerm_postgresql_flexible_server",
		"azurerm_mssql_flexible_server",
		"azurerm_mysql_flexible_server",
	}
	count(object.get(finding, "changed_paths", [])) > 0
}

# Web applications expose attack surface; configuration drift is MEDIUM.
is_medium_drift(finding) if {
	finding.type in {"azurerm_linux_web_app", "azurerm_windows_web_app"}
	count(object.get(finding, "changed_paths", [])) > 0
}

# Subnet changes affect network segmentation.
is_medium_drift(finding) if {
	finding.type == "azurerm_subnet"
	count(object.get(finding, "changed_paths", [])) > 0
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
