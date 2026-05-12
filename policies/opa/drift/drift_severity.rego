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
	changed_paths_has_key(finding, "security_rule")
}

is_critical_drift(finding) if {
	finding.type == "azurerm_network_security_rule"
	changed_paths_has_key(finding, "access")
}

is_critical_drift(finding) if {
	finding.type == "azurerm_linux_virtual_machine"
	changed_paths_has_key(finding, "admin_password")
}

is_critical_drift(finding) if {
	finding.type == "azurerm_sql_server"
	changed_paths_has_key(finding, "administrator_login_password")
}

# SQL logical server opened to public network is immediately exploitable.
is_critical_drift(finding) if {
	finding.type in {"azurerm_sql_server", "azurerm_mssql_server"}
	changed_paths_has_key(finding, "public_network_access_enabled")
}

is_critical_drift(finding) if {
	finding.type in {"azurerm_sql_server", "azurerm_mssql_server"}
	changed_paths_has_key(finding, "public_network_access")
}

# Any drift making blob container access public is immediately exploitable.
is_critical_drift(finding) if {
	finding.type == "azurerm_storage_container"
	changed_paths_has_key(finding, "container_access_type")
}

# Any drift on a standalone key vault access policy resource = CRITICAL.
# Adding/changing permissions or object_id directly grants access to secrets.
is_critical_drift(finding) if {
	finding.type == "azurerm_key_vault_access_policy"
	count(object.get(finding, "changed_paths", [])) > 0
}

is_high_drift(finding) if {
	finding.type == "azurerm_key_vault"
	changed_paths_has_key(finding, "access_policy")
}

is_high_drift(finding) if {
	finding.type == "azurerm_key_vault"
	changed_paths_has_key(finding, "network_acls")
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account"
	changed_paths_has_key(finding, "min_tls_version")
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account"
	changed_paths_has_key(finding, "allow_blob_public_access")
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account"
	changed_paths_has_key(finding, "allow_nested_items_to_be_public")
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account"
	changed_paths_has_key(finding, "public_network_access_enabled")
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account"
	changed_paths_has_key(finding, "network_rules")
}

is_high_drift(finding) if {
	finding.type == "azurerm_storage_account_network_rules"
	changed_paths_has_key(finding, "default_action")
}

is_high_drift(finding) if {
	finding.type == "azurerm_backup_protected_vm"
	changed_paths_has_key(finding, "protection_state")
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
	changed_paths_has_key(finding, "enabled_log")
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
	changed_paths_has_key(finding, "retention_in_days")
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
