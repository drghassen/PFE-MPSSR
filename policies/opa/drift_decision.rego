# ==============================================================================
# CloudSentinel — Shift-Right Drift Policy Decision
# ==============================================================================

package cloudsentinel.shiftright.drift

import future.keywords.if
import future.keywords.in

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
        "resource_id": finding.address,
        "status": "COMPLIANT"
    }
]

# ==============================================================================
# Fonction Principale
# ==============================================================================

evaluate_drift(finding) := decision if {
    severity := determine_severity(finding)
    action := determine_action(severity, finding)
    custodian_policy := get_custodian_policy(finding)
    
    decision := {
        "resource_id": finding.address,
        "resource_type": finding.type,
        "provider": finding.provider_name,
        "severity": severity,
        "reason": build_reason(severity, finding),
        "action_required": action,
        "changed_paths": finding.changed_paths,
        "custodian_policy": custodian_policy,
        "original_actions": finding.actions
    }
}

# ==============================================================================
# Détermination de Sévérité (else-if chain)
# ==============================================================================

determine_severity(finding) := "CRITICAL" if {
    is_critical_drift(finding)
} else := "HIGH" if {
    is_high_drift(finding)
} else := "MEDIUM" if {
    is_medium_drift(finding)
} else := "LOW" if {
    is_low_drift(finding)
} else := "INFO"

# ==============================================================================
# Règles de Classification
# ==============================================================================

is_critical_drift(finding) if {
    finding.type == "azurerm_network_security_group"
    "security_rule" in finding.changed_paths
}

is_critical_drift(finding) if {
    finding.type == "azurerm_network_security_rule"
    "access" in finding.changed_paths
}

is_critical_drift(finding) if {
    finding.type == "azurerm_linux_virtual_machine"
    "admin_password" in finding.changed_paths
}

is_critical_drift(finding) if {
    finding.type == "azurerm_sql_server"
    "administrator_login_password" in finding.changed_paths
}

is_high_drift(finding) if {
    finding.type == "azurerm_key_vault"
    "access_policy" in finding.changed_paths
}

is_high_drift(finding) if {
    finding.type == "azurerm_key_vault"
    "network_acls" in finding.changed_paths
}

is_high_drift(finding) if {
    finding.type == "azurerm_storage_account"
    "min_tls_version" in finding.changed_paths
}

is_high_drift(finding) if {
    finding.type == "azurerm_storage_account"
    "allow_blob_public_access" in finding.changed_paths
}

is_medium_drift(finding) if {
    finding.type == "azurerm_monitor_diagnostic_setting"
    "enabled_log" in finding.changed_paths
}

is_low_drift(finding) if {
    finding.type == "azurerm_log_analytics_workspace"
    "retention_in_days" in finding.changed_paths
}

# ==============================================================================
# Détermination de l'Action (else-if chain)
# ==============================================================================

determine_action(severity, finding) := "immediate_review" if {
    severity == "CRITICAL"
} else := "auto_remediate" if {
    severity == "HIGH"
    finding.type == "azurerm_storage_account"
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

get_custodian_policy(finding) := "enforce-storage-tls" if {
    finding.type == "azurerm_storage_account"
    "min_tls_version" in finding.changed_paths
} else := "deny-public-storage" if {
    finding.type == "azurerm_storage_account"
    "allow_blob_public_access" in finding.changed_paths
} else := null

# ==============================================================================
# Helpers (else-if chain)
# ==============================================================================

build_reason(severity, finding) := sprintf("Critical drift on %s: %v", [finding.type, finding.changed_paths]) if {
    severity == "CRITICAL"
} else := sprintf("High-severity drift on %s requiring remediation", [finding.type]) if {
    severity == "HIGH"
} else := sprintf("Configuration drift on %s", [finding.type]) if {
    severity == "MEDIUM"
} else := sprintf("Low-impact drift on %s", [finding.type]) if {
    severity == "LOW"
} else := "Drift within acceptable bounds"