from __future__ import annotations

# ---------------------------------------------------------------------------
# Security dimension taxonomy
# Observation only — no verdict. OPA is the authoritative decision point.
# ---------------------------------------------------------------------------

_SECURITY_DIMENSIONS: dict[tuple[str, str], str] = {
    # network_exposure
    ("azurerm_network_security_group", "security_rule"): "network_exposure",
    ("azurerm_network_security_rule", "access"): "network_exposure",
    ("azurerm_firewall_policy_rule_collection_group", "network_rule_collection"): "network_exposure",
    ("azurerm_firewall_policy_rule_collection_group", "application_rule_collection"): "network_exposure",
    ("azurerm_subnet", "address_prefixes"): "network_exposure",
    ("azurerm_linux_virtual_machine", "network_interface_ids"): "network_exposure",
    ("azurerm_windows_virtual_machine", "network_interface_ids"): "network_exposure",
    # credential
    ("azurerm_linux_virtual_machine", "admin_password"): "credential",
    ("azurerm_windows_virtual_machine", "admin_password"): "credential",
    ("azurerm_sql_server", "administrator_login_password"): "credential",
    ("azurerm_postgresql_flexible_server", "administrator_login_password"): "credential",
    ("azurerm_mysql_flexible_server", "administrator_login_password"): "credential",
    # access_control
    ("azurerm_role_assignment", "role_definition_id"): "access_control",
    ("azurerm_role_assignment", "principal_id"): "access_control",
    ("azurerm_key_vault", "access_policy"): "access_control",
    ("azurerm_key_vault_access_policy", "secret_permissions"): "access_control",
    ("azurerm_key_vault_access_policy", "key_permissions"): "access_control",
    ("azurerm_key_vault_access_policy", "certificate_permissions"): "access_control",
    # data_protection
    ("azurerm_storage_account", "min_tls_version"): "data_protection",
    ("azurerm_storage_account", "allow_blob_public_access"): "data_protection",
    ("azurerm_storage_account", "allow_nested_items_to_be_public"): "data_protection",
    ("azurerm_storage_account", "public_network_access_enabled"): "data_protection",
    ("azurerm_storage_account", "network_rules"): "data_protection",
    ("azurerm_storage_account_network_rules", "default_action"): "network_exposure",
    ("azurerm_key_vault", "network_acls"): "data_protection",
    ("azurerm_sql_server", "public_network_access_enabled"): "data_protection",
    ("azurerm_postgresql_flexible_server", "public_network_access_enabled"): "data_protection",
    ("azurerm_mysql_flexible_server", "public_network_access_enabled"): "data_protection",
    # backup_resilience
    ("azurerm_backup_protected_vm", "protection_state"): "backup_resilience",
    # audit_logging
    ("azurerm_monitor_diagnostic_setting", "enabled_log"): "audit_logging",
    ("azurerm_log_analytics_workspace", "retention_in_days"): "audit_logging",
}


def _changed_path_root(path: str) -> str:
    """
    Returns the root key of a Terraform diff path.
    Examples:
      - "security_rule[0].access" -> "security_rule"
      - "network_acls.default_action" -> "network_acls"
    """
    head = path.split(".", 1)[0]
    return head.split("[", 1)[0]


def classify_security_dimensions(
    resource_type: str,
    changed_paths: list[str],
) -> list[str]:
    """
    Returns the security dimensions touched by this drift event.
    Pure observation — produces metadata for OPA, not a verdict.
    """
    dimensions: set[str] = set()
    for path in changed_paths:
        if not isinstance(path, str):
            continue
        key = (resource_type, _changed_path_root(path))
        if key in _SECURITY_DIMENSIONS:
            dimensions.add(_SECURITY_DIMENSIONS[key])
    return sorted(dimensions)


# ---------------------------------------------------------------------------
# Fallback severity tables — used ONLY when OPA is disabled or unavailable.
# OPA is the authoritative Policy Decision Point for severity.
# ---------------------------------------------------------------------------

_PATH_SEVERITY_MAP: dict[tuple[str, str], str] = {
    # Critical — network rules
    ("azurerm_network_security_group", "security_rule"): "Critical",
    ("azurerm_network_security_rule", "access"): "Critical",
    ("azurerm_firewall_policy_rule_collection_group", "network_rule_collection"): "Critical",
    ("azurerm_firewall_policy_rule_collection_group", "application_rule_collection"): "Critical",
    # Critical — RBAC
    ("azurerm_role_assignment", "role_definition_id"): "Critical",
    ("azurerm_role_assignment", "principal_id"): "Critical",
    # Critical — credentials
    ("azurerm_linux_virtual_machine", "admin_password"): "Critical",
    ("azurerm_windows_virtual_machine", "admin_password"): "Critical",
    ("azurerm_sql_server", "administrator_login_password"): "Critical",
    ("azurerm_postgresql_flexible_server", "administrator_login_password"): "Critical",
    ("azurerm_mysql_flexible_server", "administrator_login_password"): "Critical",
    # High — vault access
    ("azurerm_key_vault", "access_policy"): "High",
    ("azurerm_key_vault", "network_acls"): "High",
    ("azurerm_key_vault_access_policy", "secret_permissions"): "High",
    ("azurerm_key_vault_access_policy", "key_permissions"): "High",
    ("azurerm_key_vault_access_policy", "certificate_permissions"): "High",
    # High — storage data protection
    ("azurerm_storage_account", "min_tls_version"): "High",
    ("azurerm_storage_account", "allow_blob_public_access"): "High",
    ("azurerm_storage_account", "allow_nested_items_to_be_public"): "High",
    ("azurerm_storage_account", "public_network_access_enabled"): "High",
    ("azurerm_storage_account", "network_rules"): "High",
    ("azurerm_storage_account_network_rules", "default_action"): "High",
    # High — backup/recovery posture
    ("azurerm_backup_protected_vm", "protection_state"): "High",
    # High — database exposure
    ("azurerm_sql_server", "public_network_access_enabled"): "High",
    ("azurerm_postgresql_flexible_server", "public_network_access_enabled"): "High",
    ("azurerm_mysql_flexible_server", "public_network_access_enabled"): "High",
    # High — network topology
    ("azurerm_subnet", "address_prefixes"): "High",
    ("azurerm_linux_virtual_machine", "network_interface_ids"): "High",
    ("azurerm_windows_virtual_machine", "network_interface_ids"): "High",
    # Medium — monitoring
    ("azurerm_monitor_diagnostic_setting", "enabled_log"): "Medium",
    ("azurerm_virtual_network", "address_space"): "Medium",
    # Low — retention
    ("azurerm_log_analytics_workspace", "retention_in_days"): "Low",
}

_RESOURCE_TYPE_FALLBACK_SEVERITY: dict[str, str] = {
    "azurerm_role_assignment": "Critical",
    "azurerm_virtual_machine": "High",
    "azurerm_linux_virtual_machine": "High",
    "azurerm_windows_virtual_machine": "High",
    "azurerm_storage_account": "High",
    "azurerm_storage_account_network_rules": "High",
    "azurerm_backup_protected_vm": "High",
    "azurerm_recovery_services_vault": "High",
    "azurerm_sql_server": "High",
    "azurerm_postgresql_flexible_server": "High",
    "azurerm_mysql_flexible_server": "High",
    "azurerm_key_vault": "High",
    "azurerm_key_vault_access_policy": "High",
    "azurerm_network_security_rule": "High",
    "azurerm_subnet": "Medium",
    "azurerm_network_security_group": "Medium",
    "azurerm_resource_group": "Low",
    "azurerm_virtual_network": "Low",
    "azurerm_log_analytics_workspace": "Low",
    "_default": "Medium",
}

_SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def classify_drift_severity(
    resource_type: str,
    changed_paths: list[str],
    resource_id: str | None = None,
    provenance: str | None = None,
) -> str:
    """
    Fallback severity classifier — called ONLY when OPA is disabled or unavailable.
    Returns the maximum severity across all matching paths, floored by the resource-type default.
    """
    type_floor = _RESOURCE_TYPE_FALLBACK_SEVERITY.get(
        resource_type, _RESOURCE_TYPE_FALLBACK_SEVERITY["_default"]
    )
    if resource_id is None and provenance == "inferred_from_output":
        return type_floor

    matched = [
        _PATH_SEVERITY_MAP[(resource_type, _changed_path_root(path))]
        for path in changed_paths
        if isinstance(path, str)
        and (resource_type, _changed_path_root(path)) in _PATH_SEVERITY_MAP
    ]
    if matched:
        path_max = max(matched, key=lambda s: _SEVERITY_ORDER.index(s))
        return max([path_max, type_floor], key=lambda s: _SEVERITY_ORDER.index(s))
    return type_floor
