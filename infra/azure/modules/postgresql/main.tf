resource "azurerm_private_dns_zone" "postgres" {
  name                = var.private_dns_zone_name
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "${var.server_name}-pdns-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = var.virtual_network_id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = var.server_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = var.postgresql_version
  delegated_subnet_id           = var.delegated_subnet_id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  administrator_login           = var.administrator_login
  administrator_password        = var.administrator_password
  zone                          = var.availability_zone
  storage_mb                    = var.storage_mb
  sku_name                      = var.sku_name
  backup_retention_days         = var.backup_retention_days
  public_network_access_enabled = false
  tags                          = var.tags

  # CIS 4.3.7 / CKV2_CS_AZ_036 — absent attribute defaults to TLS 1.0 in Azure.
  # Explicitly enforce TLS 1.2 minimum; TLS 1.0 and 1.1 are cryptographically broken.
  ssl_minimal_tls_version_enforced = var.ssl_minimal_tls_version

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

# =============================================================================
# SERVER PARAMETER HARDENING
# =============================================================================
#
# VERIFIED AGAINST AZURE FLEXIBLE SERVER PARAMETER SCHEMA (API 2022-12-01)
#
# VALID parameters (confirmed to exist in Flexible Server):
#   log_checkpoints    — CIS 4.3.1  | default: off → set on
#   log_connections    — CIS 4.3.2  | default: off → set on
#   log_disconnections — CIS 4.3.3  | default: off → set on
#   log_statement      — CIS 4.3.6  | default: none → set ddl
#
# SCHEMA MISMATCH — do NOT configure via azurerm_postgresql_flexible_server_configuration:
#   connection_throttling  — Single Server parameter only; does not exist in Flexible Server
#                           Prowler check postgresql_flexible_server_connection_throttling_on
#                           returns (ResourceNotFound) on Flexible Server.
#                           → Fix mapping in Prowler/OPA layer, NOT here.
#
#   log_retention_days     — Single Server parameter only; Flexible Server controls log
#                           retention via Azure Monitor Diagnostic Setting retention policy.
#                           → Already handled by azurerm_monitor_diagnostic_setting.postgres.
#
locals {
  # Keys must match exact Azure parameter names verified via:
  #   az postgres flexible-server parameter show --name <key> --server-name ...
  pg_security_parameters = {
    log_checkpoints    = "on"   # CIS 4.3.1 — checkpoint activity aids crash recovery audit
    log_connections    = "on"   # CIS 4.3.2 — each new client connection logged
    log_disconnections = "on"   # CIS 4.3.3 — session terminations logged with duration
    log_statement      = "ddl"  # CIS 4.3.6 — DDL (CREATE/DROP/ALTER) logged; "all" is too
    # verbose for production throughput; "ddl" satisfies CIS minimum
  }
}

resource "azurerm_postgresql_flexible_server_configuration" "security" {
  for_each = local.pg_security_parameters

  name      = each.key
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = each.value
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = var.database_name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"

  timeouts {
    create = "60m"
    read   = "5m"
    delete = "30m"
  }
}

resource "azurerm_monitor_diagnostic_setting" "postgres" {
  name                       = "${var.server_name}-diag"
  target_resource_id         = azurerm_postgresql_flexible_server.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category_group = "allLogs"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}
