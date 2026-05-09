resource "azurerm_mssql_server" "this" {
  count               = var.enabled ? 1 : 0
  name                = var.server_name
  resource_group_name = var.resource_group_name
  location            = var.location
  version             = "12.0"
  minimum_tls_version = "1.2"

  public_network_access_enabled = false

  azuread_administrator {
    login_username              = var.azuread_admin_login
    object_id                   = var.azuread_admin_object_id
    azuread_authentication_only = true
  }

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

resource "azurerm_mssql_database" "this" {
  count     = var.enabled ? 1 : 0
  name      = var.database_name
  server_id = azurerm_mssql_server.this[0].id
  sku_name  = var.sku_name

  tags = var.tags
}

resource "azurerm_private_dns_zone" "sql" {
  count               = var.enabled ? 1 : 0
  name                = "privatelink.database.windows.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "sql" {
  count                 = var.enabled ? 1 : 0
  name                  = "pdnslink-sql-${var.server_name}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.sql[0].name
  virtual_network_id    = var.vnet_id
  tags                  = var.tags
}

resource "azurerm_mssql_server_extended_auditing_policy" "this" {
  count             = var.enabled ? 1 : 0
  server_id         = azurerm_mssql_server.this[0].id
  enabled           = true
  retention_in_days = 90
}

resource "azurerm_mssql_server_security_alert_policy" "this" {
  count                = var.enabled ? 1 : 0
  resource_group_name  = var.resource_group_name
  server_name          = azurerm_mssql_server.this[0].name
  state                = "Enabled"
  email_account_admins = true
}

resource "azurerm_mssql_server_vulnerability_assessment" "this" {
  count                           = var.enabled ? 1 : 0
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.this[0].id
  storage_container_path          = "${var.audit_storage_endpoint}vulnerability-assessment/"

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
  }
}

resource "azurerm_private_endpoint" "sql" {
  count               = var.enabled ? 1 : 0
  name                = "pe-${var.server_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "psc-${var.server_name}"
    private_connection_resource_id = azurerm_mssql_server.this[0].id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "dns-group-sql"
    private_dns_zone_ids = [azurerm_private_dns_zone.sql[0].id]
  }

  tags = var.tags
}
