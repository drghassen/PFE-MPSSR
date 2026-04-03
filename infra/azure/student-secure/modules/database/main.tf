resource "random_password" "mysql_admin" {
  count            = var.enabled ? 1 : 0
  length           = 32
  special          = true
  override_special = "!@#$%^*()-_=+[]{}:?"
}

locals {
  mysql_secret_suffix = replace(var.base_name, "-", "")
}

resource "azurerm_private_dns_zone" "mysql" {
  count               = var.enabled ? 1 : 0
  name                = "privatelink.mysql.database.azure.com"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "mysql" {
  count                 = var.enabled ? 1 : 0
  name                  = "mysql-vnet-link-${replace(var.base_name, "-", "")}"
  private_dns_zone_name = azurerm_private_dns_zone.mysql[0].name
  resource_group_name   = var.resource_group_name
  virtual_network_id    = var.virtual_network_id
  tags                  = var.tags
}

resource "azurerm_mysql_flexible_server" "this" {
  count                  = var.enabled ? 1 : 0
  name                   = "mysql-${replace(var.base_name, "-", "")}"
  location               = var.location
  resource_group_name    = var.resource_group_name
  administrator_login    = var.mysql_admin_username
  administrator_password = random_password.mysql_admin[0].result
  backup_retention_days  = 7
  geo_redundant_backup_enabled = true
  delegated_subnet_id    = var.delegated_subnet_id
  private_dns_zone_id    = azurerm_private_dns_zone.mysql[0].id
  sku_name               = var.mysql_sku_name
  version                = "8.0.21"
  zone                   = "1"
  tags                   = var.tags

  storage {
    size_gb           = 20
    iops              = 360
    auto_grow_enabled = true
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.mysql[0]]
}

resource "azurerm_mysql_flexible_database" "app" {
  count               = var.enabled ? 1 : 0
  name                = "appdb"
  resource_group_name = var.resource_group_name
  server_name         = azurerm_mysql_flexible_server.this[0].name
  charset             = "utf8mb4"
  collation           = "utf8mb4_unicode_ci"
}

resource "azurerm_private_endpoint" "mysql" {
  count               = var.enabled ? 1 : 0
  name                = "pep-mysql-${replace(var.base_name, "-", "")}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-mysql-${replace(var.base_name, "-", "")}"
    private_connection_resource_id = azurerm_mysql_flexible_server.this[0].id
    subresource_names              = ["mysqlServer"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "pdzg-mysql-${replace(var.base_name, "-", "")}"
    private_dns_zone_ids = [azurerm_private_dns_zone.mysql[0].id]
  }
}

resource "azurerm_key_vault_secret" "mysql_admin_username" {
  count           = var.enabled && var.manage_key_vault_secrets ? 1 : 0
  name            = "mysql-admin-username-${local.mysql_secret_suffix}"
  value           = var.mysql_admin_username
  key_vault_id    = var.key_vault_id
  expiration_date = var.secret_expiration_date
  content_type    = "text/plain"

  tags = merge(var.tags, {
    SecretClass = "credential"
    Rotation    = "manual"
    ManagedBy   = "opentofu"
  })
}

resource "azurerm_key_vault_secret" "mysql_admin_password" {
  count           = var.enabled && var.manage_key_vault_secrets ? 1 : 0
  name            = "mysql-admin-password-${local.mysql_secret_suffix}"
  value           = random_password.mysql_admin[0].result
  key_vault_id    = var.key_vault_id
  expiration_date = var.secret_expiration_date
  content_type    = "text/plain"

  tags = merge(var.tags, {
    SecretClass = "credential"
    Rotation    = "manual"
    ManagedBy   = "opentofu"
  })
}
