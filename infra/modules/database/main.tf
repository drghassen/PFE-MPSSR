data "azurerm_key_vault_secret" "db_password" {
  name         = var.db_password_secret_name
  key_vault_id = var.key_vault_id
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                              = "${var.name_prefix}-pgfs"
  resource_group_name               = var.resource_group_name
  location                          = var.location
  version                           = "15"
  administrator_login               = var.admin_login
  administrator_password            = data.azurerm_key_vault_secret.db_password.value
  sku_name                          = var.sku_name
  storage_mb                        = 32768
  backup_retention_days             = 7
  geo_redundant_backup_enabled      = false
  public_network_access_enabled     = false
  zone                              = "1"
  tags                              = var.tags
}

# Special Azure flag: 0.0.0.0/0.0.0.0 = allow Azure-internal services only
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.this.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Dev whitelist — add VM public IP and your own IP after first apply
resource "azurerm_postgresql_flexible_server_firewall_rule" "allowed" {
  for_each         = toset(var.allowed_ips)
  name             = "allow-${replace(each.value, ".", "-")}"
  server_id        = azurerm_postgresql_flexible_server.this.id
  start_ip_address = each.value
  end_ip_address   = each.value
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = var.db_name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}
