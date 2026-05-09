resource "azurerm_cosmosdb_account" "this" {
  count               = var.enabled ? 1 : 0
  name                = var.account_name
  location            = var.location
  resource_group_name = var.resource_group_name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  capabilities {
    name = "EnableServerless"
  }

  dynamic "geo_location" {
    for_each = [var.location]
    content {
      location          = geo_location.value
      failover_priority = 0
    }
  }

  public_network_access_enabled     = true
  is_virtual_network_filter_enabled = true
  local_authentication_disabled     = true

  dynamic "virtual_network_rule" {
    for_each = toset(var.allowed_subnet_ids)
    content {
      id = virtual_network_rule.value
    }
  }

  backup {
    type                = "Periodic"
    interval_in_minutes = 240
    retention_in_hours  = 8
  }

  tags = var.tags
}

resource "azurerm_cosmosdb_sql_database" "this" {
  count               = var.enabled ? 1 : 0
  name                = var.database_name
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.this[0].name
}
