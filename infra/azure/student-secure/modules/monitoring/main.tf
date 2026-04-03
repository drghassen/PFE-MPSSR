resource "azurerm_log_analytics_workspace" "this" {
  name                = "law-${replace(var.base_name, "-", "")}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_network_watcher" "this" {
  name                = "nw-${replace(var.base_name, "-", "")}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_watcher_flow_log" "nsg" {
  for_each = var.network_security_ids

  name                 = "flow-${each.key}-${replace(var.base_name, "-", "")}"
  network_watcher_name = azurerm_network_watcher.this.name
  resource_group_name  = var.resource_group_name
  network_security_group_id = each.value
  storage_account_id        = var.storage_account_id
  enabled                   = true
  version                   = 2
  tags                      = var.tags

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.this.workspace_id
    workspace_region      = var.location
    workspace_resource_id = azurerm_log_analytics_workspace.this.id
    interval_in_minutes   = 10
  }
}

resource "azurerm_monitor_log_profile" "activity" {
  name = "activity-log-profile-${replace(var.base_name, "-", "")}"

  categories = [
    "Action",
    "Delete",
    "Write"
  ]

  locations = [
    "global",
    var.location
  ]

  retention_policy {
    enabled = true
    days    = 365
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "diag-storage-${replace(var.base_name, "-", "")}"
  target_resource_id         = var.storage_account_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
  }
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "diag-kv-${replace(var.base_name, "-", "")}"
  target_resource_id         = var.key_vault_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "AuditEvent"
  }
}
