resource "azurerm_log_analytics_workspace" "this" {
  name                = "law-${replace(var.base_name, "-", "")}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_monitor_log_profile" "activity" {
  name = "activity-log-profile-${replace(var.base_name, "-", "")}"
  storage_account_id = var.storage_account_id

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
  target_resource_id         = "${var.storage_account_id}/blobServices/default"
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
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "diag-kv-${replace(var.base_name, "-", "")}"
  target_resource_id         = var.key_vault_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "AuditEvent"
  }
}
