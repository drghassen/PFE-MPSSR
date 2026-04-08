resource "azurerm_log_analytics_workspace" "this" {
  name                = "law-${replace(var.base_name, "-", "")}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name               = "diag-activity-${replace(var.base_name, "-", "")}"
  target_resource_id = "/subscriptions/${var.subscription_id}/providers/Microsoft.Insights/diagnosticSettings/activity"
  storage_account_id = var.storage_account_id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
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
