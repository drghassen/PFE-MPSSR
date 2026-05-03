output "storage_account_id" {
  description = "Resource ID of the flow-log storage account."
  value       = azurerm_storage_account.flowlogs.id
}

output "storage_account_name" {
  description = "Name of the flow-log storage account."
  value       = azurerm_storage_account.flowlogs.name
}

output "flow_log_ids" {
  description = "Map of NSG key to flow log resource ID."
  value       = { for k, v in azurerm_network_watcher_flow_log.nsg : k => v.id }
}

output "network_watcher_id" {
  description = "Resource ID of the referenced (existing) Network Watcher."
  value       = data.azurerm_network_watcher.this.id
}

output "network_watcher_location" {
  description = "Region of the referenced Network Watcher."
  value       = data.azurerm_network_watcher.this.location
}
