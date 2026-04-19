output "nsg_id" {
  description = "Network Security Group ID."
  value       = azurerm_network_security_group.this.id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID used for diagnostics."
  value       = azurerm_log_analytics_workspace.this.id
}

output "log_analytics_workspace_name" {
  description = "Log Analytics workspace name."
  value       = azurerm_log_analytics_workspace.this.name
}
