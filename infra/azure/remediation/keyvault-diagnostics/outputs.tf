output "diagnostic_setting_id" {
  description = "Resource ID of the applied diagnostic setting."
  value       = azurerm_monitor_diagnostic_setting.kv_audit.id
}

output "key_vault_id" {
  description = "Resource ID of the remediated Key Vault (unchanged)."
  value       = data.azurerm_key_vault.target.id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace receiving the audit logs."
  value       = data.azurerm_log_analytics_workspace.law.id
}
