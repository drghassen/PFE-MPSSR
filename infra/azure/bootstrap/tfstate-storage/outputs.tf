output "storage_account_id" {
  description = "Resource ID of the Terraform state storage account."
  value       = azurerm_storage_account.tfstate.id
}

output "storage_account_name" {
  description = "Name of the storage account (use as TFSTATE_STORAGE_ACCOUNT in CI)."
  value       = azurerm_storage_account.tfstate.name
}

output "primary_blob_endpoint" {
  description = "Primary blob service endpoint."
  value       = azurerm_storage_account.tfstate.primary_blob_endpoint
}

output "min_tls_version" {
  description = "Enforced minimum TLS version."
  value       = azurerm_storage_account.tfstate.min_tls_version
}

output "https_only" {
  description = "Whether HTTPS-only traffic is enforced."
  value       = azurerm_storage_account.tfstate.https_traffic_only_enabled
}

output "versioning_enabled" {
  description = "Whether blob versioning is enabled (state recovery capability)."
  value       = azurerm_storage_account.tfstate.blob_properties[0].versioning_enabled
}

output "network_default_action" {
  description = "Network rules default action. Should be Allow (Phase 1) or Deny (Phase 2+)."
  value       = azurerm_storage_account.tfstate.network_rules[0].default_action
}

output "diagnostic_setting_id" {
  description = "Resource ID of the diagnostic setting (empty if LAW not configured)."
  value       = var.log_analytics_workspace_name != "" ? azurerm_monitor_diagnostic_setting.tfstate_blob[0].id : "not-configured"
}
