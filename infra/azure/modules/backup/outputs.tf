output "vault_id" {
  description = "Recovery Services Vault ID."
  value       = azurerm_recovery_services_vault.this.id
}

output "vault_name" {
  description = "Recovery Services Vault name."
  value       = azurerm_recovery_services_vault.this.name
}

output "policy_id" {
  description = "VM backup policy ID."
  value       = azurerm_backup_policy_vm.daily.id
}
