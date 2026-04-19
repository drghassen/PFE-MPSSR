output "vm_identity_id" {
  description = "User-assigned identity ID for VM."
  value       = azurerm_user_assigned_identity.vm.id
}

output "vm_identity_principal_id" {
  description = "Principal ID for VM identity."
  value       = azurerm_user_assigned_identity.vm.principal_id
}

output "ci_identity_id" {
  description = "User-assigned identity ID for CI/CD."
  value       = try(azurerm_user_assigned_identity.ci[0].id, null)
}

output "ci_identity_principal_id" {
  description = "Principal ID for CI/CD identity."
  value       = try(azurerm_user_assigned_identity.ci[0].principal_id, null)
}
