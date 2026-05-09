output "storage_assignment_id" {
  value = azurerm_role_assignment.storage_blob_data_contributor.id
}

output "key_vault_assignment_id" {
  value = azurerm_role_assignment.key_vault_secrets_user.id
}
