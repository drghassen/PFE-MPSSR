output "id" {
  value = azurerm_storage_account.this.id
}

output "name" {
  value = azurerm_storage_account.this.name
}

output "primary_blob_endpoint" {
  value = azurerm_storage_account.this.primary_blob_endpoint
}

output "allowed_subnet_ids" {
  value = var.storage_allowed_subnet_ids
}

output "private_endpoint_id" {
  value = azurerm_private_endpoint.blob.id
}

output "customer_managed_key_id" {
  value = try(azurerm_storage_account_customer_managed_key.this[0].id, null)
}

output "cmk_key_id" {
  value = var.key_vault_key_id
}
