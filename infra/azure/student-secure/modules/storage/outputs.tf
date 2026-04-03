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
