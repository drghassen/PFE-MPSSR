output "id" {
  value = azurerm_key_vault.this.id
}

output "name" {
  value = azurerm_key_vault.this.name
}

output "cmk_key_id" {
  value = null
}

output "private_endpoint_id" {
  value = azurerm_private_endpoint.key_vault.id
}
