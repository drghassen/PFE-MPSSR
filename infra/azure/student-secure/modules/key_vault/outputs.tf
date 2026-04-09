output "id" {
  value = azurerm_key_vault.this.id
}

output "name" {
  value = azurerm_key_vault.this.name
}

output "cmk_key_id" {
  value = (
    trimspace(var.existing_cmk_key_id) != ""
    ? trimspace(var.existing_cmk_key_id)
    : try(azurerm_key_vault_key.cmk[0].id, null)
  )
}

output "cmk_key_name" {
  value = (
    trimspace(var.existing_cmk_key_id) != ""
    ? regex("^https://[^/]+/keys/([^/]+)(?:/[^/]+)?$", trimspace(var.existing_cmk_key_id))[0]
    : try(azurerm_key_vault_key.cmk[0].name, null)
  )
}

output "private_endpoint_id" {
  value = azurerm_private_endpoint.key_vault.id
}
