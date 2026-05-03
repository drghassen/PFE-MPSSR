output "id" {
  description = "Key Vault ID."
  value       = azurerm_key_vault.this.id
}

output "name" {
  description = "Key Vault name."
  value       = azurerm_key_vault.this.name
}

output "vault_uri" {
  description = "Key Vault URI."
  value       = azurerm_key_vault.this.vault_uri
}

output "private_endpoint_id" {
  description = "Key Vault private endpoint ID."
  value       = azurerm_private_endpoint.vault.id
}

output "private_dns_zone_id" {
  description = "Key Vault private DNS zone ID."
  value       = azurerm_private_dns_zone.vault.id
}
