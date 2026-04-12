output "id" {
  value = azurerm_key_vault.this.id
}

output "name" {
  value = azurerm_key_vault.this.name
}

output "cmk_key_id" {
  sensitive = true
  value = (
    trimspace(var.existing_cmk_key_id) != ""
    ? trimspace(var.existing_cmk_key_id)
    : try(azurerm_key_vault_key.cmk[0].id, null)
  )
}

output "cmk_key_name" {
  sensitive = true
  value = (
    trimspace(var.existing_cmk_key_id) != ""
    ? regex("^https://[^/]+/keys/([^/]+)(?:/[^/]+)?$", trimspace(var.existing_cmk_key_id))[0]
    : try(azurerm_key_vault_key.cmk[0].name, null)
  )
}

output "private_endpoint_id" {
  value = azurerm_private_endpoint.key_vault.id
}

# CKV2_CS_AZ_010 — Disk Encryption Set ID for OS disk CMK encryption.
# Null when no managed CMK is provisioned (existing key path or disabled CMK).
output "disk_encryption_set_id" {
  description = "Azure Disk Encryption Set resource ID. Null when CMK is not managed by this module."
  sensitive   = true
  value       = try(azurerm_disk_encryption_set.this[0].id, null)
}

