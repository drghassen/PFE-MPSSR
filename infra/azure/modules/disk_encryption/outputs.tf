output "disk_encryption_set_id" {
  description = "Disk Encryption Set ID — pass to VM os_disk.disk_encryption_set_id."
  value       = azurerm_disk_encryption_set.this.id
}

output "disk_encryption_set_name" {
  description = "Disk Encryption Set name."
  value       = azurerm_disk_encryption_set.this.name
}

output "key_id" {
  description = "Key Vault key ID used as the CMK."
  value       = azurerm_key_vault_key.disk_cmk.id
}
