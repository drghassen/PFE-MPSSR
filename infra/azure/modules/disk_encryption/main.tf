resource "azurerm_key_vault_key" "disk_cmk" {
  name         = "disk-cmk-${var.name_prefix}-${var.environment}"
  key_vault_id = var.key_vault_id
  key_type     = "RSA"
  key_size     = 4096
  key_opts     = ["decrypt", "encrypt", "unwrapKey", "wrapKey"]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P1Y"
    notify_before_expiry = "P30D"
  }
}

resource "azurerm_disk_encryption_set" "this" {
  name                      = "des-${var.name_prefix}-${var.environment}"
  location                  = var.location
  resource_group_name       = var.resource_group_name
  key_vault_key_id          = azurerm_key_vault_key.disk_cmk.id
  auto_key_rotation_enabled = true

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# Grant the DES managed identity permission to use the key for disk encryption.
resource "azurerm_role_assignment" "des_kv_crypto_user" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_disk_encryption_set.this.identity[0].principal_id
}
