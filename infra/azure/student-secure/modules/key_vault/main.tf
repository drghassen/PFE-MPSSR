data "azurerm_client_config" "current" {}

locals {
  key_vault_name_raw = lower(replace("kv-${var.base_name}", "-", ""))
  key_vault_name     = substr(local.key_vault_name_raw, 0, 24)
  use_existing_cmk   = trimspace(var.existing_cmk_key_id) != ""
}

resource "azurerm_private_dns_zone" "key_vault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "key_vault" {
  name                  = "kv-vnet-link-${replace(var.base_name, "-", "")}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.key_vault.name
  virtual_network_id    = var.virtual_network_id
  tags                  = var.tags
}

resource "azurerm_key_vault" "this" {
  name                          = local.key_vault_name
  location                      = var.location
  resource_group_name           = var.resource_group_name
  tenant_id                     = var.tenant_id
  sku_name                      = "premium"
  enable_rbac_authorization     = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false
  tags                          = var.tags

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = []
    virtual_network_subnet_ids = [var.private_subnet_id]
  }

}

resource "azurerm_private_endpoint" "key_vault" {
  name                = "pep-kv-${replace(var.base_name, "-", "")}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-kv-${replace(var.base_name, "-", "")}"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "pdzg-kv-${replace(var.base_name, "-", "")}"
    private_dns_zone_ids = [azurerm_private_dns_zone.key_vault.id]
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.key_vault]
}

resource "azurerm_key_vault_key" "cmk" {
  count = local.use_existing_cmk ? 0 : 1

  name            = var.cmk_key_name
  key_vault_id    = azurerm_key_vault.this.id
  key_type        = var.cmk_key_type
  key_size        = var.cmk_key_size
  key_opts        = ["wrapKey", "unwrapKey"]
  expiration_date = var.key_expiration_date
  tags            = var.tags
}

# CKV2_CS_AZ_010 / CIS 7.1 — Azure Disk Encryption Set.
# Binds the CMK to OS disk encryption for VMs using this Key Vault.
# Created only when a CMK is managed by this module (use_existing_cmk = false).
resource "azurerm_disk_encryption_set" "this" {
  count = local.use_existing_cmk ? 0 : 1

  name                = "des-${var.base_name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  key_vault_key_id    = azurerm_key_vault_key.cmk[0].id
  encryption_type     = "EncryptionAtRestWithCustomerKey"
  tags                = var.tags

  identity {
    type = "SystemAssigned"
  }
}

# Grant the DES identity access to unwrap/wrap the CMK in Key Vault.
resource "azurerm_role_assignment" "des_crypto_user" {
  count = local.use_existing_cmk ? 0 : 1

  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_disk_encryption_set.this[0].identity[0].principal_id

  depends_on = [azurerm_disk_encryption_set.this]
}

