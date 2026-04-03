data "azurerm_client_config" "current" {}

locals {
  key_vault_name_raw = lower(replace("kv-${var.base_name}", "-", ""))
  key_vault_name     = substr(local.key_vault_name_raw, 0, 24)
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
