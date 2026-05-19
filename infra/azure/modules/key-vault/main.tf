resource "azurerm_key_vault" "this" {
  name                            = var.name
  location                        = var.location
  resource_group_name             = var.resource_group_name
  tenant_id                       = var.tenant_id
  sku_name                        = "standard"
  soft_delete_retention_days      = 90
  purge_protection_enabled        = true
  public_network_access_enabled   = true
  enabled_for_disk_encryption     = true
  enabled_for_deployment          = false
  enabled_for_template_deployment = false
  rbac_authorization_enabled      = true
  tags                            = var.tags

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }
}

resource "azurerm_private_dns_zone" "vault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "time_sleep" "after_private_dns_zone" {
  create_duration = "15s"
  depends_on      = [azurerm_private_dns_zone.vault]
}

resource "azurerm_private_dns_zone_virtual_network_link" "vault" {
  name                  = "${var.name}-vnet-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.vault.name
  virtual_network_id    = var.vnet_id
  registration_enabled  = false
  tags                  = var.tags
  depends_on            = [time_sleep.after_private_dns_zone]
}
