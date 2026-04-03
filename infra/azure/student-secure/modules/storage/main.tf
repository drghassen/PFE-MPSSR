data "azurerm_client_config" "current" {}

locals {
  suffix                = substr(replace(data.azurerm_client_config.current.subscription_id, "-", ""), 0, 6)
  storage_name_untrimed = lower(replace("st${replace(var.base_name, "-", "")}${local.suffix}", "-", ""))
  storage_name          = substr(local.storage_name_untrimed, 0, 24)
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "st-vnet-link-${replace(var.base_name, "-", "")}"
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  resource_group_name   = var.resource_group_name
  virtual_network_id    = var.virtual_network_id
  tags                  = var.tags
}

resource "azurerm_storage_account" "this" {
  name                              = local.storage_name
  location                          = var.location
  resource_group_name               = var.resource_group_name
  account_tier                      = "Standard"
  account_replication_type          = "GRS"
  account_kind                      = "StorageV2"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  infrastructure_encryption_enabled = true
  tags                              = var.tags

  identity {
    type = "SystemAssigned"
  }

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true

    delete_retention_policy {
      days = 7
    }

    container_delete_retention_policy {
      days = 7
    }
  }

  sas_policy {
    expiration_period = "1.00:00:00"
  }

  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = 10
    }
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = var.storage_allowed_subnet_ids
  }
}

resource "azurerm_private_endpoint" "blob" {
  name                = "pep-blob-${replace(var.base_name, "-", "")}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-blob-${replace(var.base_name, "-", "")}"
    private_connection_resource_id = azurerm_storage_account.this.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "pdzg-blob-${replace(var.base_name, "-", "")}"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.blob]
}
