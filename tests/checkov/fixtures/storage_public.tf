resource "azurerm_resource_group" "rg" {
  name     = "rg-storage-public"
  location = "westeurope"
}

resource "azurerm_storage_account" "public_sa" {
  name                     = "cspublicsa001"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Intentional misconfig for testing CKV2_CS_AZ_001/002
  allow_nested_items_to_be_public = true
  enable_https_traffic_only       = false
  min_tls_version                 = "TLS1_0"
}
