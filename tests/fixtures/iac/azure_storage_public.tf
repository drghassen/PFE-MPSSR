resource "azurerm_resource_group" "rg" {
  name     = "rg-cloudsentinel-test"
  location = "westeurope"
}

resource "azurerm_storage_account" "insecure" {
  name                          = "csteststorageacct"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  allow_nested_items_to_be_public = true
  enable_https_traffic_only     = false
  min_tls_version               = "TLS1_0"
}
