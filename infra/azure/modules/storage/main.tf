data "azurerm_client_config" "current" {}

locals {
  subscription_suffix = substr(replace(data.azurerm_client_config.current.subscription_id, "-", ""), 0, 6)
  storage_name_raw    = lower(replace("st${var.project_name}${var.environment}${local.subscription_suffix}", "-", ""))
  storage_name        = substr(local.storage_name_raw, 0, 24)
}

resource "azurerm_storage_account" "main" {
  name                     = local.storage_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Risky on purpose: legacy TLS and HTTP traffic are allowed.
  min_tls_version               = "TLS1_0"
  https_traffic_only_enabled    = false
  public_network_access_enabled = true

  # Risky on purpose: nested public blobs and shared keys remain enabled.
  allow_nested_items_to_be_public = true
  shared_access_key_enabled       = true

  network_rules {
    default_action = "Allow"
    bypass         = ["AzureServices"]
  }

  # Risky on purpose: versioning disabled for weaker recoverability.
  blob_properties {
    versioning_enabled = false
  }

  tags = var.tags
}

resource "azurerm_storage_container" "public_data" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "blob"
}

resource "azurerm_storage_container" "internal_logs" {
  name                  = "internal-logs"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}
