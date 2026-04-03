provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
    key_vault {
      purge_soft_delete_on_destroy       = false
      recover_soft_deleted_key_vaults    = true
      recover_soft_deleted_secrets       = true
      recover_soft_deleted_keys          = true
      purge_soft_deleted_keys_on_destroy = false
    }
  }
}
