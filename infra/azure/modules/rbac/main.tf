resource "azurerm_role_assignment" "storage_blob_data_contributor" {
  scope                = var.storage_account_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = var.principal_id
}

resource "azurerm_role_assignment" "key_vault_secrets_user" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.principal_id
}

resource "azurerm_role_assignment" "rg_reader" {
  count                = var.grant_rg_reader ? 1 : 0
  scope                = var.resource_group_id
  role_definition_name = "Reader"
  principal_id         = var.principal_id
}

resource "azurerm_role_assignment" "cosmos_reader" {
  count                = var.cosmosdb_account_id != null ? 1 : 0
  scope                = var.cosmosdb_account_id
  role_definition_name = "Reader"
  principal_id         = var.principal_id
}
