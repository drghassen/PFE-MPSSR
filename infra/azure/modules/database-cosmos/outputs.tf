output "account_id" {
  value = try(azurerm_cosmosdb_account.this[0].id, null)
}

output "account_name" {
  value = try(azurerm_cosmosdb_account.this[0].name, null)
}
