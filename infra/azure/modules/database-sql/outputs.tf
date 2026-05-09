output "server_id" {
  value = try(azurerm_mssql_server.this[0].id, null)
}

output "server_name" {
  value = try(azurerm_mssql_server.this[0].name, null)
}

output "server_fqdn" {
  value = try(azurerm_mssql_server.this[0].fully_qualified_domain_name, null)
}

output "database_id" {
  value = try(azurerm_mssql_database.this[0].id, null)
}

output "private_endpoint_ip" {
  value = try(azurerm_private_endpoint.sql[0].private_service_connection[0].private_ip_address, null)
}
