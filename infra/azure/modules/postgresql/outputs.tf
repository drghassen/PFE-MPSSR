output "id" {
  description = "PostgreSQL server ID."
  value       = azurerm_postgresql_flexible_server.this.id
}

output "name" {
  description = "PostgreSQL server name."
  value       = azurerm_postgresql_flexible_server.this.name
}

output "fqdn" {
  description = "PostgreSQL FQDN."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "database_name" {
  description = "Database name."
  value       = azurerm_postgresql_flexible_server_database.this.name
}

output "private_dns_zone_id" {
  description = "PostgreSQL private DNS zone ID."
  value       = azurerm_private_dns_zone.postgres.id
}
