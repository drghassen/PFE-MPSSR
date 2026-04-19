output "db_fqdn" {
  description = "PostgreSQL server fully-qualified domain name."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "db_name" {
  description = "Database name."
  value       = azurerm_postgresql_flexible_server_database.this.name
}

output "db_admin_login" {
  description = "PostgreSQL administrator login."
  value       = azurerm_postgresql_flexible_server.this.administrator_login
}

output "db_port" {
  description = "PostgreSQL port."
  value       = 5432
}
