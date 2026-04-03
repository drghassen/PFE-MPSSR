output "server_id" {
  value = azurerm_mysql_flexible_server.this.id
}

output "server_fqdn" {
  value = azurerm_mysql_flexible_server.this.fqdn
}

output "private_dns_zone_id" {
  value = azurerm_private_dns_zone.mysql.id
}

output "private_endpoint_id" {
  value = azurerm_private_endpoint.mysql.id
}

output "mysql_admin_username_secret_id" {
  value = azurerm_key_vault_secret.mysql_admin_username.id
}

output "mysql_admin_password_secret_id" {
  value = azurerm_key_vault_secret.mysql_admin_password.id
}
