output "server_id" {
  value = try(azurerm_mysql_flexible_server.this[0].id, null)
}

output "server_fqdn" {
  value = try(azurerm_mysql_flexible_server.this[0].fqdn, null)
}

output "private_dns_zone_id" {
  value = try(azurerm_private_dns_zone.mysql[0].id, null)
}

output "private_endpoint_id" {
  value = try(azurerm_private_endpoint.mysql[0].id, null)
}

output "mysql_admin_username_secret_id" {
  value = try(azurerm_key_vault_secret.mysql_admin_username[0].id, null)
}

output "mysql_admin_password_secret_id" {
  value = try(azurerm_key_vault_secret.mysql_admin_password[0].id, null)
}
