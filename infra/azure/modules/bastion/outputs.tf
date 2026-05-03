output "id" {
  description = "Bastion host ID."
  value       = azurerm_bastion_host.this.id
}

output "name" {
  description = "Bastion host name."
  value       = azurerm_bastion_host.this.name
}

output "public_ip" {
  description = "Bastion public IP."
  value       = azurerm_public_ip.this.ip_address
}
