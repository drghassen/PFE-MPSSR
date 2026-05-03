output "vnet_id" {
  description = "Virtual network ID."
  value       = azurerm_virtual_network.this.id
}

output "vnet_name" {
  description = "Virtual network name."
  value       = azurerm_virtual_network.this.name
}

output "app_subnet_id" {
  description = "Application subnet ID."
  value       = azurerm_subnet.app.id
}

output "private_endpoints_subnet_id" {
  description = "Private endpoints subnet ID."
  value       = azurerm_subnet.private_endpoints.id
}

output "data_subnet_id" {
  description = "Data subnet ID."
  value       = azurerm_subnet.data.id
}

output "bastion_subnet_id" {
  description = "Bastion subnet ID."
  value       = azurerm_subnet.bastion.id
}
