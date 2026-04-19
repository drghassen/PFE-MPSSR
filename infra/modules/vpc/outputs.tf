output "vnet_id" {
  description = "Virtual network ID."
  value       = azurerm_virtual_network.this.id
}

output "public_subnet_id" {
  description = "Public subnet ID."
  value       = azurerm_subnet.public.id
}

output "private_subnet_id" {
  description = "Private subnet ID."
  value       = azurerm_subnet.private.id
}

output "nat_gateway_id" {
  description = "NAT gateway ID when enabled."
  value       = try(azurerm_nat_gateway.this[0].id, null)
}
